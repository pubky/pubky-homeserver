#[cfg(test)]
use crate::AppContext;
use crate::{
    persistence::{
        files::events::EventsService,
        sql::{
            entities::blob::{BlobGarbageClaim, BlobReadLeaseRecord, BlobRepository},
            entry::{EntryEntity, EntryRepository},
            user::{UserEntity, UserRepository},
            SqlDb, UnifiedExecutor,
        },
    },
    services::user_service::{UserService, FILE_METADATA_SIZE},
    shared::webdav::EntryPath,
    ConfigToml,
};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use lru::LruCache;
#[cfg(test)]
use opendal::Buffer;
use std::{
    num::NonZeroUsize,
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::super::{FileIoError, FileStream, OpendalService, WriteStreamError};

const ABANDONED_UPLOAD_AGE_SECONDS: i64 = 60 * 60;
const UPLOAD_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
const UPLOAD_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);
const STALE_UPLOAD_RECOVERY_GRACE_SECONDS: i64 = 5 * 60;
// A failed remote close can complete after the client loses the response.
const ABANDONED_UPLOAD_SETTLE_SECONDS: i64 = 60 * 60;
const ACTIVE_BLOB_RETENTION_SECONDS: i64 = 5 * 60;
const STALE_GARBAGE_CLAIM_SECONDS: i64 = 5 * 60;
const FAILED_CLEANUP_RETRY_SECONDS: i64 = 60;
const CLEANUP_BATCH_SIZE: usize = 64;
const CLEANUP_CONCURRENCY: usize = 8;
const CLEANUP_TIME_BUDGET: Duration = Duration::from_secs(45);
const CLEANUP_DELETE_TIMEOUT: Duration = Duration::from_secs(5);
const READ_LEASE_SECONDS: i64 = 2 * 60;
const READ_LEASE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const READ_LEASE_DATABASE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_LEASE_CACHE_CAPACITY: usize = 4096;
// Bound physical data to the active version, one retained version, and one replacement upload.
const PHYSICAL_STORAGE_QUOTA_MULTIPLIER: u64 = 3;

/// Coordinates logical file entries in PostgreSQL with immutable backend blobs.
#[derive(Debug, Clone)]
pub struct FileService {
    pub(crate) opendal: OpendalService,
    pub(crate) db: SqlDb,
    events_service: EventsService,
    user_service: UserService,
    default_storage_mb: Option<u64>,
    read_leases: Arc<Mutex<ReadLeaseCache>>,
}

struct UploadHeartbeat {
    handle: Option<JoinHandle<()>>,
    cancellation: CancellationToken,
}

#[derive(Debug)]
struct ActiveBlobReadLease {
    record: BlobReadLeaseRecord,
    cancellation: CancellationToken,
    db: SqlDb,
}

type ReadLeaseCell = Arc<tokio::sync::Mutex<Weak<ActiveBlobReadLease>>>;
type ReadLeaseCache = LruCache<String, ReadLeaseCell>;

/// Keeps one immutable backend object alive while a response or DAV handle reads it.
pub(crate) struct BlobReadLease {
    inner: Arc<ActiveBlobReadLease>,
}

struct LeaseProtectedStream {
    stream: FileStream,
    lease: Option<BlobReadLease>,
    terminated: bool,
}

enum CommitWriteError {
    BeforeCommit(FileIoError),
    CommitOutcomeUnknown(FileIoError),
}

struct UploadReservation {
    user_id: i32,
    tracked_length: u64,
    max_blob_length: Option<u64>,
}

#[derive(Clone, Copy)]
enum WriteMode {
    Client,
    AdminOverwrite,
    AdminCreate,
}

impl WriteMode {
    fn enforces_write_path(self) -> bool {
        matches!(self, Self::Client)
    }

    fn requires_missing_destination(self) -> bool {
        matches!(self, Self::AdminCreate)
    }
}

impl UploadHeartbeat {
    fn start(db: SqlDb, blob_key: String) -> Self {
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(UPLOAD_HEARTBEAT_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                interval.tick().await;
                match Self::touch_upload(&db, &blob_key, UPLOAD_HEARTBEAT_TIMEOUT).await {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!(blob_key, "Blob upload is no longer active");
                        task_cancellation.cancel();
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(blob_key, %error, "Failed to refresh active blob upload");
                        task_cancellation.cancel();
                        break;
                    }
                }
            }
        });
        Self {
            handle: Some(handle),
            cancellation,
        }
    }

    async fn touch_upload(
        db: &SqlDb,
        blob_key: &str,
        timeout: Duration,
    ) -> Result<bool, FileIoError> {
        tokio::time::timeout(
            timeout,
            BlobRepository::touch_upload(blob_key, &mut db.pool().into()),
        )
        .await
        .map_err(|_| FileIoError::UploadLeaseLost)?
        .map_err(FileIoError::from)
    }

    fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    async fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl ActiveBlobReadLease {
    fn start(db: SqlDb, record: BlobReadLeaseRecord) -> Arc<Self> {
        let lease = Arc::new(Self {
            record: record.clone(),
            cancellation: CancellationToken::new(),
            db: db.clone(),
        });
        let cancellation = lease.cancellation.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(READ_LEASE_HEARTBEAT_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => break,
                    _ = interval.tick() => {
                        let refresh = tokio::time::timeout(
                            READ_LEASE_DATABASE_TIMEOUT,
                            BlobRepository::refresh_read_lease(
                                &record,
                                READ_LEASE_SECONDS,
                                &mut db.pool().into(),
                            ),
                        )
                        .await;
                        match refresh {
                            Ok(Ok(true)) => {}
                            Ok(Ok(false)) => {
                                tracing::warn!(blob_key = record.blob_key, "Blob read lease was lost");
                                cancellation.cancel();
                                break;
                            }
                            Ok(Err(error)) => {
                                tracing::warn!(blob_key = record.blob_key, %error, "Failed to refresh blob read lease");
                                cancellation.cancel();
                                break;
                            }
                            Err(_) => {
                                tracing::warn!(blob_key = record.blob_key, "Blob read lease refresh timed out");
                                cancellation.cancel();
                                break;
                            }
                        }
                    }
                }
            }
        });
        lease
    }
}

impl BlobReadLease {
    fn is_active(&self) -> bool {
        !self.inner.cancellation.is_cancelled()
    }

    fn protects(&self, blob_key: &str) -> bool {
        self.inner.record.blob_key == blob_key && self.is_active()
    }
}

impl Drop for ActiveBlobReadLease {
    fn drop(&mut self) {
        self.cancellation.cancel();
        let record = self.record.clone();
        let db = self.db.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                match tokio::time::timeout(
                    READ_LEASE_DATABASE_TIMEOUT,
                    BlobRepository::release_read_lease(&record, &mut db.pool().into()),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(blob_key = record.blob_key, %error, "Failed to release blob read lease");
                    }
                    Err(_) => {
                        tracing::warn!(blob_key = record.blob_key, "Blob read lease release timed out");
                    }
                }
            });
        }
    }
}

impl Stream for LeaseProtectedStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.terminated {
            return Poll::Ready(None);
        }
        let Some(lease) = self.lease.as_ref() else {
            return Poll::Ready(None);
        };
        if !lease.is_active() {
            self.terminated = true;
            self.lease.take();
            return Poll::Ready(Some(Err(std::io::Error::other("blob read lease lost"))));
        }
        let result = Pin::new(&mut self.stream).poll_next(context);
        if matches!(result, Poll::Ready(None | Some(Err(_)))) {
            self.terminated = true;
            self.lease.take();
        }
        result
    }
}

impl Drop for UploadHeartbeat {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl FileService {
    pub fn new(
        opendal_service: OpendalService,
        db: SqlDb,
        events_service: EventsService,
        user_service: UserService,
        default_storage_mb: Option<u64>,
    ) -> Self {
        Self {
            opendal: opendal_service,
            db,
            events_service,
            user_service,
            default_storage_mb,
            read_leases: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(READ_LEASE_CACHE_CAPACITY)
                    .expect("read lease cache capacity must be non-zero"),
            ))),
        }
    }

    pub fn new_from_config(
        config: &ConfigToml,
        data_directory: &Path,
        db: SqlDb,
        events_service: EventsService,
        user_service: crate::services::user_service::UserService,
    ) -> Result<Self, FileIoError> {
        let opendal_service = OpendalService::new_from_config(&config.storage, data_directory)?;
        Ok(Self::new(
            opendal_service,
            db,
            events_service,
            user_service,
            config.storage.default_quota_mb,
        ))
    }

    /// Get the metadata of a file.
    pub async fn get_info(
        &self,
        path: &EntryPath,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<EntryEntity, FileIoError> {
        match EntryRepository::get_by_path(path, executor).await {
            Ok(entry) => Ok(entry),
            Err(sqlx::Error::RowNotFound) => Err(FileIoError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// Get the content of a file as a stream of bytes.
    /// The stream is chunked.
    /// Errors if the file does not exist.
    #[cfg(test)]
    pub async fn get_stream(&self, path: &EntryPath) -> Result<FileStream, FileIoError> {
        let entry = self.get_info(path, &mut self.db.pool().into()).await?;
        self.get_entry_stream(&entry).await
    }

    /// Get the content selected by an already-loaded logical entry.
    pub(crate) async fn get_entry_stream(
        &self,
        entry: &EntryEntity,
    ) -> Result<FileStream, FileIoError> {
        let blob_key = Self::backend_key(entry);
        let lease = self.acquire_blob_read_lease(&blob_key).await?;
        let stream = self.opendal.get_stream_by_key(&blob_key).await?;
        Ok(Box::new(LeaseProtectedStream {
            stream,
            lease: Some(lease),
            terminated: false,
        }))
    }

    pub(crate) async fn acquire_entry_read_lease(
        &self,
        entry: &EntryEntity,
    ) -> Result<BlobReadLease, FileIoError> {
        self.acquire_blob_read_lease(&Self::backend_key(entry))
            .await
    }

    async fn acquire_blob_read_lease(&self, blob_key: &str) -> Result<BlobReadLease, FileIoError> {
        let cell = {
            let mut cache = self
                .read_leases
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(
                cache
                    .get_or_insert_ref(blob_key, || Arc::new(tokio::sync::Mutex::new(Weak::new()))),
            )
        };
        let mut cached = cell.lock().await;
        if let Some(inner) = cached
            .upgrade()
            .filter(|lease| !lease.cancellation.is_cancelled())
        {
            return Ok(BlobReadLease { inner });
        }

        let lease_id = uuid::Uuid::new_v4().simple().to_string();
        let record = BlobRepository::create_read_lease(
            blob_key,
            &lease_id,
            READ_LEASE_SECONDS,
            &mut self.db.pool().into(),
        )
        .await?
        .ok_or(FileIoError::ReadLeaseLost)?;
        let inner = ActiveBlobReadLease::start(self.db.clone(), record);
        *cached = Arc::downgrade(&inner);
        Ok(BlobReadLease { inner })
    }

    /// Read one byte range selected by an already-loaded logical entry.
    pub(crate) async fn get_entry_range(
        &self,
        entry: &EntryEntity,
        lease: &BlobReadLease,
        range: std::ops::Range<u64>,
    ) -> Result<Bytes, FileIoError> {
        let blob_key = Self::backend_key(entry);
        if !lease.protects(&blob_key) {
            return Err(FileIoError::ReadLeaseLost);
        }
        self.opendal.get_range_by_key(&blob_key, range).await
    }

    /// Write a streamed file and atomically publish its logical entry.
    pub async fn write_stream(
        &self,
        path: &EntryPath,
        stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
    ) -> Result<EntryEntity, FileIoError> {
        self.write_stream_inner(path, stream, WriteMode::Client, None)
            .await
    }

    /// Write a streamed file with a trusted upper-bound hint for upload reservation.
    pub async fn write_stream_with_size_hint(
        &self,
        path: &EntryPath,
        stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
        size_hint: u64,
    ) -> Result<EntryEntity, FileIoError> {
        self.write_stream_inner(path, stream, WriteMode::Client, Some(size_hint))
            .await
    }

    /// Delete a file.
    pub async fn delete(&self, path: &EntryPath) -> Result<(), FileIoError> {
        self.delete_inner(path, true).await
    }

    /// Delete a file bypassing write-path restrictions.
    /// Used by both admin file APIs.
    pub async fn admin_delete(&self, path: &EntryPath) -> Result<(), FileIoError> {
        self.delete_inner(path, false).await
    }

    /// Write through the admin interface without user write-path policy.
    #[cfg(test)]
    pub(crate) async fn admin_write_stream(
        &self,
        path: &EntryPath,
        stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
    ) -> Result<EntryEntity, FileIoError> {
        self.write_stream_inner(path, stream, WriteMode::AdminOverwrite, None)
            .await
    }

    pub(crate) async fn admin_write_stream_with_size_hint(
        &self,
        path: &EntryPath,
        stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
        size_hint: u64,
    ) -> Result<EntryEntity, FileIoError> {
        self.write_stream_inner(path, stream, WriteMode::AdminOverwrite, Some(size_hint))
            .await
    }

    pub(crate) async fn admin_create_stream_with_size_hint(
        &self,
        path: &EntryPath,
        stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
        size_hint: u64,
    ) -> Result<EntryEntity, FileIoError> {
        self.write_stream_inner(path, stream, WriteMode::AdminCreate, Some(size_hint))
            .await
    }

    pub(crate) async fn admin_users(&self) -> Result<Vec<String>, FileIoError> {
        Ok(UserRepository::get_all(&mut self.db.pool().into())
            .await?
            .into_iter()
            .map(|user| user.public_key.z32())
            .collect())
    }

    pub(crate) async fn admin_spool_limit(
        &self,
        path: &EntryPath,
        existing: Option<&EntryEntity>,
    ) -> Result<Option<u64>, FileIoError> {
        let user = match self
            .user_service
            .get_in_tx(path.pubkey(), &mut self.db.pool().into())
            .await
        {
            Ok(user) => user,
            Err(sqlx::Error::RowNotFound) => return Err(FileIoError::NotFound),
            Err(error) => return Err(error.into()),
        };
        let Some(max_bytes) = crate::persistence::files::storage_quota::resolve_storage_max_bytes(
            &user,
            self.default_storage_mb,
        ) else {
            return Ok(None);
        };
        let existing_usage = existing.map_or(0, |entry| {
            entry.content_length.saturating_add(FILE_METADATA_SIZE)
        });
        let usage_without_file = user.used_bytes.saturating_sub(existing_usage);
        Ok(Some(
            max_bytes
                .saturating_sub(usage_without_file)
                .saturating_sub(FILE_METADATA_SIZE),
        ))
    }

    pub(crate) async fn contains_directory(&self, path: &EntryPath) -> Result<bool, FileIoError> {
        Ok(EntryRepository::contains_directory(path, &mut self.db.pool().into()).await?)
    }

    pub(crate) async fn list_shallow_all(
        &self,
        path: &EntryPath,
    ) -> Result<Vec<EntryPath>, FileIoError> {
        let mut entries = Vec::new();
        let mut cursor = None;
        loop {
            let page = EntryRepository::list_shallow(
                path,
                Some(crate::constants::DEFAULT_MAX_LIST_LIMIT),
                cursor,
                false,
                &mut self.db.pool().into(),
            )
            .await?;
            let Some(last) = page.last().cloned() else {
                break;
            };
            let page_len = page.len();
            entries.extend(page);
            if page_len < crate::constants::DEFAULT_MAX_LIST_LIMIT as usize {
                break;
            }
            cursor = Some(last);
        }
        Ok(entries)
    }

    pub(crate) async fn get_info_many(
        &self,
        paths: &[EntryPath],
    ) -> Result<Vec<EntryEntity>, FileIoError> {
        let Some(first) = paths.first() else {
            return Ok(Vec::new());
        };
        Ok(
            EntryRepository::get_by_paths(first.pubkey(), paths, &mut self.db.pool().into())
                .await?,
        )
    }

    pub(crate) async fn admin_copy(
        &self,
        from: &EntryPath,
        to: &EntryPath,
    ) -> Result<(), FileIoError> {
        let source = self.get_info(from, &mut self.db.pool().into()).await?;
        let source_length = source.content_length;
        let stream = self.get_entry_stream(&source).await?;
        self.write_stream_inner(
            to,
            stream.map(|result| {
                result.map_err(|error| WriteStreamError::Other(anyhow::Error::new(error)))
            }),
            WriteMode::AdminCreate,
            Some(source_length),
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn admin_rename(
        &self,
        from: &EntryPath,
        to: &EntryPath,
    ) -> Result<(), FileIoError> {
        if from == to {
            return Ok(());
        }

        let mut tx = self.db.pool().begin().await?;
        let result = async {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            let (mut source_user, mut destination_user) =
                self.lock_move_users(from, to, &mut executor).await?;

            let source_entry = match EntryRepository::get_by_path(from, &mut executor).await {
                Ok(entry) => entry,
                Err(sqlx::Error::RowNotFound) => return Err(FileIoError::NotFound),
                Err(error) => return Err(error.into()),
            };
            match EntryRepository::get_by_path(to, &mut executor).await {
                Ok(_) => return Err(FileIoError::PathCollision),
                Err(sqlx::Error::RowNotFound) => {}
                Err(error) => return Err(error.into()),
            }
            if EntryRepository::has_file_folder_collision(to, &mut executor).await? {
                return Err(FileIoError::PathCollision);
            }
            let source_blob_key = Self::backend_key(&source_entry);
            EntryRepository::create_with_blob_key(
                destination_user
                    .as_ref()
                    .map_or(source_user.id, |user| user.id),
                to.path(),
                Some(&source_blob_key),
                &source_entry.content_hash,
                source_entry.content_length,
                &source_entry.content_type,
                &mut executor,
            )
            .await?;
            EntryRepository::delete(source_entry.id, &mut executor).await?;

            let destination_user_id = destination_user
                .as_ref()
                .map_or(source_user.id, |user| user.id);
            self.events_service
                .create_event(
                    destination_user_id,
                    crate::persistence::files::events::EventType::Put {
                        content_hash: source_entry.content_hash,
                    },
                    to,
                    &mut executor,
                )
                .await?;
            self.events_service
                .create_event(
                    source_user.id,
                    crate::persistence::files::events::EventType::Delete,
                    from,
                    &mut executor,
                )
                .await?;

            if let Some(destination_user) = destination_user.as_mut() {
                let bytes_delta = source_entry.content_length as i64 + FILE_METADATA_SIZE as i64;
                let max_bytes = crate::persistence::files::storage_quota::resolve_storage_max_bytes(
                    destination_user,
                    self.default_storage_mb,
                );
                if crate::persistence::files::storage_quota::would_exceed_limit(
                    destination_user.used_bytes,
                    bytes_delta,
                    max_bytes,
                ) {
                    return Err(FileIoError::DiskSpaceQuotaExceeded);
                }
                destination_user.used_bytes = destination_user
                    .used_bytes
                    .saturating_add_signed(bytes_delta);
                source_user.used_bytes = source_user.used_bytes.saturating_sub(
                    source_entry
                        .content_length
                        .saturating_add(FILE_METADATA_SIZE),
                );
                self.user_service
                    .update_in_tx(destination_user, &mut executor)
                    .await?;
            }
            self.user_service
                .update_in_tx(&source_user, &mut executor)
                .await?;
            Ok(())
        }
        .await;

        match result {
            Ok(()) => tx.commit().await?,
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::error!(%rollback_error, "Failed to roll back admin rename");
                }
                return Err(error);
            }
        }
        self.events_service.notify_event().await;
        Ok(())
    }

    pub(crate) async fn admin_rename_directory(
        &self,
        from: &EntryPath,
        to: &EntryPath,
    ) -> Result<(), FileIoError> {
        if from == to {
            return Ok(());
        }
        let source_prefix = format!("{}/", from.path().as_str().trim_end_matches('/'));
        let destination_prefix = format!("{}/", to.path().as_str().trim_end_matches('/'));
        if from.pubkey() == to.pubkey() && destination_prefix.starts_with(&source_prefix) {
            return Err(FileIoError::PathCollision);
        }

        let mut tx = self.db.pool().begin().await?;
        let result = async {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            let (mut source_user, mut destination_user) =
                self.lock_move_users(from, to, &mut executor).await?;
            let entries = EntryRepository::list_descendants(from, &mut executor).await?;
            if entries.is_empty() {
                return Err(FileIoError::NotFound);
            }
            match EntryRepository::get_by_path(to, &mut executor).await {
                Ok(_) => return Err(FileIoError::PathCollision),
                Err(sqlx::Error::RowNotFound) => {}
                Err(error) => return Err(error.into()),
            }
            if EntryRepository::has_file_folder_collision(to, &mut executor).await? {
                return Err(FileIoError::PathCollision);
            }

            let moved_bytes = entries.iter().fold(0u64, |total, entry| {
                total.saturating_add(entry.content_length.saturating_add(FILE_METADATA_SIZE))
            });

            if let Some(destination_user) = destination_user.as_mut() {
                let bounded_delta = moved_bytes.min(i64::MAX as u64) as i64;
                let max_bytes = crate::persistence::files::storage_quota::resolve_storage_max_bytes(
                    destination_user,
                    self.default_storage_mb,
                );
                if crate::persistence::files::storage_quota::would_exceed_limit(
                    destination_user.used_bytes,
                    bounded_delta,
                    max_bytes,
                ) {
                    return Err(FileIoError::DiskSpaceQuotaExceeded);
                }
                destination_user.used_bytes = destination_user
                    .used_bytes
                    .saturating_add_signed(bounded_delta);
                source_user.used_bytes = source_user.used_bytes.saturating_sub(moved_bytes);
                self.user_service
                    .update_in_tx(destination_user, &mut executor)
                    .await?;
                self.user_service
                    .update_in_tx(&source_user, &mut executor)
                    .await?;
            }

            let destination_user_id = destination_user
                .as_ref()
                .map_or(source_user.id, |user| user.id);
            for entry in entries {
                let suffix = entry
                    .path
                    .path()
                    .as_str()
                    .strip_prefix(&source_prefix)
                    .ok_or(FileIoError::PathCollision)?;
                let destination_path = crate::shared::webdav::StoragePath::new(&format!(
                    "{destination_prefix}{suffix}"
                ))
                .map_err(|_| FileIoError::PathCollision)?;
                let destination_entry_path = EntryPath::new(to.pubkey().clone(), destination_path);
                let blob_key = Self::backend_key(&entry);
                EntryRepository::move_to(
                    entry.id,
                    destination_user_id,
                    destination_entry_path.path(),
                    &blob_key,
                    &mut executor,
                )
                .await?;
                self.events_service
                    .create_event(
                        destination_user_id,
                        crate::persistence::files::events::EventType::Put {
                            content_hash: entry.content_hash,
                        },
                        &destination_entry_path,
                        &mut executor,
                    )
                    .await?;
                self.events_service
                    .create_event(
                        source_user.id,
                        crate::persistence::files::events::EventType::Delete,
                        &entry.path,
                        &mut executor,
                    )
                    .await?;
            }
            Ok(())
        }
        .await;

        match result {
            Ok(()) => tx.commit().await?,
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::error!(%rollback_error, "Failed to roll back admin directory rename");
                }
                return Err(error);
            }
        }
        self.events_service.notify_event().await;
        Ok(())
    }

    async fn lock_move_users(
        &self,
        from: &EntryPath,
        to: &EntryPath,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<(UserEntity, Option<UserEntity>), sqlx::Error> {
        if from.pubkey() == to.pubkey() {
            return self
                .user_service
                .get_for_no_key_update(from.pubkey(), executor)
                .await
                .map(|user| (user, None));
        }
        if from.pubkey().z32() < to.pubkey().z32() {
            let source = self
                .user_service
                .get_for_no_key_update(from.pubkey(), executor)
                .await?;
            let destination = self
                .user_service
                .get_for_no_key_update(to.pubkey(), executor)
                .await?;
            Ok((source, Some(destination)))
        } else {
            let destination = self
                .user_service
                .get_for_no_key_update(to.pubkey(), executor)
                .await?;
            let source = self
                .user_service
                .get_for_no_key_update(from.pubkey(), executor)
                .await?;
            Ok((source, Some(destination)))
        }
    }

    /// Recover orphaned uploads and retry deferred backend deletion.
    pub(crate) async fn recover_blob_storage(&self) -> Result<(), FileIoError> {
        BlobRepository::enqueue_stale_uploads(
            ABANDONED_UPLOAD_AGE_SECONDS,
            STALE_UPLOAD_RECOVERY_GRACE_SECONDS,
            &mut self.db.pool().into(),
        )
        .await?;
        BlobRepository::prune_expired_read_leases(&mut self.db.pool().into()).await?;
        self.drain_blob_garbage().await;
        Ok(())
    }

    /// Queue immutable backend objects that are no longer represented in PostgreSQL.
    pub(crate) async fn reconcile_untracked_blobs(&self) -> Result<u64, FileIoError> {
        let mut lister = self.opendal.blob_lister().await?;
        let mut blob_keys = Vec::with_capacity(CLEANUP_BATCH_SIZE);
        let mut queued = 0;

        while let Some(entry) = lister.next().await {
            let entry = entry?;
            if !entry.metadata().is_file() {
                continue;
            }
            blob_keys.push(entry.path().to_string());
            if blob_keys.len() == CLEANUP_BATCH_SIZE {
                queued +=
                    BlobRepository::enqueue_untracked_blobs(&blob_keys, &mut self.db.pool().into())
                        .await?;
                blob_keys.clear();
            }
        }
        queued +=
            BlobRepository::enqueue_untracked_blobs(&blob_keys, &mut self.db.pool().into()).await?;
        Ok(queued)
    }

    async fn write_stream_inner(
        &self,
        path: &EntryPath,
        stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
        mode: WriteMode,
        size_hint: Option<u64>,
    ) -> Result<EntryEntity, FileIoError> {
        if mode.enforces_write_path() {
            self.check_write_path_allowed(path).await?;
        }

        let blob_key = format!("__pubky/blobs/{}", uuid::Uuid::new_v4().simple());
        let reservation = self.reserve_upload(path, &blob_key, size_hint).await?;
        let upload_heartbeat = UploadHeartbeat::start(self.db.clone(), blob_key.clone());

        let write_result = self
            .opendal
            .write_blob_stream_guarded(
                &blob_key,
                stream,
                path,
                reservation.max_blob_length,
                upload_heartbeat.cancellation(),
            )
            .await;
        let metadata = match write_result {
            Ok(metadata) => metadata,
            Err(error) => {
                upload_heartbeat.stop().await;
                self.abandon_upload(&blob_key, reservation.user_id, reservation.tracked_length)
                    .await;
                return Err(error);
            }
        };
        let upload_size_result = BlobRepository::set_upload_size(
            &blob_key,
            metadata.length as u64,
            &mut self.db.pool().into(),
        )
        .await;
        upload_heartbeat.stop().await;
        let upload_is_active = match upload_size_result {
            Ok(active) => active,
            Err(error) => {
                self.abandon_upload(&blob_key, reservation.user_id, metadata.length as u64)
                    .await;
                return Err(error.into());
            }
        };
        if !upload_is_active {
            self.abandon_upload(&blob_key, reservation.user_id, metadata.length as u64)
                .await;
            return Err(FileIoError::UploadLeaseLost);
        }

        let result = self.commit_write(path, &blob_key, &metadata, mode).await;
        match result {
            Ok(entry) => {
                self.events_service.notify_event().await;
                Ok(entry)
            }
            Err(CommitWriteError::BeforeCommit(error)) => {
                self.abandon_upload(&blob_key, reservation.user_id, metadata.length as u64)
                    .await;
                Err(error)
            }
            Err(CommitWriteError::CommitOutcomeUnknown(error)) => {
                // The transaction may have committed before the connection failed.
                // Durable upload recovery removes the blob only if it remained staged.
                Err(error)
            }
        }
    }

    async fn reserve_upload(
        &self,
        path: &EntryPath,
        blob_key: &str,
        size_hint: Option<u64>,
    ) -> Result<UploadReservation, FileIoError> {
        let mut tx = self.db.pool().begin().await?;
        let result = async {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            let user = self
                .user_service
                .get_for_no_key_update(path.pubkey(), &mut executor)
                .await?;
            let max_bytes = crate::persistence::files::storage_quota::resolve_storage_max_bytes(
                &user,
                self.default_storage_mb,
            );
            let reservation = match max_bytes {
                Some(max_bytes) => size_hint.unwrap_or(max_bytes),
                None => size_hint.unwrap_or(0),
            };
            if max_bytes.is_some_and(|max_bytes| reservation > max_bytes) {
                return Err(FileIoError::DiskSpaceQuotaExceeded);
            }
            let tracked =
                BlobRepository::tracked_bytes_for_user(user.id, FILE_METADATA_SIZE, &mut executor)
                    .await?;
            let physical_usage = user.used_bytes.saturating_add(tracked);
            if max_bytes.is_some_and(|max_bytes| {
                physical_usage.saturating_add(reservation.max(FILE_METADATA_SIZE))
                    > max_bytes.saturating_mul(PHYSICAL_STORAGE_QUOTA_MULTIPLIER)
            }) {
                return Err(FileIoError::DiskSpaceQuotaExceeded);
            }
            BlobRepository::stage_upload(blob_key, user.id, reservation, &mut executor).await?;
            Ok(UploadReservation {
                user_id: user.id,
                tracked_length: reservation,
                max_blob_length: max_bytes,
            })
        }
        .await;
        match result {
            Ok(reservation) => {
                tx.commit().await?;
                Ok(reservation)
            }
            Err(error) => {
                tx.rollback().await?;
                Err(error)
            }
        }
    }

    async fn commit_write(
        &self,
        path: &EntryPath,
        blob_key: &str,
        metadata: &super::super::FileMetadata,
        mode: WriteMode,
    ) -> Result<EntryEntity, CommitWriteError> {
        let mut tx = self
            .db
            .pool()
            .begin()
            .await
            .map_err(|error| CommitWriteError::BeforeCommit(error.into()))?;
        let result = async {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            let mut user = self
                .user_service
                .get_for_no_key_update(path.pubkey(), &mut executor)
                .await?;

            if EntryRepository::has_file_folder_collision(path, &mut executor).await? {
                return Err(FileIoError::PathCollision);
            }

            let existing = match EntryRepository::get_by_path(path, &mut executor).await {
                Ok(entry) => Some(entry),
                Err(sqlx::Error::RowNotFound) => None,
                Err(error) => return Err(error.into()),
            };
            if mode.requires_missing_destination() && existing.is_some() {
                return Err(FileIoError::PathCollision);
            }
            let existing_bytes = existing.as_ref().map_or(0, |entry| entry.content_length);
            let metadata_bytes = if existing.is_none() {
                FILE_METADATA_SIZE as i64
            } else {
                0
            };
            let bytes_delta = metadata.length as i64 - existing_bytes as i64 + metadata_bytes;
            let max_bytes = crate::persistence::files::storage_quota::resolve_storage_max_bytes(
                &user,
                self.default_storage_mb,
            );
            let tracked_blob_bytes =
                BlobRepository::tracked_bytes_for_user(user.id, FILE_METADATA_SIZE, &mut executor)
                    .await?;
            if max_bytes.is_some_and(|max_bytes| {
                user.used_bytes.saturating_add(tracked_blob_bytes)
                    > max_bytes.saturating_mul(PHYSICAL_STORAGE_QUOTA_MULTIPLIER)
            }) {
                return Err(FileIoError::DiskSpaceQuotaExceeded);
            }
            if crate::persistence::files::storage_quota::would_exceed_limit(
                user.used_bytes,
                bytes_delta,
                max_bytes,
            ) {
                return Err(FileIoError::DiskSpaceQuotaExceeded);
            }

            let old_blob_key = existing.as_ref().map(Self::backend_key);
            match existing {
                Some(mut entry) => {
                    entry.blob_key = Some(blob_key.to_string());
                    entry.content_hash = metadata.hash;
                    entry.content_length = metadata.length as u64;
                    entry.content_type = metadata.content_type.clone();
                    EntryRepository::update(&entry, &mut executor).await?;
                }
                None => {
                    EntryRepository::create_with_blob_key(
                        user.id,
                        path.path(),
                        Some(blob_key),
                        &metadata.hash,
                        metadata.length as u64,
                        &metadata.content_type,
                        &mut executor,
                    )
                    .await?;
                }
            }

            self.events_service
                .create_event(
                    user.id,
                    crate::persistence::files::events::EventType::Put {
                        content_hash: metadata.hash,
                    },
                    path,
                    &mut executor,
                )
                .await?;
            user.used_bytes = user.used_bytes.saturating_add_signed(bytes_delta);
            self.user_service.update_in_tx(&user, &mut executor).await?;
            BlobRepository::activate_upload(blob_key, &mut executor).await?;
            if let Some(old_blob_key) = old_blob_key {
                BlobRepository::enqueue_garbage(
                    &old_blob_key,
                    user.id,
                    existing_bytes,
                    ACTIVE_BLOB_RETENTION_SECONDS,
                    &mut executor,
                )
                .await?;
            }

            EntryRepository::get_by_path(path, &mut executor)
                .await
                .map_err(Into::into)
        }
        .await;

        match result {
            Ok(entry) => {
                tx.commit()
                    .await
                    .map_err(|error| CommitWriteError::CommitOutcomeUnknown(error.into()))?;
                Ok(entry)
            }
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::error!(%rollback_error, "Failed to roll back blob publication");
                }
                Err(CommitWriteError::BeforeCommit(error))
            }
        }
    }

    async fn delete_inner(
        &self,
        path: &EntryPath,
        enforce_write_policy: bool,
    ) -> Result<(), FileIoError> {
        if enforce_write_policy {
            self.check_write_path_allowed(path).await?;
        }

        match EntryRepository::get_by_path(path, &mut self.db.pool().into()).await {
            Ok(_) => {}
            Err(sqlx::Error::RowNotFound) => return Err(FileIoError::NotFound),
            Err(error) => return Err(error.into()),
        }

        let mut tx = self.db.pool().begin().await?;
        let result = async {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            let mut user = self
                .user_service
                .get_for_no_key_update(path.pubkey(), &mut executor)
                .await?;
            let entry = match EntryRepository::get_by_path(path, &mut executor).await {
                Ok(entry) => entry,
                Err(sqlx::Error::RowNotFound) => return Err(FileIoError::NotFound),
                Err(error) => return Err(error.into()),
            };
            EntryRepository::delete(entry.id, &mut executor).await?;
            self.events_service
                .create_event(
                    user.id,
                    crate::persistence::files::events::EventType::Delete,
                    path,
                    &mut executor,
                )
                .await?;
            user.used_bytes = user
                .used_bytes
                .saturating_sub(entry.content_length.saturating_add(FILE_METADATA_SIZE));
            self.user_service.update_in_tx(&user, &mut executor).await?;
            BlobRepository::enqueue_garbage(
                &Self::backend_key(&entry),
                user.id,
                entry.content_length,
                ACTIVE_BLOB_RETENTION_SECONDS,
                &mut executor,
            )
            .await?;
            Ok(())
        }
        .await;

        match result {
            Ok(()) => tx.commit().await?,
            Err(error) => {
                tx.rollback().await?;
                return Err(error);
            }
        }
        self.events_service.notify_event().await;
        Ok(())
    }

    async fn check_write_path_allowed(&self, path: &EntryPath) -> Result<(), FileIoError> {
        let Some(quota) = self.user_service.resolve_quota(path.pubkey()).await? else {
            return Ok(());
        };
        if quota.is_write_path_allowed(path.path().as_str()) {
            Ok(())
        } else {
            Err(FileIoError::WritePathForbidden)
        }
    }

    async fn abandon_upload(&self, blob_key: &str, user_id: i32, content_length: u64) {
        let result: Result<(), sqlx::Error> = async {
            let mut tx = self.db.pool().begin().await?;
            {
                let mut executor = UnifiedExecutor::from_tx(&mut tx);
                BlobRepository::abandon_upload(
                    blob_key,
                    user_id,
                    content_length,
                    ABANDONED_UPLOAD_SETTLE_SECONDS,
                    &mut executor,
                )
                .await?;
            }
            tx.commit().await?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::error!(blob_key, %error, "Failed to queue abandoned blob for cleanup");
        }
    }

    async fn drain_blob_garbage(&self) {
        let started_at = Instant::now();
        loop {
            if started_at.elapsed() >= CLEANUP_TIME_BUDGET.saturating_sub(CLEANUP_DELETE_TIMEOUT) {
                break;
            }
            let claims = match BlobRepository::claim_garbage(
                CLEANUP_BATCH_SIZE as i64,
                STALE_GARBAGE_CLAIM_SECONDS,
                &mut self.db.pool().into(),
            )
            .await
            {
                Ok(claims) if claims.is_empty() => break,
                Ok(claims) => claims,
                Err(error) => {
                    tracing::error!(%error, "Failed to claim blob cleanup work");
                    return;
                }
            };

            futures_util::stream::iter(claims)
                .for_each_concurrent(CLEANUP_CONCURRENCY, |claim| self.delete_claimed_blob(claim))
                .await;
        }
    }

    async fn delete_claimed_blob(&self, claim: BlobGarbageClaim) {
        match tokio::time::timeout(
            CLEANUP_DELETE_TIMEOUT,
            self.opendal.delete_by_key(&claim.blob_key),
        )
        .await
        {
            Ok(Ok(())) => {
                if let Err(error) =
                    BlobRepository::finish_garbage(&claim, &mut self.db.pool().into()).await
                {
                    tracing::error!(blob_key = claim.blob_key, %error, "Failed to finish blob cleanup");
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(blob_key = claim.blob_key, %error, "Blob cleanup will be retried");
                self.defer_garbage_claim(&claim).await;
            }
            Err(_) => {
                tracing::warn!(
                    blob_key = claim.blob_key,
                    "Blob cleanup timed out and will be retried"
                );
                self.defer_garbage_claim(&claim).await;
            }
        }
    }

    async fn defer_garbage_claim(&self, claim: &BlobGarbageClaim) {
        if let Err(error) = BlobRepository::defer_garbage(
            claim,
            FAILED_CLEANUP_RETRY_SECONDS,
            &mut self.db.pool().into(),
        )
        .await
        {
            tracing::error!(blob_key = claim.blob_key, %error, "Failed to defer blob cleanup claim");
        }
    }

    fn backend_key(entry: &EntryEntity) -> String {
        entry
            .blob_key
            .clone()
            .unwrap_or_else(|| entry.path.as_str().to_string())
    }
}

#[cfg(test)]
impl FileService {
    pub fn new_from_context(context: &AppContext) -> Result<Self, FileIoError> {
        let opendal_service = OpendalService::new(context)?;
        Ok(Self::new(
            opendal_service,
            context.sql_db.clone(),
            context.events_service.clone(),
            context.user_service.clone(),
            context.config_toml.storage.default_quota_mb,
        ))
    }

    /// Get the content of a file as bytes.
    /// Errors if the file does not exist.
    pub async fn get(&self, path: &EntryPath) -> Result<Bytes, FileIoError> {
        let mut stream = self.get_stream(path).await?;
        let mut collected_data = Vec::new();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            collected_data.extend_from_slice(&chunk);
        }

        Ok(Bytes::from(collected_data))
    }

    /// Write a complete file through the streamed storage path.
    pub async fn write(&self, path: &EntryPath, data: Buffer) -> Result<EntryEntity, FileIoError> {
        let stream = futures_util::stream::iter(vec![Ok(Bytes::from(data.to_vec()))]);
        let entry = self.write_stream(path, stream).await?;
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        services::user_service::FILE_METADATA_SIZE,
        shared::{quota::UserQuota, webdav::StoragePath},
        storage_config::StorageConfigToml,
    };
    use futures_lite::StreamExt;

    use super::*;

    async fn filesystem_context() -> std::sync::Arc<AppContext> {
        AppContext::test_with_config(|config| {
            config.storage.backend = StorageConfigToml::FileSystem;
        })
        .await
    }

    async fn fail_all_event_inserts(context: &AppContext) {
        sqlx::query(
            r#"
            CREATE FUNCTION fail_event_insert() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'forced event insert failure';
            END;
            $$ LANGUAGE plpgsql
            "#,
        )
        .execute(context.sql_db.pool())
        .await
        .unwrap();
        sqlx::query(
            r#"
            CREATE TRIGGER fail_event_insert_trigger
            BEFORE INSERT ON events
            FOR EACH ROW EXECUTE FUNCTION fail_event_insert()
            "#,
        )
        .execute(context.sql_db.pool())
        .await
        .unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_write_get_delete_db_and_opendal() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();

        let user = user_service.create(&pubkey).await.unwrap();

        // User should not have any data usage yet
        assert_eq!(user.used_bytes, 0);

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());

        // Test getting a non-existent file
        match file_service.get_stream(&path).await {
            Ok(_) => panic!("Should error for non-existent file"),
            Err(FileIoError::NotFound) => {}
            Err(e) => panic!("Should error for non-existent file: {}", e),
        };

        // Test data
        let test_data = b"Hello, world! This is test data for the get method.";
        let chunks = vec![Ok(Bytes::from(test_data.as_slice()))];
        let stream = futures_util::stream::iter(chunks);

        file_service.write_stream(&path, stream).await.unwrap();
        let user = user_service.get(&pubkey).await.unwrap();
        assert_eq!(
            user.used_bytes,
            test_data.len() as u64 + FILE_METADATA_SIZE,
            "Data usage should be the size of the file"
        );

        // Get the file content and verify
        let mut stream = file_service
            .get_stream(&path)
            .await
            .expect("File should exist");
        let mut collected_data = Vec::new();
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.unwrap();
            collected_data.extend_from_slice(&chunk);
        }

        assert_eq!(
            collected_data,
            test_data.to_vec(),
            "Content should match original data"
        );

        file_service.delete(&path).await.unwrap();
        let result = file_service.get_stream(&path).await;
        assert!(result.is_err(), "Should error for deleted file");
        let user = user_service.get(&pubkey).await.unwrap();
        assert_eq!(
            user.used_bytes, 0,
            "Data usage should be 0 after deleting file"
        );

        // Test OpenDal location
        let path = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/test_opendal.txt").unwrap(),
        );
        let chunks = vec![Ok(Bytes::from(test_data.as_slice()))];
        let stream = futures_util::stream::iter(chunks);
        file_service.write_stream(&path, stream).await.unwrap();
        let user = user_service.get(&pubkey).await.unwrap();
        assert_eq!(
            user.used_bytes,
            test_data.len() as u64 + FILE_METADATA_SIZE,
            "Data usage should be the size of the file"
        );

        // Get the file content and verify
        let mut stream = file_service
            .get_stream(&path)
            .await
            .expect("File should exist");
        let mut collected_data = Vec::new();
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.unwrap();
            collected_data.extend_from_slice(&chunk);
        }

        assert_eq!(
            collected_data,
            test_data.to_vec(),
            "Content should match original data for OpenDal location"
        );

        // Clean up
        file_service.delete(&path).await.unwrap();
        let result = file_service.get_stream(&path).await;
        assert!(result.is_err(), "Should error for deleted file");
        let user = user_service.get(&pubkey).await.unwrap();
        assert_eq!(
            user.used_bytes, 0,
            "Data usage should be 0 after deleting file"
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_write_get_basic() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create(&pubkey).await.unwrap();

        let test_data = b"Hello, world!";
        let buffer = Buffer::from(test_data.as_slice());

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
        file_service.write(&path, buffer.clone()).await.unwrap();
        let content = file_service.get(&path).await.unwrap();
        assert_eq!(content.as_ref(), test_data);

        // Test OpenDal
        let opendal_path = EntryPath::new(pubkey, StoragePath::new("/test_opendal.txt").unwrap());
        file_service.write(&opendal_path, buffer).await.unwrap();
        let content = file_service.get(&opendal_path).await.unwrap();
        assert_eq!(content.as_ref(), test_data);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_data_usage_update_basic() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create_with_quota_mb(&pubkey, 1).await;

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
        let test_data = vec![1u8; 1024];
        let buffer = Buffer::from(test_data.clone());

        file_service.write(&path, buffer).await.unwrap();
        let user = user_service.get(&pubkey).await.unwrap();
        assert_eq!(user.used_bytes, test_data.len() as u64 + FILE_METADATA_SIZE);

        // Delete the file and check if the data usage is updated correctly.
        file_service.delete(&path).await.unwrap();
        let user = user_service.get(&pubkey).await.unwrap();
        assert_eq!(user.used_bytes, 0);
    }

    /// Override and existing entry and check if the data usage is updated correctly.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_data_usage_override_existing_entry() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create_with_quota_mb(&pubkey, 1).await;

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
        let test_data = vec![1u8; 1024];
        let buffer = Buffer::from(test_data.clone());

        file_service.write(&path, buffer).await.unwrap();

        let test_data2 = vec![2u8; 1024];
        let buffer2 = Buffer::from(test_data2.clone());
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());

        file_service.write(&path, buffer2).await.unwrap();

        assert_eq!(
            user_service.get(&pubkey).await.unwrap().used_bytes,
            test_data2.len() as u64 + FILE_METADATA_SIZE
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_rejects_descendant_when_exact_file_exists() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let db = context.sql_db.clone();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create(&pubkey).await.unwrap();

        let exact_path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/foo").unwrap());
        let descendant_path = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/app/foo/bar.json").unwrap(),
        );

        file_service
            .write(&exact_path, Buffer::from(vec![1; 10]))
            .await
            .unwrap();
        let err = file_service
            .write(&descendant_path, Buffer::from(vec![2; 10]))
            .await
            .expect_err("descendant write should be rejected");

        assert!(matches!(err, FileIoError::PathCollision));
        file_service
            .get_info(&descendant_path, &mut db.pool().into())
            .await
            .expect_err("Rejected descendant should not create metadata");
        file_service
            .get(&descendant_path)
            .await
            .expect_err("Rejected descendant should not create a blob");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_rejects_exact_file_when_descendant_exists() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let db = context.sql_db.clone();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create(&pubkey).await.unwrap();

        let exact_path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/foo").unwrap());
        let descendant_path =
            EntryPath::new(pubkey, StoragePath::new("/pub/app/foo/bar.json").unwrap());

        file_service
            .write(&descendant_path, Buffer::from(vec![1; 10]))
            .await
            .unwrap();
        let err = file_service
            .write(&exact_path, Buffer::from(vec![2; 10]))
            .await
            .expect_err("exact-file write should be rejected");

        assert!(matches!(err, FileIoError::PathCollision));
        file_service
            .get_info(&exact_path, &mut db.pool().into())
            .await
            .expect_err("Rejected exact file should not create metadata");
        file_service
            .get(&exact_path)
            .await
            .expect_err("Rejected exact file should not create a blob");
    }

    /// Write a file that is exactly at the quota and check if the data usage is updated correctly.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_data_usage_exactly_to_quota() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create_with_quota_mb(&pubkey, 1).await;

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
        let test_data = vec![1u8; 1024 * 1024 - FILE_METADATA_SIZE as usize];
        let buffer = Buffer::from(test_data.clone());

        file_service.write(&path, buffer).await.unwrap();

        assert_eq!(
            user_service.get(&pubkey).await.unwrap().used_bytes,
            test_data.len() as u64 + FILE_METADATA_SIZE
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_data_usage_above_quota() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create_with_quota_mb(&pubkey, 1).await;

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
        let test_data = vec![1u8; 1024 * 1024 + 1];
        let buffer = Buffer::from(test_data.clone());

        match file_service.write(&path, buffer).await {
            Ok(_) => panic!("Should error for file above quota"),
            Err(FileIoError::DiskSpaceQuotaExceeded) => {} // All good
            Err(e) => {
                panic!("Should error for file above quota: {:?}", e);
            }
        }

        assert_eq!(user_service.get(&pubkey).await.unwrap().used_bytes, 0);
    }

    /// Override and existing entry and check if the data usage is updated correctly.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_data_usage_override_existing_above_quota() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let user_service = context.user_service.clone();

        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        user_service.create_with_quota_mb(&pubkey, 1).await;

        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());
        let test_data = vec![1u8; 1024];
        let buffer = Buffer::from(test_data.clone());

        file_service.write(&path, buffer).await.unwrap();

        let test_data2 = vec![2u8; 1024 * 1024 + 1];
        let buffer2 = Buffer::from(test_data2.clone());
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test_file.txt").unwrap());

        match file_service.write(&path, buffer2).await {
            Ok(_) => panic!("Should error for file above quota"),
            Err(FileIoError::DiskSpaceQuotaExceeded) => {} // All good
            Err(e) => {
                panic!("Should error for file above quota: {:?}", e);
            }
        }

        assert_eq!(
            user_service.get(&pubkey).await.unwrap().used_bytes,
            test_data.len() as u64 + FILE_METADATA_SIZE
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_legacy_entry_is_readable_and_rewritten_to_immutable_blob() {
        let context = filesystem_context().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        let user = context.user_service.create(&pubkey).await.unwrap();
        let path = EntryPath::new(pubkey, StoragePath::new("/pub/legacy.txt").unwrap());
        let legacy = Bytes::from_static(b"legacy");
        let metadata = file_service
            .opendal
            .write_blob_stream(
                path.as_str(),
                futures_util::stream::iter([Ok(legacy.clone())]),
                &path,
            )
            .await
            .unwrap();
        EntryRepository::create(
            user.id,
            path.path(),
            &metadata.hash,
            metadata.length as u64,
            &metadata.content_type,
            &mut context.sql_db.pool().into(),
        )
        .await
        .unwrap();

        assert_eq!(file_service.get(&path).await.unwrap(), legacy);
        let rewritten = file_service
            .write(&path, Buffer::from(b"new".to_vec()))
            .await
            .unwrap();
        assert!(rewritten.blob_key.is_some());
        assert_eq!(file_service.get(&path).await.unwrap().as_ref(), b"new");
        assert!(file_service
            .opendal
            .blob_exists(path.as_str())
            .await
            .unwrap());

        sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
            .execute(context.sql_db.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE blob_read_leases SET expires_at = statement_timestamp()")
            .execute(context.sql_db.pool())
            .await
            .unwrap();
        file_service.recover_blob_storage().await.unwrap();
        assert!(!file_service
            .opendal
            .blob_exists(path.as_str())
            .await
            .unwrap());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_legacy_entry_remains_readable_after_directory_move() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        let user = context.user_service.create(&pubkey).await.unwrap();
        let source_directory =
            EntryPath::new(pubkey.clone(), StoragePath::new("/pub/source").unwrap());
        let destination_directory =
            EntryPath::new(pubkey.clone(), StoragePath::new("/pub/moved").unwrap());
        let source = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/source/legacy.txt").unwrap(),
        );
        let destination =
            EntryPath::new(pubkey, StoragePath::new("/pub/moved/legacy.txt").unwrap());
        let content = Bytes::from_static(b"legacy");
        let metadata = file_service
            .opendal
            .write_blob_stream(
                source.as_str(),
                futures_util::stream::iter([Ok(content.clone())]),
                &source,
            )
            .await
            .unwrap();
        EntryRepository::create(
            user.id,
            source.path(),
            &metadata.hash,
            metadata.length as u64,
            &metadata.content_type,
            &mut context.sql_db.pool().into(),
        )
        .await
        .unwrap();

        file_service
            .admin_rename_directory(&source_directory, &destination_directory)
            .await
            .unwrap();

        assert!(matches!(
            file_service.get(&source).await,
            Err(FileIoError::NotFound)
        ));
        assert_eq!(file_service.get(&destination).await.unwrap(), content);
        let moved = file_service
            .get_info(&destination, &mut context.sql_db.pool().into())
            .await
            .unwrap();
        assert_eq!(moved.blob_key.as_deref(), Some(source.as_str()));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_failed_pointer_switch_preserves_previous_content() {
        let context = filesystem_context().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();
        let path = EntryPath::new(pubkey, StoragePath::new("/pub/state.bin").unwrap());
        let original = file_service
            .write(&path, Buffer::from(b"original".to_vec()))
            .await
            .unwrap();

        sqlx::query(
            r#"
            CREATE FUNCTION fail_blob_pointer_update() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'forced pointer failure';
            END;
            $$ LANGUAGE plpgsql
            "#,
        )
        .execute(context.sql_db.pool())
        .await
        .unwrap();
        sqlx::query(
            r#"
            CREATE TRIGGER fail_blob_pointer_update_trigger
            BEFORE UPDATE ON entries
            FOR EACH ROW EXECUTE FUNCTION fail_blob_pointer_update()
            "#,
        )
        .execute(context.sql_db.pool())
        .await
        .unwrap();

        file_service
            .write(&path, Buffer::from(b"replacement".to_vec()))
            .await
            .expect_err("pointer update should fail");
        let restarted_service = FileService::new_from_context(&context).unwrap();
        let entry = restarted_service
            .get_info(&path, &mut context.sql_db.pool().into())
            .await
            .unwrap();
        assert_eq!(entry.blob_key, original.blob_key);
        assert_eq!(
            restarted_service.get(&path).await.unwrap().as_ref(),
            b"original"
        );

        let staged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_uploads")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        let abandoned_key: String = sqlx::query_scalar("SELECT blob_key FROM blob_garbage")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        assert_eq!(staged, 0);
        assert!(restarted_service
            .opendal
            .blob_exists(&abandoned_key)
            .await
            .unwrap());
        restarted_service.recover_blob_storage().await.unwrap();
        assert!(restarted_service
            .opendal
            .blob_exists(&abandoned_key)
            .await
            .unwrap());
        sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
            .execute(context.sql_db.pool())
            .await
            .unwrap();
        restarted_service.recover_blob_storage().await.unwrap();
        assert!(!restarted_service
            .opendal
            .blob_exists(&abandoned_key)
            .await
            .unwrap());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_event_failure_rolls_back_write_and_cleans_blob() {
        let context = filesystem_context().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/state.bin").unwrap());
        fail_all_event_inserts(&context).await;

        file_service
            .write(&path, Buffer::from(b"content".to_vec()))
            .await
            .expect_err("event failure should fail the write");

        let restarted_service = FileService::new_from_context(&context).unwrap();
        assert!(matches!(
            restarted_service.get(&path).await,
            Err(FileIoError::NotFound)
        ));
        assert_eq!(
            context.user_service.get(&pubkey).await.unwrap().used_bytes,
            0
        );
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        let uploads: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_uploads")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        let abandoned_key: String = sqlx::query_scalar("SELECT blob_key FROM blob_garbage")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        assert_eq!(events, 0);
        assert_eq!(uploads, 0);
        assert!(restarted_service
            .opendal
            .blob_exists(&abandoned_key)
            .await
            .unwrap());
        restarted_service.recover_blob_storage().await.unwrap();
        assert!(restarted_service
            .opendal
            .blob_exists(&abandoned_key)
            .await
            .unwrap());
        sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
            .execute(context.sql_db.pool())
            .await
            .unwrap();
        restarted_service.recover_blob_storage().await.unwrap();
        assert!(!restarted_service
            .opendal
            .blob_exists(&abandoned_key)
            .await
            .unwrap());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_recovery_removes_stale_uploaded_blob() {
        let context = filesystem_context().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        let path = EntryPath::new(pubkey, StoragePath::new("/pub/orphan.bin").unwrap());
        let blob_key = "__pubky/blobs/stale-upload";

        BlobRepository::stage_upload(blob_key, 1, 6, &mut context.sql_db.pool().into())
            .await
            .unwrap();
        file_service
            .opendal
            .write_blob_stream(
                blob_key,
                futures_util::stream::iter([Ok(Bytes::from_static(b"orphan"))]),
                &path,
            )
            .await
            .unwrap();
        sqlx::query("UPDATE blob_uploads SET updated_at = CURRENT_TIMESTAMP - INTERVAL '2 hours'")
            .execute(context.sql_db.pool())
            .await
            .unwrap();

        let restarted_service = FileService::new_from_context(&context).unwrap();
        restarted_service.recover_blob_storage().await.unwrap();
        let staged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_uploads")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        let garbage: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        assert_eq!(staged, 0);
        assert_eq!(garbage, 1);
        assert!(restarted_service
            .opendal
            .blob_exists(blob_key)
            .await
            .unwrap());

        sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
            .execute(context.sql_db.pool())
            .await
            .unwrap();
        restarted_service.recover_blob_storage().await.unwrap();
        assert!(!restarted_service
            .opendal
            .blob_exists(blob_key)
            .await
            .unwrap());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_reconciliation_removes_untracked_blob_only() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();
        let path = EntryPath::new(pubkey, StoragePath::new("/pub/active.bin").unwrap());
        let active = file_service
            .write(&path, Buffer::from(b"active".to_vec()))
            .await
            .unwrap();
        let active_blob_key = active.blob_key.unwrap();
        let orphan_blob_key = "__pubky/blobs/late-orphan";
        file_service
            .opendal
            .write_blob_stream(
                orphan_blob_key,
                futures_util::stream::iter([Ok(Bytes::from_static(b"orphan"))]),
                &path,
            )
            .await
            .unwrap();

        assert_eq!(file_service.reconcile_untracked_blobs().await.unwrap(), 1);
        file_service.recover_blob_storage().await.unwrap();

        assert!(file_service
            .opendal
            .blob_exists(&active_blob_key)
            .await
            .unwrap());
        assert!(!file_service
            .opendal
            .blob_exists(orphan_blob_key)
            .await
            .unwrap());

        file_service
            .opendal
            .write_blob_stream(
                orphan_blob_key,
                futures_util::stream::iter([Ok(Bytes::from_static(b"late"))]),
                &path,
            )
            .await
            .unwrap();
        assert_eq!(file_service.reconcile_untracked_blobs().await.unwrap(), 1);
        file_service.recover_blob_storage().await.unwrap();
        assert!(!file_service
            .opendal
            .blob_exists(orphan_blob_key)
            .await
            .unwrap());
        assert_eq!(file_service.get(&path).await.unwrap().as_ref(), b"active");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_blob_cleanup_retries_backend_delete_failure() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();
        let first_path =
            EntryPath::new(pubkey.clone(), StoragePath::new("/pub/first.bin").unwrap());
        let second_path = EntryPath::new(pubkey, StoragePath::new("/pub/second.bin").unwrap());
        let first = file_service
            .write(&first_path, Buffer::from(b"first".to_vec()))
            .await
            .unwrap();
        let second = file_service
            .write(&second_path, Buffer::from(b"second".to_vec()))
            .await
            .unwrap();
        let first_blob_key = first.blob_key.unwrap();
        let second_blob_key = second.blob_key.unwrap();
        file_service.delete(&first_path).await.unwrap();
        file_service.delete(&second_path).await.unwrap();
        sqlx::query(
            "UPDATE blob_garbage SET available_at = CASE \
             WHEN blob_key = $1 THEN CURRENT_TIMESTAMP - INTERVAL '2 minutes' \
             ELSE CURRENT_TIMESTAMP - INTERVAL '1 minute' END",
        )
        .bind(&first_blob_key)
        .execute(context.sql_db.pool())
        .await
        .unwrap();

        file_service.opendal.fail_next_delete();
        file_service.recover_blob_storage().await.unwrap();
        assert!(file_service
            .opendal
            .blob_exists(&first_blob_key)
            .await
            .unwrap());
        assert!(!file_service
            .opendal
            .blob_exists(&second_blob_key)
            .await
            .unwrap());
        let pending: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COUNT(claim_token) FROM blob_garbage WHERE blob_key = $1",
        )
        .bind(&first_blob_key)
        .fetch_one(context.sql_db.pool())
        .await
        .unwrap();
        assert_eq!(pending, (1, 1));
        assert!(
            BlobRepository::create_read_lease(
                &first_blob_key,
                "late-reader",
                READ_LEASE_SECONDS,
                &mut context.sql_db.pool().into(),
            )
            .await
            .unwrap()
            .is_none(),
            "an ambiguous backend deletion must remain tombstoned"
        );

        sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP WHERE blob_key = $1")
            .bind(&first_blob_key)
            .execute(context.sql_db.pool())
            .await
            .unwrap();
        file_service.recover_blob_storage().await.unwrap();
        assert!(!file_service
            .opendal
            .blob_exists(&first_blob_key)
            .await
            .unwrap());
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage WHERE blob_key = $1")
                .bind(&first_blob_key)
                .fetch_one(context.sql_db.pool())
                .await
                .unwrap();
        assert_eq!(pending, 0);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_cleanup_recovers_after_blob_delete_before_acknowledgement() {
        let context = filesystem_context().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let path = EntryPath::new(public_key, StoragePath::new("/pub/state.bin").unwrap());
        let entry = file_service
            .write(&path, Buffer::from(b"content".to_vec()))
            .await
            .unwrap();
        let blob_key = entry.blob_key.unwrap();
        file_service.delete(&path).await.unwrap();
        sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
            .execute(context.sql_db.pool())
            .await
            .unwrap();
        let claim = BlobRepository::claim_garbage(
            1,
            STALE_GARBAGE_CLAIM_SECONDS,
            &mut context.sql_db.pool().into(),
        )
        .await
        .unwrap()
        .remove(0);
        file_service
            .opendal
            .delete_by_key(&claim.blob_key)
            .await
            .unwrap();

        sqlx::query(
            "UPDATE blob_garbage SET claimed_at = CURRENT_TIMESTAMP - INTERVAL '10 minutes'",
        )
        .execute(context.sql_db.pool())
        .await
        .unwrap();
        let restarted_service = FileService::new_from_context(&context).unwrap();
        restarted_service.recover_blob_storage().await.unwrap();

        assert!(!restarted_service
            .opendal
            .blob_exists(&blob_key)
            .await
            .unwrap());
        let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        assert_eq!(pending, 0);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_retained_versions_are_bounded_by_physical_quota() {
        let context = AppContext::test_with_config(|config| {
            config.storage.default_quota_mb = Some(1);
        })
        .await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let path = EntryPath::new(public_key, StoragePath::new("/pub/state.bin").unwrap());
        let content_length = 800 * 1024;

        for byte in [1, 2, 3] {
            file_service
                .write_stream_with_size_hint(
                    &path,
                    futures_util::stream::iter([Ok(Bytes::from(vec![byte; content_length]))]),
                    content_length as u64,
                )
                .await
                .unwrap();
        }

        let error = file_service
            .write_stream_with_size_hint(
                &path,
                futures_util::stream::iter([Ok(Bytes::from(vec![4; content_length]))]),
                content_length as u64,
            )
            .await
            .expect_err("retained versions must count toward physical storage limits");
        assert!(matches!(error, FileIoError::DiskSpaceQuotaExceeded));

        sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
            .execute(context.sql_db.pool())
            .await
            .unwrap();
        file_service.recover_blob_storage().await.unwrap();
        file_service
            .write_stream_with_size_hint(
                &path,
                futures_util::stream::iter([Ok(Bytes::from(vec![4; content_length]))]),
                content_length as u64,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_active_reader_delays_blob_cleanup() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let path = EntryPath::new(public_key, StoragePath::new("/pub/state.bin").unwrap());
        let original = file_service
            .write(&path, Buffer::from(b"original".to_vec()))
            .await
            .unwrap();
        let original_key = original.blob_key.clone().unwrap();
        let stream = file_service.get_entry_stream(&original).await.unwrap();

        file_service
            .write(&path, Buffer::from(b"replacement".to_vec()))
            .await
            .unwrap();
        sqlx::query("UPDATE blob_garbage SET available_at = statement_timestamp()")
            .execute(context.sql_db.pool())
            .await
            .unwrap();
        file_service.recover_blob_storage().await.unwrap();
        assert!(file_service
            .opendal
            .get_stream_by_key(&original_key)
            .await
            .is_ok());

        drop(stream);
        for _ in 0..20 {
            let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_read_leases")
                .fetch_one(context.sql_db.pool())
                .await
                .unwrap();
            if leases == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        file_service.recover_blob_storage().await.unwrap();
        assert!(matches!(
            file_service.opendal.get_stream_by_key(&original_key).await,
            Err(FileIoError::NotFound)
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_concurrent_local_readers_share_and_release_one_lease() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let path = EntryPath::new(public_key, StoragePath::new("/pub/state.bin").unwrap());
        let entry = file_service
            .write(&path, Buffer::from(b"content".to_vec()))
            .await
            .unwrap();

        let first = file_service.acquire_entry_read_lease(&entry).await.unwrap();
        let second = file_service.acquire_entry_read_lease(&entry).await.unwrap();

        assert!(Arc::ptr_eq(&first.inner, &second.inner));
        assert_eq!(
            file_service
                .read_leases
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1
        );
        let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_read_leases")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        assert_eq!(leases, 1);

        drop(first);
        let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_read_leases")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        assert_eq!(leases, 1);
        drop(second);
        for _ in 0..20 {
            let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_read_leases")
                .fetch_one(context.sql_db.pool())
                .await
                .unwrap();
            if leases == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the final reader should release the shared database lease");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_upload_heartbeat_times_out_while_row_is_locked() {
        let context = AppContext::test().await;
        BlobRepository::stage_upload("blob-a", 1, 10, &mut context.sql_db.pool().into())
            .await
            .unwrap();
        let mut tx = context.sql_db.pool().begin().await.unwrap();
        sqlx::query("SELECT blob_key FROM blob_uploads WHERE blob_key = 'blob-a' FOR UPDATE")
            .execute(&mut *tx)
            .await
            .unwrap();

        let error =
            UploadHeartbeat::touch_upload(&context.sql_db, "blob-a", Duration::from_millis(25))
                .await
                .unwrap_err();
        tx.rollback().await.unwrap();

        assert!(matches!(error, FileIoError::UploadLeaseLost));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_cleanup_drains_more_than_one_batch() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        let user = context.user_service.create(&public_key).await.unwrap();
        let content_path = EntryPath::new(public_key, StoragePath::new("/pub/blob").unwrap());

        for index in 0..80 {
            let blob_key = format!("__pubky/blobs/cleanup-{index}");
            file_service
                .opendal
                .write_blob_stream(
                    &blob_key,
                    futures_util::stream::iter([Ok(Bytes::from_static(b"x"))]),
                    &content_path,
                )
                .await
                .unwrap();
            BlobRepository::enqueue_garbage(
                &blob_key,
                user.id,
                1,
                0,
                &mut context.sql_db.pool().into(),
            )
            .await
            .unwrap();
        }

        file_service.recover_blob_storage().await.unwrap();

        let garbage: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        assert_eq!(garbage, 0);
        for index in 0..80 {
            assert!(!file_service
                .opendal
                .blob_exists(&format!("__pubky/blobs/cleanup-{index}"))
                .await
                .unwrap());
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_overwrite_rejects_file_directory_collisions() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let child = EntryPath::new(
            public_key.clone(),
            StoragePath::new("/pub/dir/child").unwrap(),
        );
        file_service
            .write(&child, Buffer::from(b"child".to_vec()))
            .await
            .unwrap();
        let parent = EntryPath::new(public_key.clone(), StoragePath::new("/pub/dir").unwrap());
        assert!(matches!(
            file_service
                .admin_write_stream(
                    &parent,
                    futures_util::stream::iter([Ok(Bytes::from_static(b"parent"))]),
                )
                .await,
            Err(FileIoError::PathCollision)
        ));

        let ancestor = EntryPath::new(public_key.clone(), StoragePath::new("/pub/file").unwrap());
        file_service
            .write(&ancestor, Buffer::from(b"file".to_vec()))
            .await
            .unwrap();
        let descendant = EntryPath::new(public_key, StoragePath::new("/pub/file/child").unwrap());
        assert!(matches!(
            file_service
                .admin_write_stream(
                    &descendant,
                    futures_util::stream::iter([Ok(Bytes::from_static(b"child"))]),
                )
                .await,
            Err(FileIoError::PathCollision)
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_event_failure_rolls_back_delete() {
        let context = filesystem_context().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/state.bin").unwrap());
        let original = file_service
            .write(&path, Buffer::from(b"content".to_vec()))
            .await
            .unwrap();
        let usage = context.user_service.get(&pubkey).await.unwrap().used_bytes;
        fail_all_event_inserts(&context).await;

        file_service
            .delete(&path)
            .await
            .expect_err("event failure should fail the delete");

        let restarted_service = FileService::new_from_context(&context).unwrap();
        let entry = restarted_service
            .get_info(&path, &mut context.sql_db.pool().into())
            .await
            .unwrap();
        assert_eq!(entry.blob_key, original.blob_key);
        assert_eq!(
            restarted_service.get(&path).await.unwrap().as_ref(),
            b"content"
        );
        assert_eq!(
            context.user_service.get(&pubkey).await.unwrap().used_bytes,
            usage
        );
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        let garbage: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        assert_eq!(events, 1);
        assert_eq!(garbage, 0);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_concurrent_file_folder_writes_commit_one() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();
        let ancestor = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/foo").unwrap());
        let descendant = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/app/foo/bar.json").unwrap(),
        );
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));

        let ancestor_write = {
            let service = file_service.clone();
            let path = ancestor.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                service.write(&path, Buffer::from(vec![1; 10])).await
            })
        };
        let descendant_write = {
            let service = file_service.clone();
            let path = descendant.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                service.write(&path, Buffer::from(vec![2; 20])).await
            })
        };
        barrier.wait().await;
        let ancestor_result = ancestor_write.await.unwrap();
        let descendant_result = descendant_write.await.unwrap();

        assert_ne!(ancestor_result.is_ok(), descendant_result.is_ok());
        let collision = ancestor_result
            .as_ref()
            .err()
            .or_else(|| descendant_result.as_ref().err())
            .unwrap();
        assert!(matches!(collision, FileIoError::PathCollision));
        let ancestor_entry =
            EntryRepository::get_by_path(&ancestor, &mut context.sql_db.pool().into()).await;
        let descendant_entry =
            EntryRepository::get_by_path(&descendant, &mut context.sql_db.pool().into()).await;
        assert_ne!(ancestor_entry.is_ok(), descendant_entry.is_ok());
        let content_length = ancestor_entry
            .as_ref()
            .map(|entry| entry.content_length)
            .unwrap_or_else(|_| descendant_entry.unwrap().content_length);
        assert_eq!(
            context.user_service.get(&pubkey).await.unwrap().used_bytes,
            content_length + FILE_METADATA_SIZE
        );
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        assert_eq!(events, 1);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_write_path_policy_rejects_disallowed_mutations() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        let user = context.user_service.create(&pubkey).await.unwrap();
        let quota = UserQuota {
            allowed_write_paths: Some(vec![StoragePath::new("/pub/allowed/").unwrap()]),
            ..Default::default()
        };
        context
            .user_service
            .set_quota_in_tx(user.id, &quota, &mut context.sql_db.pool().into())
            .await
            .unwrap();
        let allowed = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/allowed/data.bin").unwrap(),
        );
        let blocked = EntryPath::new(pubkey, StoragePath::new("/pub/blocked.bin").unwrap());

        file_service
            .write(&allowed, Buffer::from(b"allowed".to_vec()))
            .await
            .unwrap();
        file_service
            .admin_write_stream(
                &blocked,
                futures_util::stream::iter([Ok(Bytes::from_static(b"blocked"))]),
            )
            .await
            .unwrap();

        assert!(matches!(
            file_service
                .write(&blocked, Buffer::from(b"replacement".to_vec()))
                .await,
            Err(FileIoError::WritePathForbidden)
        ));
        assert!(matches!(
            file_service.delete(&blocked).await,
            Err(FileIoError::WritePathForbidden)
        ));
        assert_eq!(
            file_service.get(&blocked).await.unwrap().as_ref(),
            b"blocked"
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_loaded_entry_selects_one_immutable_version() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();
        let path = EntryPath::new(pubkey, StoragePath::new("/pub/state.bin").unwrap());
        let original = file_service
            .write(&path, Buffer::from(b"original".to_vec()))
            .await
            .unwrap();
        file_service
            .write(&path, Buffer::from(b"replacement".to_vec()))
            .await
            .unwrap();

        let mut original_stream = file_service.get_entry_stream(&original).await.unwrap();
        let mut original_content = Vec::new();
        while let Some(chunk) = original_stream.next().await {
            original_content.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(original_content, b"original");
        assert_eq!(
            file_service.get(&path).await.unwrap().as_ref(),
            b"replacement"
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_concurrent_writes_leave_one_complete_version() {
        let context = filesystem_context().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/state.bin").unwrap());
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));

        let first = {
            let service = file_service.clone();
            let path = path.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                service.write(&path, Buffer::from(b"aaa".to_vec())).await
            })
        };
        let second = {
            let service = file_service.clone();
            let path = path.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                service.write(&path, Buffer::from(b"bbb".to_vec())).await
            })
        };
        barrier.wait().await;
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();

        let restarted_service = FileService::new_from_context(&context).unwrap();
        let content = restarted_service.get(&path).await.unwrap();
        assert!(content.as_ref() == b"aaa" || content.as_ref() == b"bbb");
        assert_eq!(
            context.user_service.get(&pubkey).await.unwrap().used_bytes,
            3 + FILE_METADATA_SIZE
        );
        let entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        assert_eq!(entries, 1);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_concurrent_write_and_delete_leave_consistent_state() {
        let context = filesystem_context().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let path = EntryPath::new(
            public_key.clone(),
            StoragePath::new("/pub/state.bin").unwrap(),
        );
        file_service
            .write(&path, Buffer::from(b"old".to_vec()))
            .await
            .unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));

        let write = {
            let service = file_service.clone();
            let path = path.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                service.write(&path, Buffer::from(b"new".to_vec())).await
            })
        };
        let delete = {
            let service = file_service.clone();
            let path = path.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                service.delete(&path).await
            })
        };
        barrier.wait().await;
        write.await.unwrap().unwrap();
        delete.await.unwrap().unwrap();

        let restarted_service = FileService::new_from_context(&context).unwrap();
        let content = restarted_service.get(&path).await;
        let entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        let used_bytes = context
            .user_service
            .get(&public_key)
            .await
            .unwrap()
            .used_bytes;
        match content {
            Ok(content) => {
                assert_eq!(content.as_ref(), b"new");
                assert_eq!(entries, 1);
                assert_eq!(used_bytes, 3 + FILE_METADATA_SIZE);
            }
            Err(FileIoError::NotFound) => {
                assert_eq!(entries, 0);
                assert_eq!(used_bytes, 0);
            }
            Err(error) => panic!("unexpected read error after concurrent mutation: {error}"),
        }
        let staged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_uploads")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        assert_eq!(staged, 0);

        sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
            .execute(context.sql_db.pool())
            .await
            .unwrap();
        restarted_service.recover_blob_storage().await.unwrap();
        let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
            .fetch_one(context.sql_db.pool())
            .await
            .unwrap();
        assert_eq!(pending, 0);
        match restarted_service.get(&path).await {
            Ok(content) => assert_eq!(content.as_ref(), b"new"),
            Err(FileIoError::NotFound) => {}
            Err(error) => panic!("unexpected read error after cleanup: {error}"),
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_copy_and_rename_use_logical_entries() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();
        let source = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/source.txt").unwrap());
        let copy = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/copy.txt").unwrap());
        let renamed = EntryPath::new(pubkey, StoragePath::new("/pub/renamed.txt").unwrap());

        file_service
            .write(&source, Buffer::from(b"content".to_vec()))
            .await
            .unwrap();
        file_service.admin_copy(&source, &copy).await.unwrap();
        assert_eq!(
            file_service.get(&source).await.unwrap().as_ref(),
            b"content"
        );
        assert_eq!(file_service.get(&copy).await.unwrap().as_ref(), b"content");

        let copied_entry = file_service
            .get_info(&copy, &mut context.sql_db.pool().into())
            .await
            .unwrap();
        file_service.admin_rename(&copy, &renamed).await.unwrap();
        assert!(matches!(
            file_service.get(&copy).await,
            Err(FileIoError::NotFound)
        ));
        assert_eq!(
            file_service.get(&renamed).await.unwrap().as_ref(),
            b"content"
        );
        let renamed_entry = file_service
            .get_info(&renamed, &mut context.sql_db.pool().into())
            .await
            .unwrap();
        assert_eq!(renamed_entry.blob_key, copied_entry.blob_key);
        file_service.admin_rename(&renamed, &renamed).await.unwrap();
        assert_eq!(
            file_service.get(&renamed).await.unwrap().as_ref(),
            b"content"
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_copy_and_rename_reject_destination_collisions() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();
        let source = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/source.txt").unwrap());
        let destination = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/destination.txt").unwrap(),
        );
        file_service
            .write(&source, Buffer::from(b"source".to_vec()))
            .await
            .unwrap();
        file_service
            .write(&destination, Buffer::from(b"destination".to_vec()))
            .await
            .unwrap();

        assert!(matches!(
            file_service.admin_copy(&source, &destination).await,
            Err(FileIoError::PathCollision)
        ));
        assert!(matches!(
            file_service.admin_rename(&source, &destination).await,
            Err(FileIoError::PathCollision)
        ));
        assert_eq!(file_service.get(&source).await.unwrap().as_ref(), b"source");
        assert_eq!(
            file_service.get(&destination).await.unwrap().as_ref(),
            b"destination"
        );
        let destination_descendant = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/destination.txt/child.txt").unwrap(),
        );
        assert!(matches!(
            file_service
                .admin_copy(&source, &destination_descendant)
                .await,
            Err(FileIoError::PathCollision)
        ));

        let source_directory =
            EntryPath::new(pubkey.clone(), StoragePath::new("/pub/source").unwrap());
        let destination_directory = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/destination").unwrap(),
        );
        let source_child = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/source/child.txt").unwrap(),
        );
        let destination_child = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/destination/child.txt").unwrap(),
        );
        file_service
            .write(&source_child, Buffer::from(b"source child".to_vec()))
            .await
            .unwrap();
        file_service
            .write(
                &destination_child,
                Buffer::from(b"destination child".to_vec()),
            )
            .await
            .unwrap();

        assert!(matches!(
            file_service
                .admin_copy(&source, &destination_directory)
                .await,
            Err(FileIoError::PathCollision)
        ));
        assert!(matches!(
            file_service
                .admin_rename(&source, &destination_directory)
                .await,
            Err(FileIoError::PathCollision)
        ));
        let directory_below_file = EntryPath::new(
            pubkey,
            StoragePath::new("/pub/destination.txt/moved").unwrap(),
        );
        assert!(matches!(
            file_service
                .admin_rename_directory(&source_directory, &directory_below_file)
                .await,
            Err(FileIoError::PathCollision)
        ));
        assert!(matches!(
            file_service
                .admin_rename_directory(&source_directory, &destination_directory)
                .await,
            Err(FileIoError::PathCollision)
        ));
        assert_eq!(
            file_service.get(&source_child).await.unwrap().as_ref(),
            b"source child"
        );
        assert_eq!(
            file_service.get(&destination_child).await.unwrap().as_ref(),
            b"destination child"
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_rename_across_users_updates_accounting_and_events() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let source_pubkey = pubky_common::crypto::Keypair::random().public_key();
        let destination_pubkey = pubky_common::crypto::Keypair::random().public_key();
        let source_user = context.user_service.create(&source_pubkey).await.unwrap();
        let destination_user = context
            .user_service
            .create(&destination_pubkey)
            .await
            .unwrap();
        let source = EntryPath::new(
            source_pubkey.clone(),
            StoragePath::new("/pub/source.txt").unwrap(),
        );
        let destination = EntryPath::new(
            destination_pubkey.clone(),
            StoragePath::new("/pub/destination.txt").unwrap(),
        );
        let source_entry = file_service
            .write(&source, Buffer::from(b"source".to_vec()))
            .await
            .unwrap();

        file_service
            .admin_rename(&source, &destination)
            .await
            .unwrap();

        assert!(matches!(
            file_service.get(&source).await,
            Err(FileIoError::NotFound)
        ));
        assert_eq!(
            file_service.get(&destination).await.unwrap().as_ref(),
            b"source"
        );
        let destination_entry = file_service
            .get_info(&destination, &mut context.sql_db.pool().into())
            .await
            .unwrap();
        assert_eq!(destination_entry.blob_key, source_entry.blob_key);
        assert_eq!(
            context
                .user_service
                .get(&source_pubkey)
                .await
                .unwrap()
                .used_bytes,
            0
        );
        assert_eq!(
            context
                .user_service
                .get(&destination_pubkey)
                .await
                .unwrap()
                .used_bytes,
            b"source".len() as u64 + FILE_METADATA_SIZE
        );
        let events: Vec<(i32, String, String)> =
            sqlx::query_as("SELECT \"user\", type, path FROM events ORDER BY id DESC LIMIT 2")
                .fetch_all(context.sql_db.pool())
                .await
                .unwrap();
        assert_eq!(
            events,
            vec![
                (source_user.id, "DEL".to_string(), source.path().to_string()),
                (
                    destination_user.id,
                    "PUT".to_string(),
                    destination.path().to_string()
                ),
            ]
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_directory_rename_across_users_respects_quota() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let source_pubkey = pubky_common::crypto::Keypair::random().public_key();
        let destination_pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&source_pubkey).await.unwrap();
        context
            .user_service
            .create_with_quota_mb(&destination_pubkey, 0)
            .await;
        let source_directory = EntryPath::new(
            source_pubkey.clone(),
            StoragePath::new("/pub/source").unwrap(),
        );
        let source = EntryPath::new(
            source_pubkey.clone(),
            StoragePath::new("/pub/source/file.txt").unwrap(),
        );
        let destination_directory = EntryPath::new(
            destination_pubkey.clone(),
            StoragePath::new("/pub/destination").unwrap(),
        );
        let destination = EntryPath::new(
            destination_pubkey.clone(),
            StoragePath::new("/pub/destination/file.txt").unwrap(),
        );
        file_service
            .write(&source, Buffer::from(b"content".to_vec()))
            .await
            .unwrap();
        let source_usage = context
            .user_service
            .get(&source_pubkey)
            .await
            .unwrap()
            .used_bytes;

        assert!(matches!(
            file_service
                .admin_rename_directory(&source_directory, &destination_directory)
                .await,
            Err(FileIoError::DiskSpaceQuotaExceeded)
        ));
        assert_eq!(
            file_service.get(&source).await.unwrap().as_ref(),
            b"content"
        );
        assert!(matches!(
            file_service.get(&destination).await,
            Err(FileIoError::NotFound)
        ));
        assert_eq!(
            context
                .user_service
                .get(&source_pubkey)
                .await
                .unwrap()
                .used_bytes,
            source_usage
        );
        assert_eq!(
            context
                .user_service
                .get(&destination_pubkey)
                .await
                .unwrap()
                .used_bytes,
            0
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_rename_serializes_source_overwrite() {
        let context = AppContext::test().await;
        let file_service = FileService::new_from_context(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();
        let source = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/source.txt").unwrap());
        let renamed = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/renamed.txt").unwrap(),
        );
        file_service
            .write(&source, Buffer::from(b"old".to_vec()))
            .await
            .unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));

        let rename = {
            let service = file_service.clone();
            let source = source.clone();
            let renamed = renamed.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                service.admin_rename(&source, &renamed).await
            })
        };
        let overwrite = {
            let service = file_service.clone();
            let source = source.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                service.write(&source, Buffer::from(b"new".to_vec())).await
            })
        };
        barrier.wait().await;
        rename.await.unwrap().unwrap();
        overwrite.await.unwrap().unwrap();

        let source_content = file_service.get(&source).await;
        let renamed_content = file_service.get(&renamed).await.unwrap();
        match source_content {
            Ok(content) => {
                assert_eq!(content.as_ref(), b"new");
                assert_eq!(renamed_content.as_ref(), b"old");
                assert_eq!(
                    context.user_service.get(&pubkey).await.unwrap().used_bytes,
                    6 + 2 * FILE_METADATA_SIZE
                );
            }
            Err(FileIoError::NotFound) => {
                assert_eq!(renamed_content.as_ref(), b"new");
                assert_eq!(
                    context.user_service.get(&pubkey).await.unwrap().used_bytes,
                    3 + FILE_METADATA_SIZE
                );
            }
            Err(error) => panic!("unexpected source read error: {error}"),
        }
    }
}
