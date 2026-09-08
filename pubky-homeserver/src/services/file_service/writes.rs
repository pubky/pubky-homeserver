use crate::{
    persistence::{
        files::{FileIoError, WriteStreamError},
        sql::{
            entities::blob::BlobRepository,
            entry::{EntryEntity, EntryRepository},
            UnifiedExecutor,
        },
    },
    services::user_service::FILE_METADATA_SIZE,
    shared::webdav::EntryPath,
};
use bytes::Bytes;
use futures_util::Stream;

use super::{upload_heartbeat::UploadHeartbeat, FileService};

// A failed remote close can complete after the client loses the response.
const ABANDONED_UPLOAD_SETTLE_SECONDS: i64 = 60 * 60;
const ACTIVE_BLOB_RETENTION_SECONDS: i64 = 5 * 60;
// Bound physical data to the active version, one retained version, and one replacement upload.
const PHYSICAL_STORAGE_QUOTA_MULTIPLIER: u64 = 3;

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
pub(super) enum WriteMode {
    Client,
    AdminOverwrite,
    AdminCreate,
}

impl WriteMode {
    fn enforces_write_path(self) -> bool {
        matches!(self, Self::Client)
    }

    fn enforces_path_collisions(self) -> bool {
        matches!(self, Self::Client)
    }

    fn requires_missing_destination(self) -> bool {
        matches!(self, Self::AdminCreate)
    }
}

impl FileService {
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

    pub(super) async fn write_stream_inner(
        &self,
        path: &EntryPath,
        stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
        mode: WriteMode,
        size_hint: Option<u64>,
    ) -> Result<EntryEntity, FileIoError> {
        if mode.enforces_write_path() {
            self.check_write_path_allowed(path).await?;
        }

        let blob_key = format!("{}{}", self.blob_prefix, uuid::Uuid::new_v4().simple());
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
        metadata: &crate::persistence::files::FileMetadata,
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

            if mode.enforces_path_collisions()
                && EntryRepository::has_file_folder_collision(path, &mut executor).await?
            {
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

    pub(super) async fn delete_inner(
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
}
