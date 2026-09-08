use crate::{
    persistence::{
        files::{FileIoError, FileStream},
        sql::{
            entities::blob::{BlobReadLeaseEntity, BlobRepository},
            entry::{EntryEntity, EntryRepository},
            SqlDb, UnifiedExecutor,
        },
    },
    shared::webdav::EntryPath,
};
use bytes::Bytes;
use futures_util::Stream;
use lru::LruCache;
use std::{
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

use super::FileService;

pub(super) const READ_LEASE_SECONDS: i64 = 2 * 60;
const READ_LEASE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const READ_LEASE_DATABASE_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const READ_LEASE_CACHE_CAPACITY: usize = 4096;

#[derive(Debug)]
pub(super) struct ActiveBlobReadLease {
    record: BlobReadLeaseEntity,
    cancellation: CancellationToken,
    db: SqlDb,
}

type ReadLeaseCell = Arc<tokio::sync::Mutex<Weak<ActiveBlobReadLease>>>;
pub(super) type ReadLeaseCache = LruCache<String, ReadLeaseCell>;

/// Keeps one immutable backend object alive while a response or DAV handle reads it.
pub(crate) struct BlobReadLease {
    pub(super) inner: Arc<ActiveBlobReadLease>,
}

struct LeaseProtectedStream {
    stream: FileStream,
    lease: Option<BlobReadLease>,
    terminated: bool,
}

impl ActiveBlobReadLease {
    fn start(db: SqlDb, record: BlobReadLeaseEntity) -> Arc<Self> {
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
    pub(crate) fn is_active(&self) -> bool {
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

impl FileService {
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
}
