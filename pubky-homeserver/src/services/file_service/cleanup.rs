use crate::persistence::{files::FileIoError, sql::entities::blob::BlobRepository};
use futures_util::StreamExt;
use std::time::Duration;
use tokio::time::Instant;

use super::FileService;

const FAILED_CLEANUP_RETRY_SECONDS: i64 = 60;
const CLEANUP_BATCH_SIZE: usize = 64;
const CLEANUP_CONCURRENCY: usize = 8;
const CLEANUP_TIME_BUDGET: Duration = Duration::from_secs(45);
const CLEANUP_DELETE_TIMEOUT: Duration = Duration::from_secs(5);

impl FileService {
    /// Retry deletion of expired uploads and unreferenced blobs.
    pub(crate) async fn recover_blob_storage(&self) -> Result<(), FileIoError> {
        let deadline = Instant::now() + CLEANUP_TIME_BUDGET;
        while Instant::now() < deadline && self.cleanup_batch(None, deadline).await? > 0 {}
        Ok(())
    }

    /// Queue immutable backend objects no longer represented in PostgreSQL.
    pub(crate) async fn reconcile_untracked_blobs(&self) -> Result<u64, FileIoError> {
        let mut lister = self.opendal.blob_lister(&self.blob_prefix).await?;
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

    pub(super) async fn cleanup_for_quota(&self, user_id: i32) {
        if let Err(error) = self
            .cleanup_batch(Some(user_id), Instant::now() + CLEANUP_TIME_BUDGET)
            .await
        {
            tracing::error!(%error, "Failed to clean up unreferenced blobs for quota");
        }
    }

    async fn cleanup_batch(
        &self,
        quota_user_id: Option<i32>,
        deadline: Instant,
    ) -> Result<usize, sqlx::Error> {
        let batch = async {
            let mut tx = self.db.pool().begin().await?;
            let keys =
                BlobRepository::lock_garbage(CLEANUP_BATCH_SIZE as i64, quota_user_id, &mut tx)
                    .await?;
            let count = keys.len();
            // Only backend I/O runs concurrently; ownership and acknowledgments use this transaction.
            let results = futures_util::stream::iter(keys)
                .map(|key| async move {
                    let deleted = match tokio::time::timeout(
                        CLEANUP_DELETE_TIMEOUT,
                        self.opendal.delete_by_key(&key),
                    )
                    .await
                    {
                        Ok(Ok(())) => true,
                        Ok(Err(error)) => {
                            tracing::warn!(blob_key = key, %error, "Blob cleanup will be retried");
                            false
                        }
                        Err(_) => {
                            tracing::warn!(
                                blob_key = key,
                                "Blob cleanup timed out and will be retried"
                            );
                            false
                        }
                    };
                    (key, deleted)
                })
                .buffer_unordered(CLEANUP_CONCURRENCY)
                .collect::<Vec<_>>()
                .await;
            for (key, deleted) in results {
                if deleted {
                    BlobRepository::finish_garbage(&key, &mut tx).await?;
                } else {
                    BlobRepository::defer_garbage(&key, FAILED_CLEANUP_RETRY_SECONDS, &mut tx)
                        .await?;
                }
            }
            tx.commit().await?;
            Ok::<_, sqlx::Error>(count)
        };
        match tokio::time::timeout_at(deadline, batch).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!("Blob cleanup reached its time budget");
                Ok(0)
            }
        }
    }
}
