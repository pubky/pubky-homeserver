use crate::persistence::{
    files::FileIoError,
    sql::entities::blob::{BlobGarbageEntity, BlobRepository},
};
use futures_util::StreamExt;
use std::time::{Duration, Instant};

use super::FileService;

const ABANDONED_UPLOAD_AGE_SECONDS: i64 = 60 * 60;
const STALE_UPLOAD_RECOVERY_GRACE_SECONDS: i64 = 5 * 60;
pub(super) const STALE_GARBAGE_CLAIM_SECONDS: i64 = 5 * 60;
const FAILED_CLEANUP_RETRY_SECONDS: i64 = 60;
const CLEANUP_BATCH_SIZE: usize = 64;
const CLEANUP_CONCURRENCY: usize = 8;
const CLEANUP_TIME_BUDGET: Duration = Duration::from_secs(45);
const CLEANUP_DELETE_TIMEOUT: Duration = Duration::from_secs(5);

impl FileService {
    /// Recover orphaned uploads and retry deferred backend deletion.
    pub(crate) async fn recover_blob_storage(&self) -> Result<(), FileIoError> {
        BlobRepository::enqueue_stale_uploads(
            ABANDONED_UPLOAD_AGE_SECONDS,
            STALE_UPLOAD_RECOVERY_GRACE_SECONDS,
            &mut self.db.pool().into(),
        )
        .await?;
        self.drain_blob_garbage().await;
        Ok(())
    }

    /// Queue immutable backend objects that are no longer represented in PostgreSQL.
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

    async fn delete_claimed_blob(&self, claim: BlobGarbageEntity) {
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

    async fn defer_garbage_claim(&self, claim: &BlobGarbageEntity) {
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
}
