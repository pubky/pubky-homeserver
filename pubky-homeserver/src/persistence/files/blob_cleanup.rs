use std::time::Duration;

use tokio::task::JoinHandle;

use super::FileService;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Periodically retries durable blob cleanup work.
pub(crate) struct BlobCleanupTask {
    handles: [JoinHandle<()>; 2],
}

impl BlobCleanupTask {
    #[must_use = "the cleanup task stops when its handle is dropped"]
    pub(crate) fn start(file_service: FileService) -> Self {
        let cleanup_service = file_service.clone();
        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(error) = cleanup_service.recover_blob_storage().await {
                    tracing::error!(%error, "Failed to recover blob storage");
                }
            }
        });
        let reconciliation_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(RECONCILIATION_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                match file_service.reconcile_untracked_blobs().await {
                    Ok(queued) if queued > 0 => {
                        tracing::warn!(queued, "Queued untracked backend blobs for cleanup");
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::error!(%error, "Failed to reconcile backend blobs");
                    }
                }
            }
        });
        Self {
            handles: [cleanup_handle, reconciliation_handle],
        }
    }
}

impl Drop for BlobCleanupTask {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}
