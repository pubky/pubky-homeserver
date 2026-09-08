use crate::persistence::{
    files::FileIoError,
    sql::{entities::blob::BlobRepository, SqlDb},
};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const UPLOAD_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
const UPLOAD_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct UploadHeartbeat {
    handle: Option<JoinHandle<()>>,
    cancellation: CancellationToken,
}

impl UploadHeartbeat {
    pub(super) fn start(db: SqlDb, blob_key: String) -> Self {
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

    pub(super) async fn touch_upload(
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

    pub(super) fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    pub(super) async fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Drop for UploadHeartbeat {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}
