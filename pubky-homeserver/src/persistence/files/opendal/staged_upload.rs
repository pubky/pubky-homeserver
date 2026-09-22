use bytes::Bytes;
use futures_util::{stream::StreamExt, Stream};
use opendal::Operator;

use super::super::{FileIoError, WriteStreamError};
use super::finalization::spawn_finalization;
use crate::shared::webdav::EntryPath;

/// An upload the backend has staged but not published, so the existing blob
/// is untouched until [`publish`](Self::publish). The write lifecycle is
/// described in the [`files`](crate::persistence::files) module docs.
///
/// `publish` and [`discard`](Self::discard) consume the upload. One dropped
/// before either is discarded on a spawned task so its staged bytes do not
/// linger.
pub(super) struct StagedUpload {
    /// `None` once published or discarded.
    writer: Option<opendal::Writer>,
    path: EntryPath,
}

impl StagedUpload {
    pub(super) async fn begin(operator: &Operator, path: &EntryPath) -> Result<Self, FileIoError> {
        let writer = operator.writer(path.as_str()).await?;
        Ok(Self {
            writer: Some(writer),
            path: path.clone(),
        })
    }

    /// Stage every chunk of `stream`, stopping at its first error.
    pub(super) async fn write_all(
        &mut self,
        mut stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin,
    ) -> Result<(), FileIoError> {
        let writer = self
            .writer
            .as_mut()
            .expect("upload is written to before it is published or discarded");
        while let Some(chunk_result) = stream.next().await {
            writer.write(chunk_result?).await?;
        }
        Ok(())
    }

    /// Publish the staged bytes and commit their entry, on a task that
    /// outlives a dropped request.
    pub(super) async fn publish(mut self) -> Result<(), FileIoError> {
        let mut writer = self.take_writer();
        spawn_finalization(async move { writer.close().await })
            .await
            .map(|_backend_metadata| ())
    }

    /// Drop the staged bytes. The caller reports why, so a failed cleanup is
    /// only logged.
    pub(super) async fn discard(mut self) {
        if let Err(error) = self.take_writer().abort().await {
            tracing::warn!(path = %self.path, %error, "Failed to abort broken upload");
        }
    }

    fn take_writer(&mut self) -> opendal::Writer {
        self.writer
            .take()
            .expect("upload is published or discarded at most once")
    }
}

impl Drop for StagedUpload {
    fn drop(&mut self) {
        let Some(mut writer) = self.writer.take() else {
            return;
        };
        let path = self.path.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = writer.abort().await {
                    tracing::debug!(%path, %error, "Could not abort dropped upload");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use bytes::Bytes;
    use futures_util::StreamExt;

    use super::super::opendal_service::OpendalService;
    use crate::persistence::files::write_finalization_layer::test_support::wait_until;
    use crate::persistence::files::{FileIoError, WriteStreamError};
    use crate::shared::webdav::{EntryPath, StoragePath};
    use crate::storage_config::StorageConfigToml;
    use crate::AppContext;

    /// A service on the production filesystem backend, a user with `quota_mb`,
    /// a file path of theirs holding `old`, and the staging directory.
    async fn fs_service_with_old_file(
        quota_mb: u64,
    ) -> (Arc<AppContext>, OpendalService, EntryPath, PathBuf) {
        let context = AppContext::test_with_config(|c| {
            c.storage.backend = StorageConfigToml::FileSystem;
        })
        .await;
        let service = OpendalService::new(&context).unwrap();
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        context
            .user_service
            .create_with_quota_mb(&pubkey, quota_mb)
            .await;
        let path = EntryPath::new(pubkey, StoragePath::new("/pub/test.txt").unwrap());
        service.write(&path, b"old".to_vec()).await.unwrap();
        let staging_dir = context.data_dir.path().join("data/files-tmp");
        assert_eq!(staged_count(&staging_dir), 0);
        (context, service, path, staging_dir)
    }

    fn staged_count(staging_dir: &Path) -> usize {
        std::fs::read_dir(staging_dir).map_or(0, Iterator::count)
    }

    async fn wait_for_staged_count(staging_dir: &Path, expected: usize, message: &str) {
        wait_until(|| async { staged_count(staging_dir) == expected }, message).await;
    }

    /// A client that disconnects mid-upload drops the request future. The
    /// staged bytes must be cleaned up and the existing file left alone.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn dropped_upload_leaves_no_staged_file_and_the_old_bytes() {
        let (_context, service, path, staging_dir) = fs_service_with_old_file(1).await;

        // One chunk, then the body never completes.
        let stream = futures_util::stream::iter([Ok(Bytes::from_static(b"partial"))])
            .chain(futures_util::stream::pending());
        let upload = {
            let (service, path) = (service.clone(), path.clone());
            tokio::spawn(async move { service.write_stream(&path, Box::pin(stream)).await })
        };
        wait_for_staged_count(&staging_dir, 1, "upload should be staged while in flight").await;

        upload.abort();
        assert!(upload.await.unwrap_err().is_cancelled());

        // The abort runs on a spawned task.
        wait_for_staged_count(&staging_dir, 0, "dropped upload left its staged file").await;
        assert_eq!(
            service.get(&path).await.unwrap(),
            Bytes::from_static(b"old")
        );
    }

    /// A body that breaks mid-stream is aborted, and the caller gets the
    /// stream error rather than a cleanup error.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn broken_stream_leaves_no_staged_file_and_the_old_bytes() {
        let (_context, service, path, staging_dir) = fs_service_with_old_file(1).await;

        let stream = futures_util::stream::iter([
            Ok(Bytes::from_static(b"partial")),
            Err(WriteStreamError::Other(anyhow::anyhow!("connection reset"))),
        ]);
        let result = service.write_stream(&path, Box::pin(stream)).await;

        assert!(matches!(result, Err(FileIoError::StreamBroken(_))));
        assert_eq!(staged_count(&staging_dir), 0);
        assert_eq!(
            service.get(&path).await.unwrap(),
            Bytes::from_static(b"old")
        );
    }

    /// Quota is only known once the whole body has streamed. Rejecting it then
    /// must not have touched the existing file.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn quota_rejected_overwrite_leaves_the_old_bytes_and_no_staged_file() {
        let (_context, service, path, staging_dir) = fs_service_with_old_file(1).await;

        let result = service.write(&path, vec![42u8; 1024 * 1024]).await;

        assert!(matches!(result, Err(FileIoError::DiskSpaceQuotaExceeded)));
        assert_eq!(staged_count(&staging_dir), 0);
        assert_eq!(
            service.get(&path).await.unwrap(),
            Bytes::from_static(b"old")
        );
    }
}
