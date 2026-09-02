use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use opendal::Operator;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use tokio_util::sync::CancellationToken;

use crate::{
    shared::webdav::EntryPath,
    storage_config::{StorageConfigToml, StorageToml},
};

#[cfg(test)]
use crate::AppContext;

use super::super::{FileIoError, FileMetadata, FileMetadataBuilder, FileStream, WriteStreamError};

fn build_backend_operator(
    storage_config: &StorageToml,
    data_directory: &Path,
) -> Result<(Operator, Option<PathBuf>), FileIoError> {
    let backend = match &storage_config.backend {
        StorageConfigToml::FileSystem => {
            let files_dir = data_directory.join("data/files");
            let blob_dir = files_dir.join("__pubky/blobs");
            std::fs::create_dir_all(&blob_dir)?;
            sync_directory_tree(data_directory, &blob_dir)?;
            let files_dir_string = files_dir
                .to_str()
                .ok_or_else(|| {
                    FileIoError::OpenDAL(opendal::Error::new(
                        opendal::ErrorKind::Unexpected,
                        "Invalid storage path",
                    ))
                })?
                .to_string();
            (
                opendal::Operator::new(opendal::services::Fs::default().root(&files_dir_string))?
                    .finish(),
                Some(files_dir),
            )
        }
        #[cfg(feature = "storage-gcs")]
        StorageConfigToml::GoogleBucket(config) => {
            tracing::info!(
                bucket = config.bucket_name,
                "Store files in Google Cloud Storage"
            );
            tracing::warn!(
                bucket = config.bucket_name,
                "Google Cloud Storage requires soft delete and Object Versioning to be disabled, plus an AbortIncompleteMultipartUpload lifecycle rule for __pubky/blobs/"
            );
            (opendal::Operator::new(config.to_builder()?)?.finish(), None)
        }
        #[cfg(any(feature = "storage-memory", test))]
        StorageConfigToml::InMemory => {
            tracing::info!("Store files in memory");
            (
                opendal::Operator::new(opendal::services::Memory::default())?.finish(),
                None,
            )
        }
    };
    Ok(backend)
}

fn sync_directory_tree(root: &Path, leaf: &Path) -> Result<(), std::io::Error> {
    let mut current = leaf.to_path_buf();
    loop {
        sync_directory(&current)?;
        if current == root {
            break;
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent.to_path_buf();
        if !current.starts_with(root) {
            break;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .sync_all()
}

/// Chunk size used when streaming backend objects.
const CHUNK_SIZE: usize = 16 * 1024;
const WRITER_ABORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Reads and writes immutable backend objects through the configured OpenDAL backend.
#[derive(Debug, Clone)]
pub struct OpendalService {
    operator: Operator,
    filesystem_root: Option<Arc<PathBuf>>,
    #[cfg(test)]
    fail_next_delete: Arc<AtomicBool>,
}

impl OpendalService {
    pub fn new_from_config(
        storage_config: &StorageToml,
        data_directory: &Path,
    ) -> Result<Self, FileIoError> {
        let (operator, filesystem_root) = build_backend_operator(storage_config, data_directory)?;
        Ok(Self {
            operator,
            filesystem_root: filesystem_root.map(Arc::new),
            #[cfg(test)]
            fail_next_delete: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Write an immutable internal blob.
    #[cfg(test)]
    pub async fn write_blob_stream(
        &self,
        blob_key: &str,
        stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
        content_path: &EntryPath,
    ) -> Result<FileMetadata, FileIoError> {
        self.write_blob_stream_guarded(
            blob_key,
            stream,
            content_path,
            None,
            &CancellationToken::new(),
        )
        .await
    }

    /// Write an immutable blob while enforcing its reservation and upload lease.
    pub async fn write_blob_stream_guarded(
        &self,
        blob_key: &str,
        mut stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
        content_path: &EntryPath,
        max_length: Option<u64>,
        cancellation: &CancellationToken,
    ) -> Result<FileMetadata, FileIoError> {
        let mut writer = self.operator.writer(blob_key).await?;
        let mut metadata_builder = FileMetadataBuilder::default();
        metadata_builder.guess_mime_type_from_path(content_path.path().as_str());
        let mut written = 0u64;

        let write_result: Result<(), FileIoError> = async {
            loop {
                let chunk_result = tokio::select! {
                    _ = cancellation.cancelled() => return Err(FileIoError::UploadLeaseLost),
                    chunk = stream.next() => chunk,
                };
                let Some(chunk_result) = chunk_result else {
                    break;
                };
                let chunk = chunk_result?;
                written = written.saturating_add(chunk.len() as u64);
                if max_length.is_some_and(|max_length| written > max_length) {
                    return Err(FileIoError::DiskSpaceQuotaExceeded);
                }
                metadata_builder.update(&chunk);
                tokio::select! {
                    _ = cancellation.cancelled() => return Err(FileIoError::UploadLeaseLost),
                    result = writer.write(chunk) => result?,
                }
            }
            Ok(())
        }
        .await;

        match write_result {
            Ok(()) => {
                if cancellation.is_cancelled() {
                    Self::abort_writer(&mut writer, blob_key).await;
                    return Err(FileIoError::UploadLeaseLost);
                }
                tokio::select! {
                    _ = cancellation.cancelled() => {
                        Self::abort_writer(&mut writer, blob_key).await;
                        return Err(FileIoError::UploadLeaseLost);
                    }
                    result = writer.close() => {
                        if let Err(error) = result {
                            Self::abort_writer(&mut writer, blob_key).await;
                            return Err(error.into());
                        }
                    },
                }
                self.sync_blob_parent(blob_key).await?;
                Ok(metadata_builder.finalize())
            }
            Err(error) => {
                Self::abort_writer(&mut writer, blob_key).await;
                Err(error)
            }
        }
    }

    async fn abort_writer(writer: &mut opendal::Writer, blob_key: &str) {
        match tokio::time::timeout(WRITER_ABORT_TIMEOUT, writer.abort()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::debug!(blob_key, %error, "Backend could not abort incomplete blob write");
            }
            Err(_) => {
                tracing::warn!(blob_key, "Timed out aborting incomplete blob write");
            }
        }
    }

    /// Stream a backend object by its immutable or legacy key.
    pub async fn get_stream_by_key(&self, key: &str) -> Result<FileStream, FileIoError> {
        let reader = self.operator.reader_with(key).chunk(CHUNK_SIZE).await?;
        Ok(Box::new(reader.into_bytes_stream(0..).await?))
    }

    /// Read one byte range from a backend object.
    pub async fn get_range_by_key(
        &self,
        key: &str,
        range: std::ops::Range<u64>,
    ) -> Result<Bytes, FileIoError> {
        Ok(Bytes::from(
            self.operator.read_with(key).range(range).await?.to_vec(),
        ))
    }

    /// Delete a backend object by its immutable or legacy key.
    pub async fn delete_by_key(&self, key: &str) -> Result<(), FileIoError> {
        #[cfg(test)]
        if self.fail_next_delete.swap(false, Ordering::SeqCst) {
            return Err(FileIoError::OpenDAL(opendal::Error::new(
                opendal::ErrorKind::Unexpected,
                "injected delete failure",
            )));
        }
        self.operator.delete(key).await?;
        self.sync_blob_parent(key).await?;
        Ok(())
    }

    /// List immutable backend objects for orphan reconciliation.
    pub(crate) async fn blob_lister(&self) -> Result<opendal::Lister, FileIoError> {
        Ok(self
            .operator
            .lister_with("__pubky/blobs/")
            .recursive(true)
            .await?)
    }

    async fn sync_blob_parent(&self, key: &str) -> Result<(), FileIoError> {
        let Some(root) = self.filesystem_root.as_ref() else {
            return Ok(());
        };
        let parent = root
            .join(key.trim_start_matches('/'))
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| std::io::Error::other("blob key has no parent directory"))?;
        tokio::task::spawn_blocking(move || sync_directory(&parent))
            .await
            .map_err(|error| {
                std::io::Error::other(format!("directory sync task failed: {error}"))
            })??;
        Ok(())
    }

    #[cfg(test)]
    pub async fn blob_exists(&self, key: &str) -> Result<bool, opendal::Error> {
        self.operator.exists(key).await
    }
}

#[cfg(test)]
impl OpendalService {
    pub fn new(context: &AppContext) -> Result<Self, FileIoError> {
        Self::new_from_config(&context.config_toml.storage, context.data_dir.path())
    }

    pub fn new_from_operator(operator: Operator) -> Self {
        Self {
            operator,
            filesystem_root: None,
            fail_next_delete: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn fail_next_delete(&self) {
        self.fail_next_delete.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        persistence::files::opendal::opendal_test_operators::OpendalTestOperators,
        shared::webdav::StoragePath,
    };

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_build_backend_operator_from_filesystem_config() {
        let context = AppContext::test_with_config(|config| {
            config.storage.backend = StorageConfigToml::FileSystem;
        })
        .await;
        let service = OpendalService::new(&context).unwrap();

        assert!(!service.blob_exists("__pubky/blobs/missing").await.unwrap());
    }

    #[tokio::test]
    async fn test_blob_stream_roundtrip_across_backends() {
        let path = EntryPath::new(
            pubky_common::crypto::Keypair::random().public_key(),
            StoragePath::new("/pub/test.bin").unwrap(),
        );
        for (_scheme, operator) in OpendalTestOperators::new().operators() {
            let service = OpendalService::new_from_operator(operator);
            let input_chunks = [
                Bytes::from(vec![1; CHUNK_SIZE]),
                Bytes::from(vec![2; CHUNK_SIZE]),
                Bytes::from(vec![3; CHUNK_SIZE]),
            ];
            let data = input_chunks
                .iter()
                .flat_map(|chunk| chunk.iter().copied())
                .collect::<Vec<_>>();
            service
                .write_blob_stream(
                    "__pubky/blobs/test",
                    futures_util::stream::iter(input_chunks.into_iter().map(Ok)),
                    &path,
                )
                .await
                .unwrap();

            let mut stream = service
                .get_stream_by_key("__pubky/blobs/test")
                .await
                .unwrap();
            let mut received = Vec::new();
            let mut received_chunks = 0;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.unwrap();
                assert!(chunk.len() <= CHUNK_SIZE);
                received.extend_from_slice(&chunk);
                received_chunks += 1;
            }
            assert_eq!(received, data);
            assert!(received_chunks >= 3);
            assert_eq!(
                service
                    .get_range_by_key("__pubky/blobs/test", 10..20)
                    .await
                    .unwrap()
                    .as_ref(),
                &data[10..20]
            );

            service.delete_by_key("__pubky/blobs/test").await.unwrap();
            assert!(!service.blob_exists("__pubky/blobs/test").await.unwrap());
        }
    }

    #[tokio::test]
    async fn test_guarded_blob_write_stops_when_upload_lease_is_lost() {
        let operator = Operator::new(opendal::services::Memory::default())
            .unwrap()
            .finish();
        let service = OpendalService::new_from_operator(operator);
        let path = EntryPath::new(
            pubky_common::crypto::Keypair::random().public_key(),
            StoragePath::new("/pub/test.bin").unwrap(),
        );
        let cancellation = CancellationToken::new();
        let task_service = service.clone();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            task_service
                .write_blob_stream_guarded(
                    "__pubky/blobs/cancelled",
                    futures_util::stream::pending::<Result<Bytes, WriteStreamError>>(),
                    &path,
                    None,
                    &task_cancellation,
                )
                .await
        });

        tokio::task::yield_now().await;
        cancellation.cancel();

        assert!(matches!(
            task.await.unwrap(),
            Err(FileIoError::UploadLeaseLost)
        ));
        assert!(!service
            .blob_exists("__pubky/blobs/cancelled")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_filesystem_abort_preserves_original_write_error() {
        let directory = tempfile::tempdir().unwrap();
        let service = OpendalService::new_from_config(
            &StorageToml {
                backend: StorageConfigToml::FileSystem,
                default_quota_mb: None,
                admin_dav_spool_limit_mb: 1024,
            },
            directory.path(),
        )
        .unwrap();
        let path = EntryPath::new(
            pubky_common::crypto::Keypair::random().public_key(),
            StoragePath::new("/pub/test.bin").unwrap(),
        );

        let error = service
            .write_blob_stream_guarded(
                "__pubky/blobs/too-large",
                futures_util::stream::iter([Ok(Bytes::from_static(b"too large"))]),
                &path,
                Some(1),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, FileIoError::DiskSpaceQuotaExceeded));
    }
}
