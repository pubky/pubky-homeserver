use std::path::Path;

#[cfg(test)]
use crate::AppContext;
use crate::{
    persistence::{
        files::{
            events::EventsService, write_finalization_layer::WriteFinalizationLayer,
            write_path_layer::WritePathLayer,
        },
        sql::SqlDb,
    },
    services::user_service::UserService,
    shared::webdav::EntryPath,
    storage_config::{StorageConfigToml, StorageToml},
};
use bytes::Bytes;
use futures_util::{stream::StreamExt, Stream};
#[cfg(test)]
use opendal::Buffer;
use opendal::Operator;

use super::super::{
    FileIoError, FileMetadata, FileMetadataBuilder, FileStream, WritePreconditions,
    WriteStreamError,
};

/// Build storage operators with one transactional finalization layer and an
/// app-facing operator that additionally enforces write paths and collisions.
///
/// Both operators share the same underlying storage backend, which is
/// important for backends like `InMemory` where separate instances would
/// have independent data.
pub fn build_storage_operators(
    storage_config: &StorageToml,
    data_directory: &Path,
    sql_db: SqlDb,
    events_service: EventsService,
    user_service: UserService,
) -> Result<(Operator, Operator), FileIoError> {
    let backend_operator = match &storage_config.backend {
        StorageConfigToml::FileSystem => {
            let files_dir = data_directory.join("data/files");
            // Uploads are staged here and renamed into place on close, so a
            // rejected or aborted write never touches the existing file. Must
            // be on the same filesystem as the root, and outside it so staged
            // files never show up in listings.
            let staging_dir = data_directory.join("data/files-tmp");
            sweep_staging_dir(&staging_dir)?;
            let (Some(files_dir), Some(staging_dir)) = (files_dir.to_str(), staging_dir.to_str())
            else {
                return Err(FileIoError::OpenDAL(opendal::Error::new(
                    opendal::ErrorKind::Unexpected,
                    "Invalid path",
                )));
            };
            let builder = opendal::services::Fs::default()
                .root(files_dir)
                .atomic_write_dir(staging_dir);
            opendal::Operator::new(builder)?.finish()
        }
        #[cfg(feature = "storage-gcs")]
        StorageConfigToml::GoogleBucket(config) => {
            tracing::info!(
                "Store files in a Google Cloud Storage bucket: {}",
                config.bucket_name
            );
            let builder = config.to_builder()?;
            opendal::Operator::new(builder)?.finish()
        }
        #[cfg(any(feature = "storage-memory", test))]
        StorageConfigToml::InMemory => {
            tracing::info!("Store files in memory");
            let builder = opendal::services::Memory::default();
            opendal::Operator::new(builder)?.finish()
        }
    };

    // Collision checks apply only to app-facing mutations, so each operator
    // needs its own finalization layer.
    let admin_operator = backend_operator.clone().layer(WriteFinalizationLayer::new(
        user_service.clone(),
        sql_db.clone(),
        events_service.clone(),
        storage_config.default_quota_mb,
        false,
    ));
    let operator = backend_operator
        .layer(WriteFinalizationLayer::new(
            user_service.clone(),
            sql_db,
            events_service,
            storage_config.default_quota_mb,
            true,
        ))
        .layer(WritePathLayer::new(user_service));
    Ok((operator, admin_operator))
}

/// Remove staged uploads left behind by a previous process.
///
/// An upload whose connection drops while the server is running is aborted by
/// [`AbortOnDrop`]; only a crash mid-upload can leave a file here. Nothing is
/// in flight while the operators are being built, so everything is stale.
fn sweep_staging_dir(staging_dir: &Path) -> Result<(), FileIoError> {
    match std::fs::remove_dir_all(staging_dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(FileIoError::TempFile(error)),
    }
}

/// Aborts a backend write if the owning future is dropped before it completes,
/// e.g. when the client disconnects mid-upload and the request handler is
/// cancelled. Without this the staged bytes would never be cleaned up.
struct AbortOnDrop(Option<opendal::Writer>);

impl AbortOnDrop {
    fn take(&mut self) -> opendal::Writer {
        self.0.take().expect("writer is taken at most once")
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(mut writer) = self.0.take() {
            drop(tokio::spawn(async move {
                if let Err(error) = writer.abort().await {
                    tracing::debug!(error = %error, "Could not abort dropped upload");
                }
            }));
        }
    }
}

/// Build the storage operators from an `AppContext` (test-only convenience).
#[cfg(test)]
pub fn build_storage_operators_from_context(
    context: &AppContext,
) -> Result<(Operator, Operator), FileIoError> {
    build_storage_operators(
        &context.config_toml.storage,
        context.data_dir.path(),
        context.sql_db.clone(),
        context.events_service.clone(),
        context.user_service.clone(),
    )
}

/// The chunk size to use for reading and writing files.
/// This is used to avoid reading and writing the entire file at once.
/// Important: Not all opendal providers will respect this chunk size.
/// For example, Google Cloud Buckets will deliver chunks anything from
/// 200B to 16KB but max CHUNK_SIZE.
const CHUNK_SIZE: usize = 16 * 1024;

/// The service to write and read files to and from the configured opendal storage.
#[derive(Debug, Clone)]
pub struct OpendalService {
    /// Operator with all layers including `WritePathLayer` (for user-facing operations).
    pub(crate) operator: Operator,
    /// Operator without `WritePathLayer` (for admin operations that bypass write-path restrictions).
    pub(crate) admin_operator: Operator,
}

impl OpendalService {
    pub fn new_from_config(
        storage_config: &StorageToml,
        data_directory: &Path,
        sql_db: SqlDb,
        events_service: EventsService,
        user_service: UserService,
    ) -> Result<Self, FileIoError> {
        let (operator, admin_operator) = build_storage_operators(
            storage_config,
            data_directory,
            sql_db,
            events_service,
            user_service,
        )?;
        Ok(Self {
            operator,
            admin_operator,
        })
    }

    /// Delete a file if the `If-Match` condition in `preconditions` holds.
    /// Deleting a non-existing file will NOT return an error unless a condition is set.
    ///
    /// The condition travels as OpenDAL's delete `version`, which is the only
    /// argument a delete op carries; the finalization layer interprets it as an
    /// `If-Match` list and does not forward it to the backend. This borrows a
    /// field with a different native meaning: if versioned deletes are ever
    /// wanted, this channel must be replaced first.
    pub async fn delete(
        &self,
        path: &EntryPath,
        preconditions: &WritePreconditions,
    ) -> Result<(), FileIoError> {
        let mut delete = self.operator.delete_with(path.as_str());
        if let Some(if_match) = preconditions.if_match_header() {
            delete = delete.version(&if_match);
        }
        Ok(delete.await?)
    }

    /// Delete a file bypassing write-path restrictions.
    /// Used by `FileService::admin_delete` for the admin `/webdav` REST route.
    pub async fn admin_delete(&self, path: &EntryPath) -> Result<(), FileIoError> {
        Ok(self.admin_operator.delete(path.as_str()).await?)
    }

    /// Write a stream to the storage if `preconditions` hold for the current entry.
    ///
    /// Conditions are checked before any bytes are accepted and again inside
    /// the finalization transaction; a failed condition is
    /// [`FileIoError::PreconditionFailed`] and leaves the existing file untouched.
    pub async fn write_stream(
        &self,
        path: &EntryPath,
        mut stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
        preconditions: &WritePreconditions,
    ) -> Result<FileMetadata, FileIoError> {
        let mut writer = self.operator.writer_with(path.as_str());
        if let Some(if_match) = preconditions.if_match_header() {
            writer = writer.if_match(&if_match);
        }
        if let Some(if_none_match) = preconditions.if_none_match_header() {
            writer = writer.if_none_match(&if_none_match);
        }
        let mut guard = AbortOnDrop(Some(writer.await?));
        let mut metadata_builder = FileMetadataBuilder::default();
        metadata_builder.guess_mime_type_from_path(path.path().as_str());

        let write_result: Result<(), FileIoError> = async {
            let writer = guard.0.as_mut().expect("writer is present while streaming");
            while let Some(chunk_result) = stream.next().await {
                let chunk = chunk_result?;
                metadata_builder.update(&chunk);
                writer.write(chunk).await?;
            }
            Ok(())
        }
        .await;

        // Past this point the write either completes or is aborted explicitly;
        // the guard must not abort a second time.
        let mut writer = guard.take();
        match write_result {
            Ok(()) => {
                writer.close().await?;
                Ok(metadata_builder.finalize())
            }
            Err(e) => {
                writer.abort().await?;
                Err(e)
            }
        }
    }

    /// Get the stream of a file.
    /// Helper method because the NOT_FOUND error can happen in two different places.
    async fn get_stream_inner(&self, path: &EntryPath) -> Result<FileStream, opendal::Error> {
        let reader = self
            .operator
            .reader_with(path.as_str())
            .chunk(CHUNK_SIZE)
            .await?;

        let stream = reader.into_bytes_stream(0..).await?;
        Ok(Box::new(stream))
    }

    /// Get the content of a file as a stream of bytes.
    /// The stream is chunked by the CHUNK_SIZE.
    pub async fn get_stream(&self, path: &EntryPath) -> Result<FileStream, FileIoError> {
        Ok(self.get_stream_inner(path).await?)
    }

    /// Check if a file exists.
    pub async fn exists(&self, path: &EntryPath) -> Result<bool, opendal::Error> {
        self.operator.exists(path.as_str()).await
    }
}

#[cfg(test)]
impl OpendalService {
    pub fn new(context: &AppContext) -> Result<Self, FileIoError> {
        let (operator, admin_operator) = build_storage_operators_from_context(context)?;
        Ok(Self {
            operator,
            admin_operator,
        })
    }

    /// Create a new opendal service from an existing operator.
    /// This is useful for testing.
    pub fn new_from_operator(operator: Operator) -> Self {
        Self {
            admin_operator: operator.clone(),
            operator,
        }
    }

    /// Get the content of a file as a single Bytes object.
    /// This is useful for small files or when you want to avoid the overhead of streaming.
    #[cfg(test)]
    pub async fn get(&self, path: &EntryPath) -> Result<Bytes, FileIoError> {
        let mut stream = self.get_stream(path).await?;
        let mut content = Vec::new();
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            content.extend_from_slice(&chunk);
        }
        Ok(Bytes::from(content))
    }

    /// Write the content of a file to the storage.
    /// This is useful for small files or when you want to avoid the overhead of streaming.
    /// Use streamed writes for large files.
    #[cfg(test)]
    pub async fn write(
        &self,
        path: &EntryPath,
        buffer: impl Into<Buffer>,
    ) -> Result<FileMetadata, FileIoError> {
        let buffer: Buffer = buffer.into();
        let bytes = Bytes::from(buffer.to_vec());
        // Create a single-item stream from the buffer
        let stream = Box::pin(futures_util::stream::once(async move { Ok(bytes) }));
        // Use the existing streaming implementation
        self.write_stream(path, stream, &WritePreconditions::default())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::files::opendal::opendal_test_operators::{
        get_atomic_fs_operator, OpendalTestOperators,
    };
    use crate::shared::webdav::StoragePath;

    /// A client that disconnects mid-upload drops the request future. The
    /// staged bytes must still be cleaned up.
    #[tokio::test]
    async fn dropped_upload_is_aborted_and_leaves_no_staged_file() {
        let (operator, dir) = get_atomic_fs_operator();
        let staging_dir = dir.path().join("files-tmp");
        let service = OpendalService::new_from_operator(operator);
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        let path = EntryPath::new(pubkey, StoragePath::new("/test.txt").unwrap());

        // One chunk, then the body never completes.
        let stream = futures_util::stream::iter([Ok(Bytes::from_static(b"partial"))])
            .chain(futures_util::stream::pending());
        let upload = tokio::spawn(async move {
            service
                .write_stream(&path, Box::pin(stream), &WritePreconditions::default())
                .await
        });
        wait_for_staged_count(&staging_dir, 1, "upload should be staged while in flight").await;

        upload.abort();
        let _ = upload.await;

        // Abort runs on a spawned task.
        wait_for_staged_count(
            &staging_dir,
            0,
            "staged file was not removed after the upload future was dropped",
        )
        .await;
    }

    async fn wait_for_staged_count(staging_dir: &Path, expected: usize, message: &str) {
        for _ in 0..200 {
            let count = std::fs::read_dir(staging_dir).map_or(0, Iterator::count);
            if count == expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("{message}");
    }

    #[test]
    fn sweep_staging_dir_removes_leftovers_and_tolerates_absence() {
        let dir = tempfile::tempdir().unwrap();
        let staging_dir = dir.path().join("files-tmp");
        std::fs::create_dir_all(&staging_dir).unwrap();
        std::fs::write(staging_dir.join("stale.tmp"), b"x").unwrap();

        sweep_staging_dir(&staging_dir).unwrap();
        assert!(!staging_dir.exists());

        sweep_staging_dir(&staging_dir).unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_build_storage_operator_from_config_file_system() {
        let context = AppContext::test_with_config(|c| {
            c.storage.backend = StorageConfigToml::FileSystem;
        })
        .await;

        let service =
            OpendalService::new(&context).expect("Failed to create OpenDAL service for testing");
        let pubky = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&pubky).await.unwrap();
        let path = EntryPath::new(pubky, StoragePath::new("/test.txt").unwrap());
        assert!(!service.exists(&path).await.unwrap());
    }

    /// Make sure that the OpendalService returns a DiskSpaceQuotaExceeded error if the user has exceeded the quota.
    /// This is important because write finalization returns a RateLimited error if the user has exceeded the quota.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_quota_exceeded_error() {
        let context = AppContext::test().await;
        let service =
            OpendalService::new(&context).expect("Failed to create OpenDAL service for testing");
        let pubky = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create_with_quota_mb(&pubky, 1).await;
        let path = EntryPath::new(pubky, StoragePath::new("/test.txt").unwrap());
        let write_result = service.write(&path, vec![42u8; 1024 * 1024]).await;
        assert!(write_result.is_err());
        assert!(matches!(
            write_result,
            Err(FileIoError::DiskSpaceQuotaExceeded)
        ));
    }

    /// Test the chunked reading of a file.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_content_chunked() {
        let operators = OpendalTestOperators::new();
        for (_scheme, operator) in operators.operators() {
            let file_service = OpendalService::new_from_operator(operator);

            let pubkey = pubky_common::crypto::Keypair::random().public_key();
            let path = EntryPath::new(pubkey, StoragePath::new("/test.txt").unwrap());

            // Write a 10KB file filled with test data
            let should_chunk_count = 5;
            let test_data = vec![42u8; should_chunk_count * CHUNK_SIZE];
            file_service.write(&path, test_data.clone()).await.unwrap();

            // Read the content back using the chunked stream
            let mut stream = file_service.get_stream(&path).await.unwrap();

            let mut collected_data = Vec::new();
            let mut count = 0;
            while let Some(chunk_result) = stream.next().await {
                count += 1;
                let chunk = chunk_result.unwrap();
                collected_data.extend_from_slice(&chunk);
            }

            // Verify the data matches what we wrote
            assert_eq!(
                collected_data.len(),
                test_data.len(),
                "Total size should be 10KB"
            );
            assert_eq!(
                collected_data, test_data,
                "Content should match original data"
            );

            // Verify that we received multiple chunks according to the chunk count
            assert!(count >= should_chunk_count, "Should have received x chunks");

            // Verify that the chunks are of the correct size
            assert_eq!(
                collected_data.len(),
                should_chunk_count * CHUNK_SIZE,
                "Total size should be 10KB"
            );
            assert_eq!(
                collected_data, test_data,
                "Content should match original data"
            );

            file_service
                .delete(&path, &WritePreconditions::default())
                .await
                .expect("Should delete file");
            assert!(
                !file_service.exists(&path).await.unwrap(),
                "File should not exist after deletion"
            );
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_write_content_stream() {
        let operators = OpendalTestOperators::new();
        for (_scheme, operator) in operators.operators() {
            let file_service = OpendalService::new_from_operator(operator);

            let pubkey = pubky_common::crypto::Keypair::random().public_key();
            let path = EntryPath::new(pubkey, StoragePath::new("/test_stream.txt").unwrap());

            // Create test data - multiple chunks to test streaming
            let chunk_count = 3;
            let mut test_data = Vec::new();
            let mut chunks = Vec::new();

            // Create chunks with different patterns to verify order
            for i in 0..chunk_count {
                let chunk_data = vec![i as u8; CHUNK_SIZE];
                test_data.extend_from_slice(&chunk_data);
                chunks.push(Ok(Bytes::from(chunk_data)));
            }

            // Create a stream from the chunks
            let stream = futures_util::stream::iter(chunks);

            // Write the stream to storage
            file_service
                .write_stream(&path, stream, &WritePreconditions::default())
                .await
                .unwrap();

            // Read the content back and verify it matches
            let read_content = file_service.get(&path).await.unwrap();

            assert_eq!(
                read_content.len(),
                test_data.len(),
                "Content length should match"
            );
            assert_eq!(
                read_content.to_vec(),
                test_data,
                "Content should match original data"
            );

            file_service
                .delete(&path, &WritePreconditions::default())
                .await
                .expect("Should delete file");
            assert!(
                !file_service.exists(&path).await.unwrap(),
                "File should not exist after deletion"
            );
        }
    }
}
