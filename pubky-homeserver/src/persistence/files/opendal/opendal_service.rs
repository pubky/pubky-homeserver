use std::path::Path;

#[cfg(test)]
use crate::AppContext;
use crate::{
    persistence::{
        files::{
            events::EventsService, staged_publish_layer::StagedPublishLayer,
            write_finalization_layer::WriteFinalizationLayer, write_path_layer::WritePathLayer,
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

use super::super::{FileIoError, FileStream, WriteStreamError};

/// Build storage operators with one transactional finalization layer and an
/// app-facing operator that additionally enforces write paths and collisions,
/// over the backend `storage_config` names, see [`layer_storage_operators`].
pub fn build_storage_operators(
    storage_config: &StorageToml,
    data_directory: &Path,
    sql_db: SqlDb,
    events_service: EventsService,
    user_service: UserService,
) -> Result<(Operator, Operator), FileIoError> {
    let backend_operator = backend_operator(&storage_config.backend, data_directory)?;
    Ok(layer_storage_operators(
        backend_operator,
        storage_config.default_quota_mb,
        sql_db,
        events_service,
        user_service,
    ))
}

/// Where the filesystem backend keeps the files, under the data directory.
const FILE_SYSTEM_FILES_DIR: &str = "data/files";
/// Where the filesystem backend stages uploads, under the data directory.
pub(crate) const FILE_SYSTEM_STAGING_DIR: &str = "data/files-tmp";

/// The storage backend `backend` names.
///
/// A remote backend publishes and deletes under a generation condition
/// through [`StagedPublishLayer`], so a request it executes late is refused
/// rather than landing on a newer write. Every call to it is bounded by
/// [`BACKEND_IO_TIMEOUT`], so a hung request cannot hold a finalization, and
/// the user row with it, forever. A local backend's calls are not bounded:
/// abandoning a filesystem rename would not stop it, only lose track of it.
pub(super) fn backend_operator(
    backend: &StorageConfigToml,
    data_directory: &Path,
) -> Result<Operator, FileIoError> {
    let operator = match backend {
        StorageConfigToml::FileSystem => {
            let files_dir = data_directory.join(FILE_SYSTEM_FILES_DIR);
            // Uploads are staged here and renamed into place on close, so a
            // rejected or aborted write never touches the existing file. Must
            // be on the same filesystem as the root, and outside it so staged
            // files never show up in listings.
            let staging_dir = data_directory.join(FILE_SYSTEM_STAGING_DIR);
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
            opendal::Operator::new(builder)?
        }
        #[cfg(feature = "storage-gcs")]
        StorageConfigToml::GoogleBucket(config) => {
            tracing::info!(
                "Store files in a Google Cloud Storage bucket: {}",
                config.bucket_name
            );
            gcs_backend_operator(config)?
        }
        #[cfg(any(feature = "storage-memory", test))]
        StorageConfigToml::InMemory => {
            tracing::info!("Store files in memory");
            let builder = opendal::services::Memory::default();
            opendal::Operator::new(builder)?
        }
    };
    Ok(operator)
}

/// The app-facing and the admin operator over `backend_operator`, in that
/// order. Both finalize every write and delete in one transaction with its
/// entry, events and quota; the app-facing one also enforces write paths and
/// collisions.
///
/// Both share `backend_operator`, which matters for backends like `InMemory`,
/// where separate instances would have independent data.
pub(super) fn layer_storage_operators(
    backend_operator: Operator,
    default_quota_mb: Option<u64>,
    sql_db: SqlDb,
    events_service: EventsService,
    user_service: UserService,
) -> (Operator, Operator) {
    // Collision checks apply only to app-facing mutations, so each operator
    // needs its own finalization layer.
    let admin_operator = backend_operator.clone().layer(WriteFinalizationLayer::new(
        user_service.clone(),
        sql_db.clone(),
        events_service.clone(),
        default_quota_mb,
        false,
    ));
    let operator = backend_operator
        .layer(WriteFinalizationLayer::new(
            user_service.clone(),
            sql_db,
            events_service,
            default_quota_mb,
            true,
        ))
        .layer(WritePathLayer::new(user_service));
    (operator, admin_operator)
}

/// Longest any one call to the remote backend may take before it is
/// abandoned: a read or write of a chunk, a part upload, a list, a stat, the
/// close that finishes an upload, the copy that publishes it, or a delete.
/// Before this, a call to the bucket could hang for good.
#[cfg(feature = "storage-gcs")]
const BACKEND_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// The Google Cloud Storage operator for `config`, see [`gcs_operator`].
#[cfg(feature = "storage-gcs")]
fn gcs_backend_operator(
    config: &crate::data_directory::storage_config::GoogleBucketConfig,
) -> Result<Operator, FileIoError> {
    gcs_operator(config.to_builder()?)
}

/// The operator stack over a GCS service: its calls bounded, its writes
/// published and its deletes made under the object's generation, see
/// [`StagedPublishLayer`].
#[cfg(feature = "storage-gcs")]
pub(super) fn gcs_operator(builder: opendal::services::Gcs) -> Result<Operator, FileIoError> {
    Ok(gcs_unstaged_backend(builder)?.layer(StagedPublishLayer))
}

/// The GCS service under [`gcs_operator`]'s staging, its calls bounded. Its
/// writes and deletes carry no generation condition of their own.
#[cfg(feature = "storage-gcs")]
pub(super) fn gcs_unstaged_backend(
    builder: opendal::services::Gcs,
) -> Result<Operator, FileIoError> {
    let operator = with_own_http_client(opendal::Operator::new(builder)?).layer(
        opendal::layers::TimeoutLayer::new()
            .with_timeout(BACKEND_IO_TIMEOUT)
            .with_io_timeout(BACKEND_IO_TIMEOUT),
    );
    Ok(operator)
}

/// `operator` with an HTTP client of its own. opendal's default client is
/// shared by the process, and a connection it pools dies with the runtime
/// that opened it: tests, and a test's cleaner, each run on a runtime of
/// their own. The production GCS operator gets one too, through
/// [`gcs_unstaged_backend`], so it runs on the client the real-bucket tests
/// check. One client per operator costs nothing there.
#[cfg(feature = "storage-gcs")]
pub(super) fn with_own_http_client(operator: Operator) -> Operator {
    let transport = opendal_http_transport_reqwest::ReqwestTransport::new(reqwest::Client::new());
    operator.with_context(
        opendal::OperationContext::new()
            .with_http_transport(opendal::HttpTransporter::new(transport)),
    )
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

    /// Delete a file.
    /// Deleting a non-existing file will NOT return an error.
    pub async fn delete(&self, path: &EntryPath) -> Result<(), FileIoError> {
        Ok(self.operator.delete(path.as_str()).await?)
    }

    /// Delete a file bypassing write-path restrictions.
    /// Used by `FileService::admin_delete` for the admin `/webdav` REST route.
    pub async fn admin_delete(&self, path: &EntryPath) -> Result<(), FileIoError> {
        Ok(self.admin_operator.delete(path.as_str()).await?)
    }

    /// Write a stream to the storage. A stream that breaks mid-way aborts the
    /// upload, and the caller gets the stream error rather than a cleanup error.
    pub async fn write_stream(
        &self,
        path: &EntryPath,
        mut stream: impl Stream<Item = Result<Bytes, WriteStreamError>> + Unpin + Send,
    ) -> Result<(), FileIoError> {
        let mut writer = self.operator.writer(path.as_str()).await?;
        let write_result: Result<(), FileIoError> = async {
            while let Some(chunk_result) = stream.next().await {
                writer.write(chunk_result?).await?;
            }
            Ok(())
        }
        .await;

        match write_result {
            Ok(()) => {
                writer.close().await?;
                Ok(())
            }
            Err(stream_error) => {
                if let Err(error) = writer.abort().await {
                    tracing::warn!(path = %path, %error, "Failed to abort broken upload");
                }
                Err(stream_error)
            }
        }
    }

    /// The size of the stored blob and a stream of its bytes.
    ///
    /// The stream is one read of the backend, streamed as it arrives. Setting
    /// a chunk size would split it into one read per chunk, issued one after
    /// another, and on an object store each of those is a round trip.
    ///
    /// The length comes from a `stat`, and on a backend that returns an ETag
    /// the read is conditional on it, so the length and the bytes are of the
    /// same version: if an overwrite landed in between, the read is refused.
    /// Once open, the read keeps delivering the version it opened, even if an
    /// overwrite lands mid-stream: an object store serves a GET from one
    /// generation, and the filesystem backend's open file outlives the rename
    /// that an overwrite publishes with.
    pub async fn get_sized_stream(
        &self,
        path: &EntryPath,
    ) -> Result<(u64, FileStream), FileIoError> {
        let metadata = self.operator.stat(path.as_str()).await?;
        let length = metadata.content_length();
        let mut reader = self.operator.reader_with(path.as_str());
        if let Some(etag) = metadata.etag() {
            reader = reader.if_match(etag);
        }
        let stream = reader.await?.into_bytes_stream(0..length).await?;
        Ok((length, Box::new(stream)))
    }

    /// The size of the stored blob.
    pub async fn blob_length(&self, path: &EntryPath) -> Result<u64, FileIoError> {
        Ok(self.operator.stat(path.as_str()).await?.content_length())
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

    /// Get the content of a file as a stream of bytes.
    pub async fn get_stream(&self, path: &EntryPath) -> Result<FileStream, FileIoError> {
        Ok(self.get_sized_stream(path).await?.1)
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
    ) -> Result<(), FileIoError> {
        let buffer: Buffer = buffer.into();
        let bytes = Bytes::from(buffer.to_vec());
        // Create a single-item stream from the buffer
        let stream = Box::pin(futures_util::stream::once(async move { Ok(bytes) }));
        // Use the existing streaming implementation
        self.write_stream(path, stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::files::test_support::{
        get_fs_operator, get_memory_operator, CountingReads, Versioned,
    };
    use crate::shared::webdav::StoragePath;

    /// A size for test data that spans several stream items.
    const TEST_CHUNK_SIZE: usize = 16 * 1024;

    /// A read whose blob is replaced after it was sized is refused rather
    /// than served from the new version, whose length may differ.
    #[tokio::test]
    async fn read_of_a_blob_replaced_after_its_stat_is_refused() {
        let (fs, _tmp_dir) = get_fs_operator();
        let versioned = Versioned::new("7");
        let service = OpendalService::new_from_operator(fs.layer(versioned.clone()));
        let path = EntryPath::new(
            pubky_common::crypto::Keypair::random().public_key(),
            StoragePath::new("/pub/a.bin").unwrap(),
        );
        service
            .write(&path, vec![1u8; 3 * TEST_CHUNK_SIZE])
            .await
            .unwrap();

        let (length, mut stream) = service.get_sized_stream(&path).await.unwrap();
        assert_eq!(length as usize, 3 * TEST_CHUNK_SIZE);

        // The blob is replaced before the read is opened.
        versioned.set_generation("8");
        stream
            .next()
            .await
            .unwrap()
            .expect_err("a read of another version of the blob is refused");
    }

    /// A download is one read of the backend, whatever the blob's size. On
    /// an object store every read is a round trip, so reading a blob in small
    /// pieces one after another made a download as slow as its piece count.
    #[tokio::test]
    async fn a_download_is_one_backend_read() {
        let counting = CountingReads::default();
        let service =
            OpendalService::new_from_operator(get_memory_operator().layer(counting.clone()));
        let path = EntryPath::new(
            pubky_common::crypto::Keypair::random().public_key(),
            StoragePath::new("/pub/large.bin").unwrap(),
        );
        let test_data = vec![9u8; 10 * TEST_CHUNK_SIZE];
        service.write(&path, test_data.clone()).await.unwrap();

        let reads_before = counting.reads();
        assert_eq!(service.get(&path).await.unwrap().to_vec(), test_data);
        assert_eq!(counting.reads() - reads_before, 1);
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

    /// A homeserver configured with `file_system` storage stores a file at
    /// the longest storage path.
    #[tokio::test]
    #[ignore = "fails on the file system backend, see #715 and #716"]
    #[pubky_test_utils::test]
    async fn file_system_stores_a_file_at_the_longest_storage_path() {
        let context = AppContext::test_with_config(|c| {
            c.storage.backend = StorageConfigToml::FileSystem;
        })
        .await;
        let user = pubky_common::crypto::Keypair::random().public_key();

        stores_and_removes_files(&context, &user, &[&longest_storage_path()]).await;
    }

    /// Against the real bucket, see
    /// [`gcs_test_bucket`](crate::persistence::files::test_support::gcs_test_bucket):
    /// a homeserver configured with `google_bucket` storage stores files
    /// through the code production builds its backend with, also at the
    /// longest storage path. In the bucket's root, the user's key and that
    /// path take up the whole object name GCS allows.
    // Multi-threaded for the cleaner, which blocks on its async drop.
    #[cfg(feature = "storage-gcs")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs GCS_BUCKET and GOOGLE_APPLICATION_CREDENTIALS"]
    #[pubky_test_utils::test]
    async fn gcs_stores_files_from_the_google_bucket_config() {
        use crate::persistence::files::test_support::TestBucket;

        let bucket = TestBucket::from_env();
        let user = pubky_common::crypto::Keypair::random().public_key();
        // The homeserver stores in the bucket's root, under its users' keys.
        let _cleaner = bucket.user_cleaner(&user);
        let context = AppContext::test_with_config(|c| {
            c.storage.backend = StorageConfigToml::GoogleBucket(bucket.config());
        })
        .await;

        stores_and_removes_files(&context, &user, &["/pub/a.txt", &longest_storage_path()]).await;
    }

    /// Signs `user` up on the homeserver of `context`, then writes, reads
    /// back and deletes a file at each of `paths` through its storage.
    async fn stores_and_removes_files(
        context: &AppContext,
        user: &pubky_common::crypto::PublicKey,
        paths: &[&str],
    ) {
        let service = OpendalService::new(context).unwrap();
        context.user_service.create(user).await.unwrap();
        for path in paths {
            let path = EntryPath::new(user.clone(), StoragePath::new(path).unwrap());
            let content = path.as_str().as_bytes().to_vec();

            service.write(&path, content.clone()).await.unwrap();
            assert_eq!(service.get(&path).await.unwrap().to_vec(), content);

            service.delete(&path).await.unwrap();
            assert!(!service.exists(&path).await.unwrap());
        }
    }

    /// A path of the longest total length, whose last segments, the file
    /// name among them, are of the longest segment length.
    fn longest_storage_path() -> String {
        use pubky_common::storage_path::{
            MAX_STORAGE_PATH_SEGMENT_LENGTH, MAX_STORAGE_PATH_TOTAL_LENGTH,
        };

        let longest_segment = format!("/{}", "a".repeat(MAX_STORAGE_PATH_SEGMENT_LENGTH));
        let filler_length =
            MAX_STORAGE_PATH_TOTAL_LENGTH - "/pub/".len() - 3 * longest_segment.len();
        let path = format!(
            "/pub/{}{}",
            "b".repeat(filler_length),
            longest_segment.repeat(3)
        );
        assert_eq!(path.len(), MAX_STORAGE_PATH_TOTAL_LENGTH);
        path
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

    /// Against the real bucket, see
    /// [`gcs_test_bucket`](crate::persistence::files::test_support::gcs_test_bucket): a path with
    /// characters that URLs percent-encode is stored under its own name,
    /// below and above the 5 MiB multipart threshold, so it can be read back. That holds for a write through the
    /// staged publish and for an upload straight to the path.
    ///
    /// Up to opendal 0.57, an upload straight to such a path landed under
    /// the path percent-encoded once, where nothing finds it, see
    /// [`gcs_name_repair`](super::super::gcs_name_repair). opendal 0.58.1
    /// encodes the name of an upload once.
    // Multi-threaded for the cleaner, which blocks on its async drop.
    #[cfg(feature = "storage-gcs")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs GCS_BUCKET and GOOGLE_APPLICATION_CREDENTIALS"]
    async fn gcs_stores_paths_with_special_characters_under_their_own_name() {
        use crate::persistence::files::staged_publish_layer::{
            under_expected_generation, ExpectedGeneration, STAGING_PREFIX,
        };
        use crate::persistence::files::test_support::TestBucket;

        let bucket = TestBucket::from_env();
        let _cleaner = bucket.test_root_cleaner();
        let service =
            OpendalService::new_from_operator(gcs_operator(bucket.test_root_builder()).unwrap());
        // The bare backend, to upload straight to a path and to see the names
        // the objects are stored under.
        let backend =
            with_own_http_client(opendal::Operator::new(bucket.test_root_builder()).unwrap());
        let pubkey = pubky_common::crypto::Keypair::random().public_key();
        let small = 1024;
        let large = 6 * 1024 * 1024;
        let files = [
            ("/pub/plain.txt", small),
            ("/pub/Teest%20share/.keep", small),
            ("/pub/a b+c#d%e.txt", small),
            ("/pub/\u{fc}\u{b7}~!'()*.txt", small),
            ("/pub/big%20file \u{fc}.bin", large),
        ]
        .map(|(path, size)| {
            let path = EntryPath::new(pubkey.clone(), StoragePath::new(path).unwrap());
            (path, size)
        });

        for (path, size) in &files {
            // What the finalization does for a new file.
            let write = service.operator.write(path.as_str(), vec![7u8; *size]);
            under_expected_generation(ExpectedGeneration::Absent, write)
                .await
                .unwrap();
            assert_eq!(service.blob_length(path).await.unwrap(), *size as u64);
            assert_eq!(service.get(path).await.unwrap().len(), *size, "{path}");
        }
        let uploaded_straight = [
            ("/pub/straight a b+c#d%e.txt", small),
            ("/pub/straight big \u{fc}.bin", large),
        ]
        .map(|(path, size)| {
            let path = EntryPath::new(pubkey.clone(), StoragePath::new(path).unwrap());
            (path, size)
        });
        for (path, size) in &uploaded_straight {
            backend
                .write(path.as_str(), vec![8u8; *size])
                .await
                .unwrap();
            assert_eq!(service.get(path).await.unwrap().len(), *size, "{path}");
        }

        let mut stored: Vec<String> = backend
            .list_with("")
            .recursive(true)
            .await
            .unwrap()
            .into_iter()
            .filter(|entry| entry.metadata().is_file())
            .map(|entry| entry.path().to_string())
            .filter(|name| !name.starts_with(STAGING_PREFIX))
            .collect();
        stored.sort();
        let mut expected: Vec<String> = files
            .iter()
            .chain(&uploaded_straight)
            .map(|(path, _)| path.as_str().to_string())
            .collect();
        expected.sort();
        assert_eq!(stored, expected);
    }

    /// Against the real bucket, see
    /// [`gcs_test_bucket`](crate::persistence::files::test_support::gcs_test_bucket), the production
    /// stack end to end:
    ///
    /// 1. Writes land through staging, below and above the 5 MiB multipart
    ///    threshold, and leave no staging object behind.
    /// 2. A write, a publish and a delete prepared against an object that a
    ///    newer write has since replaced are refused, and the newer data
    ///    stays.
    /// 3. A read returns one version of the object or fails, never bytes of
    ///    two: an overwrite between two chunks ends the stream.
    // Multi-threaded for the cleaner, which blocks on its async drop.
    #[cfg(feature = "storage-gcs")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs GCS_BUCKET and GOOGLE_APPLICATION_CREDENTIALS"]
    async fn gcs_refuses_stale_changes_and_mixed_reads() {
        use crate::persistence::files::layer_domain_error::LayerDomainError;
        use crate::persistence::files::staged_publish_layer::{
            live_generation, staging_objects, under_expected_generation, ExpectedGeneration,
        };
        use crate::persistence::files::test_support::TestBucket;

        let bucket = TestBucket::from_env();
        let _cleaner = bucket.test_root_cleaner();
        // The production stack, and the backend under its staged publish,
        // through which the late requests below are sent.
        let operator = gcs_operator(bucket.test_root_builder()).unwrap();
        let backend = gcs_unstaged_backend(bucket.test_root_builder()).unwrap();
        let entry_path = EntryPath::new(
            pubky_common::crypto::Keypair::random().public_key(),
            StoragePath::new("/pub/a.bin").unwrap(),
        );
        let path = entry_path.as_str();
        let small = 1024;
        let large = 6 * 1024 * 1024;

        // What the finalization does: read the generation, then change the
        // object under it.
        let generation = || async {
            live_generation(&backend, path)
                .await
                .unwrap()
                .expect("GCS reports a generation")
        };

        // 1. A single-request upload, then a multipart one.
        let g = generation().await;
        assert_eq!(g, ExpectedGeneration::Absent);
        under_expected_generation(g, operator.write(path, vec![1u8; small]))
            .await
            .unwrap();
        assert_eq!(
            operator.read(path).await.unwrap().to_vec(),
            vec![1u8; small]
        );
        let g = generation().await;
        under_expected_generation(g, operator.write(path, vec![2u8; large]))
            .await
            .unwrap();
        assert_eq!(
            operator.read(path).await.unwrap().to_vec(),
            vec![2u8; large]
        );
        assert_eq!(
            staging_objects(&operator).await,
            0,
            "every staging object was removed"
        );

        // 2. A write, a publish and a delete are prepared against the object
        // as it is now, a newer write lands, and all three are refused; the
        // newer data, itself a multipart upload, stays intact.
        let stale = generation().await;
        assert!(matches!(stale, ExpectedGeneration::Known(_)));
        under_expected_generation(stale, operator.write(path, vec![3u8; large]))
            .await
            .unwrap();
        let late_write = under_expected_generation(stale, operator.write(path, vec![4u8; small]))
            .await
            .expect_err("a write against a replaced object is refused");
        assert!(matches!(
            LayerDomainError::of(&late_write),
            Some(LayerDomainError::PublishConflict)
        ));
        backend.write("stale", vec![4u8; 10]).await.unwrap();
        let late_publish = backend
            .copy_with("stale", path)
            .if_version_match(&stale.version_condition())
            .await
            .expect_err("a publish against a replaced object is refused");
        assert_eq!(late_publish.kind(), opendal::ErrorKind::ConditionNotMatch);
        let late_delete = backend
            .delete_with(path)
            .if_version_match(&stale.version_condition())
            .await
            .expect_err("a delete against a replaced object is refused");
        assert_eq!(late_delete.kind(), opendal::ErrorKind::ConditionNotMatch);
        assert_eq!(
            operator.read(path).await.unwrap().to_vec(),
            vec![3u8; large]
        );

        // 3. A read through the server's read path, overwritten between two
        // of its chunks: what it delivered is the version it started on, and
        // it either completes that version or fails.
        let service = OpendalService::new_from_operator(operator.clone());
        let (length, mut stream) = service.get_sized_stream(&entry_path).await.unwrap();
        assert_eq!(length as usize, large);
        let first = stream.next().await.unwrap().unwrap();
        assert!(first.iter().all(|&byte| byte == 3));
        let g = generation().await;
        under_expected_generation(g, operator.write(path, vec![5u8; large]))
            .await
            .unwrap();
        let mut delivered = first.len();
        let mut ended_in = Ok(());
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(chunk) => {
                    assert!(
                        chunk.iter().all(|&byte| byte == 3),
                        "a chunk of the newer version was mixed in"
                    );
                    delivered += chunk.len();
                }
                Err(error) => {
                    ended_in = Err(error);
                    break;
                }
            }
        }
        assert!(
            ended_in.is_err() || delivered == large,
            "the read neither completed its version nor failed"
        );
        assert_eq!(
            operator.read(path).await.unwrap().to_vec(),
            vec![5u8; large]
        );

        let g = generation().await;
        under_expected_generation(g, operator.delete(path))
            .await
            .unwrap();
        assert!(!operator.exists(path).await.unwrap());
        assert_eq!(staging_objects(&operator).await, 0);
    }
}
