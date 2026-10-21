//! The backends the storage contract runs on, see [`storage_contract_tests`].

use std::path::PathBuf;
use std::sync::Arc;

use opendal::Operator;
use pubky_common::crypto::{Keypair, PublicKey};
use tempfile::TempDir;

use super::super::opendal_service::{
    backend_operator, layer_storage_operators, OpendalService, FILE_SYSTEM_STAGING_DIR,
};
use crate::persistence::files::FileIoError;
use crate::persistence::sql::entry::EntryRepository;
use crate::shared::webdav::{EntryPath, StoragePath};
use crate::storage_config::StorageConfigToml;
use crate::AppContext;

/// Runs each storage contract case as a test of its own on each backend:
/// `memory::<case>`, `file_system::<case>` and `gcs::<case>`. A case is an
/// `async fn(&TestStorage)` in the calling module.
///
/// The `gcs` tests run against the real bucket and are ignored unless asked
/// for, see [`gcs_test_bucket`](super::gcs_test_bucket).
///
/// ```ignore
/// async fn reads_back_what_was_written(storage: &TestStorage) { /* ... */ }
///
/// storage_contract_tests!(reads_back_what_was_written);
/// ```
macro_rules! storage_contract_tests {
    ($($case:ident),+ $(,)?) => {
        mod memory {
            use $crate::persistence::files::test_support::TestStorage;
            $(
                #[tokio::test]
                #[pubky_test_utils::test]
                async fn $case() {
                    super::$case(&TestStorage::memory().await).await;
                }
            )+
        }

        mod file_system {
            use $crate::persistence::files::test_support::TestStorage;
            $(
                #[tokio::test]
                #[pubky_test_utils::test]
                async fn $case() {
                    super::$case(&TestStorage::file_system().await).await;
                }
            )+
        }

        #[cfg(feature = "storage-gcs")]
        mod gcs {
            use $crate::persistence::files::test_support::TestStorage;
            $(
                // Multi-threaded for the cleaner, which blocks on its async drop.
                #[tokio::test(flavor = "multi_thread")]
                #[ignore = "needs GCS_BUCKET and GOOGLE_APPLICATION_CREDENTIALS"]
                #[pubky_test_utils::test]
                async fn $case() {
                    super::$case(&TestStorage::gcs().await).await;
                }
            )+
        }
    };
}
pub(crate) use storage_contract_tests;

/// A backend under the layers production puts on it: the finalization of
/// every write and delete with its entry, and the write paths. A case writes
/// as [`Self::path`]'s user, who is signed up. Dropping it at the end of the
/// test removes what the test stored.
pub(crate) struct TestStorage {
    /// The app-facing service over the layered backend.
    pub(crate) service: OpendalService,
    user: PublicKey,
    backend: Backend,
    /// Holds the test database the finalization writes to.
    context: Arc<AppContext>,
}

/// The backend under a [`TestStorage`], with where it stages uploads and
/// what it removes once dropped.
enum Backend {
    /// Stages nothing, and goes with its operator.
    Memory,
    FileSystem {
        staging_dir: PathBuf,
        _directory: TempDir,
    },
    #[cfg(feature = "storage-gcs")]
    Bucket {
        operator: Operator,
        _test_root: Box<async_dropper::AsyncDropper<super::gcs_test_bucket::BucketCleaner>>,
    },
}

impl TestStorage {
    pub(crate) async fn memory() -> Self {
        Self::layered_over(get_memory_operator(), Backend::Memory).await
    }

    /// The filesystem backend as production configures it, in a temporary
    /// data directory.
    pub(crate) async fn file_system() -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory is created");
        let operator = backend_operator(&StorageConfigToml::FileSystem, directory.path())
            .expect("the filesystem backend builds");
        let backend = Backend::FileSystem {
            staging_dir: directory.path().join(FILE_SYSTEM_STAGING_DIR),
            _directory: directory,
        };
        Self::layered_over(operator, backend).await
    }

    /// The GCS backend as production builds it, with the staged publish, in
    /// the bucket from the environment under a root of the test's own.
    ///
    /// # Panics
    ///
    /// If the bucket isn't configured, see [`TestBucket::from_env`].
    ///
    /// [`TestBucket::from_env`]: super::gcs_test_bucket::TestBucket::from_env
    #[cfg(feature = "storage-gcs")]
    pub(crate) async fn gcs() -> Self {
        let bucket = super::gcs_test_bucket::TestBucket::from_env();
        let operator = super::super::opendal_service::gcs_operator(bucket.test_root_builder())
            .expect("the bucket builder is valid");
        let backend = Backend::Bucket {
            operator: operator.clone(),
            _test_root: Box::new(bucket.test_root_cleaner()),
        };
        Self::layered_over(operator, backend).await
    }

    async fn layered_over(backend_operator: Operator, backend: Backend) -> Self {
        let context = AppContext::test().await;
        let user = Keypair::random().public_key();
        context
            .user_service
            .create(&user)
            .await
            .expect("a new user is created");
        let (operator, admin_operator) = layer_storage_operators(
            backend_operator,
            context.config_toml.storage.default_quota_mb,
            context.sql_db.clone(),
            context.events_service.clone(),
            context.user_service.clone(),
        );
        Self {
            service: OpendalService {
                operator,
                admin_operator,
            },
            user,
            backend,
            context,
        }
    }

    /// `path` of the signed-up user.
    pub(crate) fn path(&self, path: &str) -> EntryPath {
        EntryPath::new(
            self.user.clone(),
            StoragePath::new(path).expect("the test uses a valid storage path"),
        )
    }

    /// Asserts that the entry of `path` describes the stored file, with its
    /// length and hash, and that there is no entry when no file is stored.
    pub(crate) async fn assert_entry_matches_file(&self, path: &EntryPath) {
        let entry =
            EntryRepository::get_by_path(path, &mut self.context.sql_db.pool().into()).await;
        match self.service.get(path).await {
            Ok(content) => {
                let entry = entry.expect("a stored file has an entry");
                assert_eq!(entry.content_length, content.len() as u64, "{path}");
                assert_eq!(
                    entry.content_hash,
                    pubky_common::crypto::hash(&content),
                    "{path}"
                );
            }
            Err(FileIoError::NotFound) => assert!(
                matches!(entry, Err(sqlx::Error::RowNotFound)),
                "{path} has an entry but no file: {entry:?}"
            ),
            Err(error) => panic!("{path} can't be read: {error}"),
        }
    }

    /// Whether a download of a few MiB arrives in more than one stream item,
    /// so that a write can land between two of them. The memory backend
    /// delivers a blob in one item.
    pub(crate) fn downloads_in_several_items(&self) -> bool {
        !matches!(self.backend, Backend::Memory)
    }

    /// Whether no upload is left staged: each one was published or removed.
    pub(crate) async fn staging_is_empty(&self) -> bool {
        match &self.backend {
            Backend::Memory => true,
            Backend::FileSystem { staging_dir, .. } => match std::fs::read_dir(staging_dir) {
                Ok(mut entries) => entries.next().is_none(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(error) => panic!("the staging directory can't be read: {error}"),
            },
            #[cfg(feature = "storage-gcs")]
            Backend::Bucket { operator, .. } => {
                crate::persistence::files::staged_publish_layer::staging_objects(operator).await
                    == 0
            }
        }
    }
}

/// Creates a filesystem operator.
/// The operator will be created in a temporary directory.
/// The directory is returned and will be deleted when TempDir is dropped.
///
/// Configured like production: uploads are staged in a sibling directory and
/// renamed into place on close.
pub(crate) fn get_fs_operator() -> (Operator, TempDir) {
    let tmp_dir = tempfile::tempdir().unwrap();
    let root = tmp_dir.path().join("files");
    let staging = tmp_dir.path().join("files-tmp");
    let builder = opendal::services::Fs::default()
        .root(root.to_str().unwrap())
        .atomic_write_dir(staging.to_str().unwrap());
    let operator = opendal::Operator::new(builder).unwrap();
    (operator, tmp_dir)
}

pub(crate) fn get_memory_operator() -> Operator {
    let builder = opendal::services::Memory::default();

    opendal::Operator::new(builder).unwrap()
}
