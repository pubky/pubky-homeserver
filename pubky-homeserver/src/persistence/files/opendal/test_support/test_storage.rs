//! The backends the storage contract runs on, see [`storage_contract_tests`].

use opendal::Operator;
use tempfile::TempDir;

/// Runs each storage contract case as a test of its own on each backend:
/// `memory::<case>`, `file_system::<case>` and `gcs::<case>`. A case is an
/// `async fn(Operator)` in the calling module.
///
/// The `gcs` tests run against the real bucket and are ignored unless asked
/// for, see [`gcs_test_bucket`](super::gcs_test_bucket).
///
/// ```ignore
/// async fn reads_back_what_was_written(operator: Operator) { /* ... */ }
///
/// storage_contract_tests!(reads_back_what_was_written);
/// ```
macro_rules! storage_contract_tests {
    ($($case:ident),+ $(,)?) => {
        mod memory {
            use $crate::persistence::files::test_support::TestStorage;
            $(
                #[tokio::test]
                async fn $case() {
                    let storage = TestStorage::memory();
                    super::$case(storage.operator.clone()).await;
                }
            )+
        }

        mod file_system {
            use $crate::persistence::files::test_support::TestStorage;
            $(
                #[tokio::test]
                async fn $case() {
                    let storage = TestStorage::file_system();
                    super::$case(storage.operator.clone()).await;
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
                async fn $case() {
                    let storage = TestStorage::gcs();
                    super::$case(storage.operator.clone()).await;
                }
            )+
        }
    };
}
pub(crate) use storage_contract_tests;

/// A backend the storage contract runs on. Dropping it at the end of the
/// test removes what the test stored.
pub(crate) struct TestStorage {
    pub(crate) operator: Operator,
    _cleanup: Cleanup,
}

/// What a backend removes once the test is done, by being dropped.
enum Cleanup {
    /// The memory backend goes with its operator.
    Nothing,
    FileSystem {
        _directory: TempDir,
    },
    #[cfg(feature = "storage-gcs")]
    Bucket {
        _test_root: async_dropper::AsyncDropper<super::gcs_test_bucket::BucketCleaner>,
    },
}

impl TestStorage {
    pub(crate) fn memory() -> Self {
        Self {
            operator: get_memory_operator(),
            _cleanup: Cleanup::Nothing,
        }
    }

    /// The filesystem backend configured like production, in a temporary
    /// directory.
    pub(crate) fn file_system() -> Self {
        let (operator, directory) = get_fs_operator();
        Self {
            operator,
            _cleanup: Cleanup::FileSystem {
                _directory: directory,
            },
        }
    }

    /// The GCS backend in the bucket from the environment, under a root of
    /// the test's own. Without the staged publish on top, which refuses a
    /// write or delete that the finalization did not give a generation; the
    /// GCS tests of the staged publish cover it.
    ///
    /// # Panics
    ///
    /// If the bucket isn't configured, see [`TestBucket::from_env`].
    ///
    /// [`TestBucket::from_env`]: super::gcs_test_bucket::TestBucket::from_env
    #[cfg(feature = "storage-gcs")]
    pub(crate) fn gcs() -> Self {
        let bucket = super::gcs_test_bucket::TestBucket::from_env();
        let operator =
            super::super::opendal_service::gcs_unstaged_backend(bucket.test_root_builder())
                .expect("the bucket builder is valid");
        Self {
            operator,
            _cleanup: Cleanup::Bucket {
                _test_root: bucket.test_root_cleaner(),
            },
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
