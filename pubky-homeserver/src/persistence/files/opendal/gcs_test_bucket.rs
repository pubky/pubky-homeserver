//! The real Google Cloud Storage bucket the GCS tests run against.
//!
//! Those tests are `#[ignore]`d, so `cargo test` stays offline, and each has
//! `gcs` in its name. Run them with `GCS_BUCKET` and
//! `GOOGLE_APPLICATION_CREDENTIALS` set:
//!
//! ```sh
//! cargo nextest run -p pubky-homeserver --all-features \
//!   --run-ignored only -E 'test(/gcs/)'
//! ```
//!
//! A test that runs without the variables fails rather than skips, so a run
//! that asked for the bucket can't pass without it. Each test works under a
//! prefix of its own and deletes it when done, so tests can share the bucket
//! and run in parallel.

use async_dropper::{AsyncDrop, AsyncDropper};
use async_trait::async_trait;
use opendal::Operator;
use pubky_common::crypto::PublicKey;
use uuid::Uuid;

use super::opendal_service::gcs_unstaged_backend;
use crate::data_directory::storage_config::{GoogleBucketConfig, GoogleServiceAccountKeyConfig};

const BUCKET_VAR: &str = "GCS_BUCKET";
const CREDENTIALS_VAR: &str = "GOOGLE_APPLICATION_CREDENTIALS";

/// The bucket named by the environment, with a root of the test's own.
pub(crate) struct TestBucket {
    bucket: String,
    credentials: String,
    test_root: String,
}

impl TestBucket {
    /// The bucket from the environment.
    ///
    /// # Panics
    ///
    /// If `GCS_BUCKET` or `GOOGLE_APPLICATION_CREDENTIALS` is not set.
    pub(crate) fn from_env() -> Self {
        let var = |name: &str| {
            std::env::var(name).unwrap_or_else(|_| {
                panic!("{name} must be set to run the GCS tests, see docs/TESTING.md")
            })
        };
        Self {
            bucket: var(BUCKET_VAR),
            credentials: var(CREDENTIALS_VAR),
            test_root: new_test_root(),
        }
    }

    /// A builder for the bucket under the test root.
    pub(crate) fn test_root_builder(&self) -> opendal::services::Gcs {
        self.bucket_root_builder().root(&self.test_root)
    }

    /// The homeserver's config for the bucket. It has no root, so a
    /// homeserver stores its entries in the bucket's root, under the keys of
    /// its users: delete those with [`Self::user_cleaner`].
    pub(crate) fn config(&self) -> GoogleBucketConfig {
        GoogleBucketConfig {
            bucket_name: self.bucket.clone(),
            credential: GoogleServiceAccountKeyConfig::Path(self.credentials.clone().into()),
        }
    }

    /// Deletes the test root from the bucket when dropped.
    pub(crate) fn test_root_cleaner(&self) -> AsyncDropper<BucketCleaner> {
        self.prefix_cleaner(&self.test_root)
    }

    /// Deletes everything a homeserver stored for `user` when dropped.
    pub(crate) fn user_cleaner(&self, user: &PublicKey) -> AsyncDropper<BucketCleaner> {
        self.prefix_cleaner(&user.z32())
    }

    fn prefix_cleaner(&self, prefix: &str) -> AsyncDropper<BucketCleaner> {
        AsyncDropper::new(BucketCleaner {
            bucket: Some(self.bucket_root()),
            prefix: format!("{prefix}/"),
        })
    }

    /// The bucket without a root.
    fn bucket_root(&self) -> Operator {
        gcs_unstaged_backend(self.bucket_root_builder()).expect("the bucket builder is valid")
    }

    fn bucket_root_builder(&self) -> opendal::services::Gcs {
        opendal::services::Gcs::default()
            .bucket(&self.bucket)
            .credential_path(&self.credentials)
    }
}

/// `ci/<run id>/<uuid>` in a GitHub Actions run, so a leftover can be traced
/// to its run, and `test_<uuid>` otherwise. A lifecycle rule on the bucket
/// deletes what a killed test leaves.
fn new_test_root() -> String {
    let test_id = Uuid::new_v4();
    match std::env::var("GITHUB_RUN_ID") {
        Ok(run_id) => format!("ci/{run_id}/{test_id}"),
        Err(_) => format!("test_{test_id}"),
    }
}

/// Deletes a prefix of the bucket when dropped. The drop blocks on the
/// delete, so the test needs `#[tokio::test(flavor = "multi_thread")]`.
#[derive(Default)]
pub(crate) struct BucketCleaner {
    /// The bucket without a root. `None` only in the default the dropper
    /// leaves behind.
    bucket: Option<Operator>,
    prefix: String,
}

#[async_trait]
impl AsyncDrop for BucketCleaner {
    async fn async_drop(&mut self) {
        let Some(bucket) = &self.bucket else {
            return;
        };
        if let Err(error) = bucket.delete_with(&self.prefix).recursive(true).await {
            println!(
                "Failed to clean up {} in the GCS test bucket: {error}",
                self.prefix
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Multi-threaded for the cleaner, which blocks on its async drop.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs GCS_BUCKET and GOOGLE_APPLICATION_CREDENTIALS"]
    async fn gcs_cleaner_removes_the_test_root() {
        let bucket = TestBucket::from_env();
        {
            let _cleaner = bucket.test_root_cleaner();
            let test_root = gcs_unstaged_backend(bucket.test_root_builder()).unwrap();
            test_root.write("a/test.txt", "test").await.unwrap();
        }

        let left = bucket
            .bucket_root()
            .list_with(&format!("{}/", bucket.test_root))
            .recursive(true)
            .await
            .unwrap();
        assert!(left.is_empty(), "the cleaner left {left:?}");
    }
}
