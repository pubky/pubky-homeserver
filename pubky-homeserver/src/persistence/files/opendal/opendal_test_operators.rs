//! Module for testing the opendal operators.
//! Allows to easily test all our storage options.
//! This is normally not necessary but helps to find subtle differences
//! in the opendal operators.

use std::sync::Arc;

use async_dropper::{AsyncDrop, AsyncDropper};
use async_trait::async_trait;
use opendal::Operator;
use tempfile::TempDir;
use uuid::Uuid;

/// A provider of operators for testing.
///
/// Provides:
/// - A filesystem operator
/// - A memory operator
/// - A GCS operator (if the environment variables are set)
///
/// The GCS operator is only available if the required environment variables are set.
/// GCS environment variables:
/// - GOOGLE_APPLICATION_CREDENTIALS: The path to the GCS credentials file.
/// - GCS_BUCKET: The name of the GCS bucket.
///
/// Example:
/// ```ignore
/// #[tokio::test]
/// async fn test_ensure_valid_path() {
///     // Iterate over all operators.
///     for (_scheme, operator) in OpendalTestOperators::new().operators() {
///         // Add a layer to the operator if needed.
///         let operator = operator.layer(MyStorageLayer::new());
///         // Perform tests
///         operator.write("1234567890/test.txt", vec![0; 10]).await.expect_err("Should fail because the path doesn't start with a pubkey");
///         // No need to clean up the operator as it is automatically cleaned up when OpendalTestOperators is dropped.
///     };
/// }
/// ```
pub struct OpendalTestOperators {
    pub fs_operator: Operator,
    /// The temporary directory for the fs operator.
    #[allow(dead_code)]
    fs_tmp_dir: Arc<TempDir>,
    pub gcs_operator: Option<Operator>,
    pub memory_operator: Operator,
    #[allow(dead_code)]
    /// Cleaner will remove the gcp bucket when dropped
    gcp_cleaner: Option<Arc<AsyncDropper<OpendalGcpCleaner>>>,
}

impl OpendalTestOperators {
    /// Create a new instance of the OperatorTestProviders.
    pub fn new() -> Self {
        let (fs_operator, fs_tmp_dir) = get_fs_operator();
        let gcs_operator = get_gcs_operator(true).expect("GCS operator should be available");
        let gcp_cleaner = gcs_operator.as_ref().map(|operator| {
            Arc::new(AsyncDropper::new(OpendalGcpCleaner::new(Some(
                operator.clone(),
            ))))
        });
        Self {
            fs_operator,
            fs_tmp_dir: Arc::new(fs_tmp_dir),
            gcs_operator,
            memory_operator: get_memory_operator(),
            gcp_cleaner,
        }
    }

    /// Get all operators.
    pub fn operators(&self) -> Vec<(opendal::Scheme, Operator)> {
        let mut operators = vec![
            (self.fs_operator.info().scheme(), self.fs_operator.clone()),
            (
                self.memory_operator.info().scheme(),
                self.memory_operator.clone(),
            ),
        ];
        if let Some(gcs_operator) = &self.gcs_operator {
            operators.push((gcs_operator.info().scheme(), gcs_operator.clone()));
        }
        operators
    }

    /// Check if the GCS operator is available.
    /// This depends on the environment variables being set. See OpendalProviders docs for more details.
    pub fn is_gcs_available(&self) -> bool {
        self.gcs_operator.is_some()
    }
}

/// Helper struct to clean up the GCS operator after the test.
/// Important: This requires the tokio::test(flavor = "multi_thread") attribute,
/// Otherwise the test will panic when the gcp cleaner is dropped
#[derive(Default)]
struct OpendalGcpCleaner {
    pub gcs_operator: Option<Operator>,
}

impl OpendalGcpCleaner {
    pub fn new(gcs_operator: Option<Operator>) -> Self {
        Self { gcs_operator }
    }
}

#[async_trait]
impl AsyncDrop for OpendalGcpCleaner {
    async fn async_drop(&mut self) {
        let gcs_operator = match &self.gcs_operator {
            Some(operator) => operator,
            None => return,
        };
        // Delete all files in the GCS root directory that are related to the test.
        let test_root_dir = gcs_operator.info().root();
        let base_gcs_operator = match get_gcs_operator(false) {
            Ok(Some(operator)) => operator,
            Ok(None) => {
                return;
            }
            Err(e) => {
                println!(
                    "Failed to cleanup the GCP test bucket. Directory: {}, Error: {}",
                    test_root_dir, e
                );
                return;
            }
        };
        match base_gcs_operator.remove_all(&test_root_dir).await {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "Failed to cleanup the GCP test bucket. Directory: {}, Error: {}",
                    test_root_dir, e
                );
            }
        }
    }
}

/// Creates a filesystem operator.
/// The operator will be created in a temporary directory.
/// The directory is returned and will be deleted when TempDir is dropped.
pub(crate) fn get_fs_operator() -> (Operator, TempDir) {
    let tmp_dir = tempfile::tempdir().unwrap();
    let s = tmp_dir.path().to_str().unwrap();
    let builder = opendal::services::Fs::default().root(s);
    let operator = opendal::Operator::new(builder).unwrap().finish();
    (operator, tmp_dir)
}

/// Creates a GCS operator if the required environment variables are set.
/// GCS environment variables:
/// - GOOGLE_APPLICATION_CREDENTIALS: The path to the GCS credentials file.
/// - GCS_BUCKET: The name of the GCS bucket.
///
/// Set `test_root_dir` to true to create a random directory that the operator
/// lives in. This is useful to avoid conflicts with other tests.
pub(crate) fn get_gcs_operator(test_root_dir: bool) -> anyhow::Result<Option<Operator>> {
    let credential_path = match std::env::var("GOOGLE_APPLICATION_CREDENTIALS") {
        Ok(path) => path,
        Err(_) => return Ok(None),
    };
    let bucket_name = match std::env::var("GCS_BUCKET") {
        Ok(path) => path,
        Err(_) => return Ok(None),
    };
    let mut builder = opendal::services::Gcs::default()
        .bucket(&bucket_name)
        .credential_path(&credential_path);
    if test_root_dir {
        builder = builder.root(&format!("test_{}", Uuid::new_v4()));
    }
    let operator = opendal::Operator::new(builder)?.finish();
    Ok(Some(operator))
}

pub(crate) fn get_memory_operator() -> Operator {
    let builder = opendal::services::Memory::default();

    opendal::Operator::new(builder).unwrap().finish()
}

#[cfg(test)]
mod tests {
    use opendal::Buffer;

    use super::*;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_operator_test_providers() {
        let providers = OpendalTestOperators::new();
        let operators = providers.operators();
        if providers.is_gcs_available() {
            assert!(
                operators.len() == 3,
                "Expected 3 operators, got {}",
                operators.len()
            );
            println!("GCS operator is available"); // Log to make it clear that GCS is included in the tests.
        } else {
            assert!(
                operators.len() == 2,
                "Expected 2 operators, got {}",
                operators.len()
            );
            println!("GCS operator is NOT available"); // Log to make it clear that GCS is NOT included in the tests.
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_gcs_cleanup() {
        let test_root_dir = {
            let operators = OpendalTestOperators::new();
            if !operators.is_gcs_available() {
                // GCS not configured. Skip test.
                return;
            }
            let gcs_operator = operators.gcs_operator.as_ref().unwrap().clone();
            gcs_operator
                .write("test.txt", Buffer::from("test"))
                .await
                .unwrap();
            gcs_operator.info().root()
        };
        tokio::time::sleep(std::time::Duration::from_secs(1)).await; // Sleep to ensure the Drop impl is executed in the background.
        let base_gcs_operator = get_gcs_operator(false).unwrap().unwrap();
        let exists = base_gcs_operator.exists(&test_root_dir).await.unwrap();
        assert!(!exists, "Test root directory should not exist anymore as it should have been deleted by the Drop impl");
    }
}
