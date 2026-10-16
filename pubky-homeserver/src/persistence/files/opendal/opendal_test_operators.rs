//! Module for testing the opendal operators.
//! Allows to easily test all our storage options.
//! This is normally not necessary but helps to find subtle differences
//! in the opendal operators.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_dropper::{AsyncDrop, AsyncDropper};
use async_trait::async_trait;
use opendal::raw::oio::{self, Delete as _};
use opendal::raw::{
    Access, Layer, LayeredAccess, OpCopier, OpCopy, OpDelete, OpList, OpRead, OpStat, OpWrite,
    RpCopy, RpDelete, RpList, RpRead, RpStat, RpWrite,
};
use opendal::{ErrorKind, Operator, Result};
use tempfile::TempDir;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::persistence::files::staged_publish_layer::{
    expected_generation, ExpectedGeneration, STAGING_PREFIX,
};

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
/// // Multi-threaded for the GCS cleaner, which blocks on its async drop.
/// #[tokio::test(flavor = "multi_thread")]
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
    pub fn operators(&self) -> Vec<(&'static str, Operator)> {
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
pub(crate) struct OpendalGcpCleaner {
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
        match base_gcs_operator
            .delete_with(&test_root_dir)
            .recursive(true)
            .await
        {
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
    // A client of its own: opendal's default is one shared by the process,
    // and a connection it pools dies with the runtime that opened it. Each
    // test, and the cleaner, runs on a runtime of its own, so a shared pool
    // hands one test a connection that died with another's runtime.
    let http_client = opendal::raw::HttpClient::with(reqwest::Client::new());
    let operator = opendal::Operator::new(builder)?
        .layer(opendal::layers::HttpClientLayer::new(http_client))
        .finish();
    Ok(Some(operator))
}

pub(crate) fn get_memory_operator() -> Operator {
    let builder = opendal::services::Memory::default();

    opendal::Operator::new(builder).unwrap().finish()
}

/// A backend for tests that behaves like an object store on the points the
/// generation condition relies on: it reports a generation and an ETag on
/// stat, refuses a read whose `If-Match` is not the current ETag, records
/// the condition each copy and delete of a real path ran under, refuses
/// copies or deletes on demand as the store does when the condition fails,
/// can hold a stat or a copy back until told to go on, and deletes through a
/// batching deleter. Layered over a real backend, which does the storing.
#[derive(Debug, Clone, Default)]
pub(crate) struct Versioned {
    generation: Arc<Mutex<String>>,
    pub(crate) seen: Arc<Mutex<Vec<Option<ExpectedGeneration>>>>,
    pub(crate) refuse_copies: Arc<AtomicBool>,
    pub(crate) refuse_deletes: Arc<AtomicBool>,
    pub(crate) batched: Arc<AtomicBool>,
    stat_stall: Stall,
    copy_stall: Stall,
}

/// Holds the next call of one kind back until the test lets it go on, so the
/// test can change the store while the call is in flight.
#[derive(Debug, Clone, Default)]
struct Stall {
    release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    reached: Arc<AtomicBool>,
}

impl Stall {
    /// Hold the next call back until the returned sender is used.
    fn arm(&self) -> oneshot::Sender<()> {
        let (release, stalled) = oneshot::channel();
        *self.release.lock().unwrap() = Some(stalled);
        release
    }

    /// Called by the call: waits for the release if the stall is armed.
    async fn hold(&self) {
        let release = self.release.lock().unwrap().take();
        if let Some(release) = release {
            self.reached.store(true, Ordering::SeqCst);
            release.await.expect("the test lets the call go on");
        }
    }

    async fn until_reached(&self) {
        for _ in 0..500 {
            if self.reached.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("the call never stalled");
    }
}

impl Versioned {
    pub(crate) fn new(generation: &str) -> Self {
        let versioned = Self::default();
        versioned.set_generation(generation);
        versioned
    }

    /// Make every object report `generation` from now on, as an overwrite
    /// of all of them would.
    pub(crate) fn set_generation(&self, generation: &str) {
        *self.generation.lock().unwrap() = generation.to_string();
    }

    fn generation(&self) -> String {
        self.generation.lock().unwrap().clone()
    }

    fn etag(&self) -> String {
        format!("\"generation-{}\"", self.generation())
    }

    /// Hold the next stat back until the returned sender is used.
    pub(crate) fn stall_next_stat(&self) -> oneshot::Sender<()> {
        self.stat_stall.arm()
    }

    pub(crate) async fn until_stat_stalled(&self) {
        self.stat_stall.until_reached().await;
    }

    /// Hold the next copy back until the returned sender is used. Whether it
    /// is refused is decided once it goes on.
    pub(crate) fn stall_next_copy(&self) -> oneshot::Sender<()> {
        self.copy_stall.arm()
    }

    pub(crate) async fn until_copy_stalled(&self) {
        self.copy_stall.until_reached().await;
    }
}

impl<A: Access> Layer<A> for Versioned {
    type LayeredAccess = VersionedAccessor<A>;

    fn layer(&self, inner: A) -> Self::LayeredAccess {
        VersionedAccessor {
            inner: Arc::new(inner),
            backend: self.clone(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct VersionedAccessor<A> {
    inner: Arc<A>,
    backend: Versioned,
}

impl<A: Access> LayeredAccess for VersionedAccessor<A> {
    type Inner = A;
    type Reader = A::Reader;
    type Writer = A::Writer;
    type Lister = A::Lister;
    type Deleter = oio::BatchDeleter<RecordingBatchDelete<A>>;
    type Copier = A::Copier;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    /// Refuses a read conditional on another ETag than the current one, as
    /// an object store does once the object was replaced. The condition is
    /// not passed on: the backend underneath does not support it.
    async fn read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::Reader)> {
        if args
            .if_match()
            .is_some_and(|etag| etag != self.backend.etag())
        {
            return Err(refusal());
        }
        let unconditional = OpRead::new().with_range(args.range());
        self.inner.read(path, unconditional).await
    }

    async fn write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::Writer)> {
        self.inner.write(path, args).await
    }

    async fn list(&self, path: &str, args: OpList) -> Result<(RpList, Self::Lister)> {
        self.inner.list(path, args).await
    }

    async fn stat(&self, path: &str, args: OpStat) -> Result<RpStat> {
        self.backend.stat_stall.hold().await;
        let mut metadata = self.inner.stat(path, args).await?.into_metadata();
        metadata.set_version(&self.backend.generation());
        metadata.set_etag(&self.backend.etag());
        Ok(RpStat::new(metadata))
    }

    async fn copy(
        &self,
        from: &str,
        to: &str,
        args: OpCopy,
        opts: OpCopier,
    ) -> Result<(RpCopy, Self::Copier)> {
        self.backend.copy_stall.hold().await;
        self.backend
            .seen
            .lock()
            .unwrap()
            .push(expected_generation());
        if self.backend.refuse_copies.load(Ordering::SeqCst) {
            return Err(refusal());
        }
        self.inner.copy(from, to, args, opts).await
    }

    async fn delete(&self) -> Result<(RpDelete, Self::Deleter)> {
        let deleter = RecordingBatchDelete {
            inner: self.inner.clone(),
            backend: self.backend.clone(),
        };
        Ok((
            RpDelete::default(),
            oio::BatchDeleter::new(deleter, Some(100)),
        ))
    }
}

/// What an object store answers when a condition does not hold.
fn refusal() -> opendal::Error {
    opendal::Error::new(ErrorKind::ConditionNotMatch, "412 Precondition Failed")
}

/// Deletes one path at a time as told, and notes a batch, which an object
/// store would run without any condition.
pub(crate) struct RecordingBatchDelete<A> {
    inner: Arc<A>,
    backend: Versioned,
}

impl<A: Access> oio::BatchDelete for RecordingBatchDelete<A> {
    async fn delete_once(&self, path: String, args: OpDelete) -> Result<()> {
        if path.starts_with(STAGING_PREFIX) {
            // A staging object never has the real path's generation: a
            // removal under one is refused, as an object store refuses it.
            if expected_generation().is_some() {
                return Err(refusal());
            }
        } else {
            self.backend
                .seen
                .lock()
                .unwrap()
                .push(expected_generation());
            if self.backend.refuse_deletes.load(Ordering::SeqCst) {
                return Err(refusal());
            }
        }
        let (_, mut deleter) = self.inner.delete().await?;
        deleter.delete(&path, args).await?;
        deleter.close().await
    }

    async fn delete_batch(
        &self,
        _batch: Vec<(String, OpDelete)>,
    ) -> Result<oio::BatchDeleteResult> {
        self.backend.batched.store(true, Ordering::SeqCst);
        Err(opendal::Error::new(
            ErrorKind::Unexpected,
            "a batch carries no condition",
        ))
    }
}

/// Counts the reads that reach the backend underneath. Each one is a request
/// of its own on an object store, so their count is what a download costs.
#[derive(Debug, Clone, Default)]
pub(crate) struct CountingReads {
    reads: Arc<AtomicUsize>,
}

impl CountingReads {
    pub(crate) fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl<A: Access> Layer<A> for CountingReads {
    type LayeredAccess = CountingReadsAccessor<A>;

    fn layer(&self, inner: A) -> Self::LayeredAccess {
        CountingReadsAccessor {
            inner,
            reads: self.reads.clone(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct CountingReadsAccessor<A> {
    inner: A,
    reads: Arc<AtomicUsize>,
}

impl<A: Access> LayeredAccess for CountingReadsAccessor<A> {
    type Inner = A;
    type Reader = A::Reader;
    type Writer = A::Writer;
    type Lister = A::Lister;
    type Deleter = A::Deleter;
    type Copier = A::Copier;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    async fn read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::Reader)> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read(path, args).await
    }

    async fn write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::Writer)> {
        self.inner.write(path, args).await
    }

    async fn list(&self, path: &str, args: OpList) -> Result<(RpList, Self::Lister)> {
        self.inner.list(path, args).await
    }

    async fn delete(&self) -> Result<(RpDelete, Self::Deleter)> {
        self.inner.delete().await
    }
}

#[cfg(test)]
mod tests {
    use opendal::Buffer;

    use super::*;

    // Multi-threaded for the cleaner, which blocks on its async drop.
    #[tokio::test(flavor = "multi_thread")]
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

    // Multi-threaded for the cleaner, which blocks on its async drop.
    #[tokio::test(flavor = "multi_thread")]
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
