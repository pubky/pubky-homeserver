//! Module for testing the opendal operators.
//! Allows to easily test all our storage options.
//! This is normally not necessary but helps to find subtle differences
//! in the opendal operators.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_dropper::{AsyncDrop, AsyncDropper};
use async_trait::async_trait;
use opendal::raw::oio::{self, Copy as _, Delete as _};
use opendal::raw::{
    Layer, OpCompose, OpCopy, OpCreateDir, OpDelete, OpList, OpPresign, OpRead, OpRename, OpStat,
    OpWrite, RpCreateDir, RpPresign, RpRead, RpRename, RpStat, Service, ServiceInfo, Servicer,
};
use opendal::{
    Buffer, BytesRange, Capability, ErrorKind, Metadata, OperationContext, Operator, Result,
};
use tempfile::TempDir;
use tokio::sync::oneshot;
use uuid::Uuid;

use super::opendal_service::with_own_http_client;
use crate::persistence::files::staged_publish_layer::{ExpectedGeneration, STAGING_PREFIX};

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
    let operator = opendal::Operator::new(builder).unwrap();
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
    let operator = with_own_http_client(opendal::Operator::new(builder)?);
    Ok(Some(operator))
}

pub(crate) fn get_memory_operator() -> Operator {
    let builder = opendal::services::Memory::default();

    opendal::Operator::new(builder).unwrap()
}

/// A backend for tests that behaves like an object store on the points the
/// generation condition relies on: it reports a generation and an ETag on
/// stat, refuses a read whose `If-Match` is not the current ETag when the
/// read is sent, records the condition each copy, compose and delete of a
/// real path carries, refuses a conditional delete of a missing object,
/// refuses copies, composes or deletes on demand as the store does when the
/// condition fails, composes one source as a copy of the generation asked
/// for, can hold a stat, read or compose back until told to go on, and
/// deletes through a batching deleter. Layered over a real backend, which
/// does the storing without conditions.
#[derive(Debug, Clone, Default)]
pub(crate) struct Versioned {
    generation: Arc<Mutex<String>>,
    pub(crate) seen: Arc<Mutex<Vec<Option<ExpectedGeneration>>>>,
    pub(crate) refuse_copies: Arc<AtomicBool>,
    pub(crate) refuse_composes: Arc<AtomicBool>,
    pub(crate) refuse_deletes: Arc<AtomicBool>,
    pub(crate) batched: Arc<AtomicBool>,
    stat_stall: Stall,
    read_stall: Stall,
    compose_stall: Stall,
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

    /// Hold the next read back until the returned sender is used.
    pub(crate) fn stall_next_read(&self) -> oneshot::Sender<()> {
        self.read_stall.arm()
    }

    pub(crate) async fn until_read_stalled(&self) {
        self.read_stall.until_reached().await;
    }

    /// Hold the next compose back until the returned sender is used. Whether
    /// it is refused is decided once it goes on.
    pub(crate) fn stall_next_compose(&self) -> oneshot::Sender<()> {
        self.compose_stall.arm()
    }

    pub(crate) async fn until_compose_stalled(&self) {
        self.compose_stall.until_reached().await;
    }

    /// Note the condition a copy or delete of a real path carries.
    fn record(&self, if_version_match: Option<&str>) {
        let expected = if_version_match.map(|version| match version {
            "0" => ExpectedGeneration::Absent,
            known => ExpectedGeneration::Known(known.parse().expect("a generation is a number")),
        });
        self.seen.lock().unwrap().push(expected);
    }
}

impl Layer for Versioned {
    fn apply_service(&self, inner: Servicer) -> Servicer {
        Arc::new(VersionedService {
            inner,
            backend: self.clone(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct VersionedService {
    inner: Servicer,
    backend: Versioned,
}

impl Service for VersionedService {
    type Reader = VersionedReader;
    type Writer = oio::Writer;
    type Lister = oio::Lister;
    type Deleter = oio::BatchDeleter<RecordingBatchDelete>;
    type Copier = oio::Copier;
    type Composer = oio::Composer;

    fn info(&self) -> ServiceInfo {
        self.inner.info()
    }

    /// The backend's, with the conditions an object store takes, and a
    /// compose of one source at a given generation.
    fn capability(&self) -> Capability {
        let mut capability = self.inner.capability();
        capability.read_with_if_match = true;
        capability.copy_with_if_version_match = true;
        capability.delete_with_if_version_match = true;
        capability.compose = true;
        capability.compose_with_source_version = true;
        capability.compose_with_if_version_match = true;
        capability.compose_with_content_type = true;
        capability
    }

    async fn create_dir(
        &self,
        ctx: &OperationContext,
        path: &str,
        args: OpCreateDir,
    ) -> Result<RpCreateDir> {
        self.inner.create_dir(ctx, path, args).await
    }

    async fn stat(&self, ctx: &OperationContext, path: &str, args: OpStat) -> Result<RpStat> {
        self.backend.stat_stall.hold().await;
        let metadata = self.inner.stat(ctx, path, args).await?.into_metadata();
        let mut metadata = metadata.into_builder();
        metadata
            .version(self.backend.generation())
            .etag(self.backend.etag());
        Ok(RpStat::new(metadata.build()))
    }

    /// The condition is checked when the read is sent, as an object store
    /// checks it. It is not passed on: the backend underneath does not
    /// support it.
    fn read(&self, ctx: &OperationContext, path: &str, args: OpRead) -> Result<Self::Reader> {
        Ok(VersionedReader {
            inner: self.inner.read(ctx, path, OpRead::new())?,
            if_match: args.if_match().map(str::to_string),
            backend: self.backend.clone(),
        })
    }

    fn write(&self, ctx: &OperationContext, path: &str, args: OpWrite) -> Result<Self::Writer> {
        self.inner.write(ctx, path, args)
    }

    fn delete(&self, ctx: &OperationContext) -> Result<Self::Deleter> {
        let deleter = RecordingBatchDelete {
            inner: self.inner.clone(),
            ctx: ctx.clone(),
            backend: self.backend.clone(),
        };
        Ok(oio::BatchDeleter::new(deleter, Some(100)))
    }

    fn list(&self, ctx: &OperationContext, path: &str, args: OpList) -> Result<Self::Lister> {
        self.inner.list(ctx, path, args)
    }

    fn copy(
        &self,
        ctx: &OperationContext,
        from: &str,
        to: &str,
        args: OpCopy,
    ) -> Result<Self::Copier> {
        self.backend.record(args.if_version_match());
        if self.backend.refuse_copies.load(Ordering::SeqCst) {
            return Err(refusal());
        }
        self.inner.copy(ctx, from, to, OpCopy::new())
    }

    fn compose(&self, ctx: &OperationContext, to: &str, args: OpCompose) -> Result<Self::Composer> {
        Ok(Box::new(VersionedComposer {
            inner: self.inner.clone(),
            ctx: ctx.clone(),
            to: to.to_string(),
            if_version_match: args.if_version_match().map(str::to_string),
            source: None,
            backend: self.backend.clone(),
        }))
    }

    async fn rename(
        &self,
        ctx: &OperationContext,
        from: &str,
        to: &str,
        args: OpRename,
    ) -> Result<RpRename> {
        self.inner.rename(ctx, from, to, args).await
    }

    async fn presign(
        &self,
        ctx: &OperationContext,
        path: &str,
        args: OpPresign,
    ) -> Result<RpPresign> {
        self.inner.presign(ctx, path, args).await
    }
}

/// What an object store answers when a condition does not hold.
fn refusal() -> opendal::Error {
    opendal::Error::new(ErrorKind::ConditionNotMatch, "412 Precondition Failed")
}

/// Reader that refuses a read conditional on another ETag than the current
/// one at the time it is sent, as an object store does once the object was
/// replaced.
pub(crate) struct VersionedReader {
    inner: oio::Reader,
    if_match: Option<String>,
    backend: Versioned,
}

impl VersionedReader {
    fn check_condition(&self) -> Result<()> {
        match &self.if_match {
            Some(etag) if *etag != self.backend.etag() => Err(refusal()),
            _ => Ok(()),
        }
    }
}

impl oio::Read for VersionedReader {
    async fn open(&self, range: BytesRange) -> Result<(RpRead, Box<dyn oio::ReadStreamDyn>)> {
        self.backend.read_stall.hold().await;
        self.check_condition()?;
        self.inner.open(range).await
    }

    async fn read(&self, range: BytesRange) -> Result<(RpRead, Buffer)> {
        self.backend.read_stall.hold().await;
        self.check_condition()?;
        self.inner.read(range).await
    }
}

/// Composes one source, as the GCS name repair does, by copying it in the
/// backend underneath. A source generation other than the current one is
/// gone, as on a bucket that keeps no older generations: not found.
pub(crate) struct VersionedComposer {
    inner: Servicer,
    ctx: OperationContext,
    to: String,
    if_version_match: Option<String>,
    /// The source path and the generation asked for.
    source: Option<(String, Option<String>)>,
    backend: Versioned,
}

impl oio::Compose for VersionedComposer {
    async fn compose(&mut self, path: &str, args: OpRead) -> Result<()> {
        if self.source.is_some() {
            return Err(opendal::Error::new(
                ErrorKind::Unsupported,
                "the test backend composes one source",
            ));
        }
        self.source = Some((path.to_string(), args.version().map(str::to_string)));
        Ok(())
    }

    async fn close(&mut self) -> Result<Metadata> {
        self.backend.compose_stall.hold().await;
        self.backend.record(self.if_version_match.as_deref());
        if self.backend.refuse_composes.load(Ordering::SeqCst) {
            return Err(refusal());
        }
        let Some((from, generation)) = self.source.take() else {
            return Err(opendal::Error::new(
                ErrorKind::ConfigInvalid,
                "a compose needs a source",
            ));
        };
        if generation.is_some_and(|generation| generation != self.backend.generation()) {
            return Err(opendal::Error::new(
                ErrorKind::NotFound,
                "404 the source generation is gone",
            ));
        }
        let mut copier = self.inner.copy(&self.ctx, &from, &self.to, OpCopy::new())?;
        while copier.next().await?.is_some() {}
        copier.close().await
    }
}

/// Deletes one path at a time as told, and notes a batch, which this test
/// backend cannot run under a condition per path.
pub(crate) struct RecordingBatchDelete {
    inner: Servicer,
    ctx: OperationContext,
    backend: Versioned,
}

impl RecordingBatchDelete {
    async fn exists(&self, path: &str) -> Result<bool> {
        match self.inner.stat(&self.ctx, path, OpStat::new()).await {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

impl oio::BatchDelete for RecordingBatchDelete {
    async fn delete_once(&self, path: String, args: OpDelete) -> Result<()> {
        let condition = args.if_version_match();
        if path.starts_with(STAGING_PREFIX) {
            // A staging object never has the real path's generation: a
            // removal under one is refused, as an object store refuses it.
            if condition.is_some() {
                return Err(refusal());
            }
        } else {
            self.backend.record(condition);
            if self.backend.refuse_deletes.load(Ordering::SeqCst) {
                return Err(refusal());
            }
            // An object store refuses a conditional delete of a missing
            // object; the backend underneath would report success.
            if condition.is_some() && !self.exists(&path).await? {
                return Err(refusal());
            }
        }
        let mut deleter = self.inner.delete(&self.ctx)?;
        deleter.delete(&path, OpDelete::new()).await?;
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

impl Layer for CountingReads {
    fn apply_service(&self, inner: Servicer) -> Servicer {
        Arc::new(CountingReadsService {
            inner,
            reads: self.reads.clone(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct CountingReadsService {
    inner: Servicer,
    reads: Arc<AtomicUsize>,
}

impl Service for CountingReadsService {
    type Reader = CountingReader;
    type Writer = oio::Writer;
    type Lister = oio::Lister;
    type Deleter = oio::Deleter;
    type Copier = oio::Copier;
    type Composer = oio::Composer;

    fn info(&self) -> ServiceInfo {
        self.inner.info()
    }

    fn capability(&self) -> Capability {
        self.inner.capability()
    }

    async fn create_dir(
        &self,
        ctx: &OperationContext,
        path: &str,
        args: OpCreateDir,
    ) -> Result<RpCreateDir> {
        self.inner.create_dir(ctx, path, args).await
    }

    async fn stat(&self, ctx: &OperationContext, path: &str, args: OpStat) -> Result<RpStat> {
        self.inner.stat(ctx, path, args).await
    }

    fn read(&self, ctx: &OperationContext, path: &str, args: OpRead) -> Result<Self::Reader> {
        Ok(CountingReader {
            inner: self.inner.read(ctx, path, args)?,
            reads: self.reads.clone(),
        })
    }

    fn write(&self, ctx: &OperationContext, path: &str, args: OpWrite) -> Result<Self::Writer> {
        self.inner.write(ctx, path, args)
    }

    fn delete(&self, ctx: &OperationContext) -> Result<Self::Deleter> {
        self.inner.delete(ctx)
    }

    fn list(&self, ctx: &OperationContext, path: &str, args: OpList) -> Result<Self::Lister> {
        self.inner.list(ctx, path, args)
    }

    fn copy(
        &self,
        ctx: &OperationContext,
        from: &str,
        to: &str,
        args: OpCopy,
    ) -> Result<Self::Copier> {
        self.inner.copy(ctx, from, to, args)
    }

    async fn rename(
        &self,
        ctx: &OperationContext,
        from: &str,
        to: &str,
        args: OpRename,
    ) -> Result<RpRename> {
        self.inner.rename(ctx, from, to, args).await
    }

    async fn presign(
        &self,
        ctx: &OperationContext,
        path: &str,
        args: OpPresign,
    ) -> Result<RpPresign> {
        self.inner.presign(ctx, path, args).await
    }
}

/// Reader that counts every request it sends.
pub(crate) struct CountingReader {
    inner: oio::Reader,
    reads: Arc<AtomicUsize>,
}

impl oio::Read for CountingReader {
    async fn open(&self, range: BytesRange) -> Result<(RpRead, Box<dyn oio::ReadStreamDyn>)> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.open(range).await
    }

    async fn read(&self, range: BytesRange) -> Result<(RpRead, Buffer)> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read(range).await
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
