//! A layer that makes a local backend behave like an object store with
//! generations, and injects its refusals and delays.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use opendal::raw::oio::{self, Copy as _, Delete as _};
use opendal::raw::{
    Layer, OpCompose, OpCopy, OpCreateDir, OpDelete, OpList, OpPresign, OpRead, OpRename, OpStat,
    OpWrite, RpCreateDir, RpPresign, RpRead, RpRename, RpStat, Service, ServiceInfo, Servicer,
};
use opendal::{Buffer, BytesRange, Capability, ErrorKind, Metadata, OperationContext, Result};
use tokio::sync::oneshot;

use crate::persistence::files::staged_publish_layer::{ExpectedGeneration, STAGING_PREFIX};

/// A backend for tests that behaves like an object store on the points the
/// generation condition relies on. Layered over a real backend, which does
/// the storing without conditions.
///
/// - A stat reports the generation and an ETag. A read whose `If-Match` is
///   not the current ETag is refused when it is sent.
/// - Each copy, compose and delete of a real path records its condition in
///   `seen`.
/// - `refuse_copies`, `refuse_composes` and `refuse_deletes` refuse those
///   requests as the store does when the condition fails. A conditional
///   delete of a missing object is refused too.
/// - A compose of one source copies the generation asked for.
/// - The `stall_next_*` methods hold a stat, read or compose back until
///   told to go on.
/// - Deletes go through a batching deleter; `batched` records that a batch
///   ran.
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
        let expected = if_version_match.map(ExpectedGeneration::from_version_condition);
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
