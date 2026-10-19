//! A layer that counts the reads a backend receives.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use opendal::raw::oio;
use opendal::raw::{
    Layer, OpCopy, OpCreateDir, OpList, OpPresign, OpRead, OpRename, OpStat, OpWrite, RpCreateDir,
    RpPresign, RpRead, RpRename, RpStat, Service, ServiceInfo, Servicer,
};
use opendal::{Buffer, BytesRange, Capability, OperationContext, Result};

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
