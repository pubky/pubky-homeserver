//! Runs an asynchronous check before a write or copy reaches the backend.
//!
//! opendal creates writers and copiers synchronously, so a layer cannot check
//! a path against the database before it hands one out. Instead, the check
//! runs before the first byte, the close, or the copy goes to the layer
//! underneath. A refused write sends nothing to the backend.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use opendal::raw::oio::{self, Copy as _};
use opendal::{Buffer, Metadata, Result};

/// An asynchronous check that a write or copy may go ahead. It must be safe
/// to run more than once: a refused check runs again on the next attempt.
pub(crate) type Preflight = Arc<dyn Fn() -> BoxFuture<'static, Result<()>> + Send + Sync>;

/// Writer that runs its preflight before anything reaches `inner`.
pub(crate) struct PreflightWriter<W> {
    inner: W,
    preflight: Preflight,
    passed: bool,
}

impl<W> PreflightWriter<W> {
    pub(crate) fn new(inner: W, preflight: Preflight) -> Self {
        Self {
            inner,
            preflight,
            passed: false,
        }
    }

    /// Run the preflight unless it has passed. A refused preflight runs
    /// again on the next call, so a later write cannot slip past it.
    async fn ensure_passed(&mut self) -> Result<()> {
        if !self.passed {
            (self.preflight)().await?;
            self.passed = true;
        }
        Ok(())
    }
}

impl<W: oio::Write> oio::Write for PreflightWriter<W> {
    async fn write(&mut self, bs: Buffer) -> Result<()> {
        self.ensure_passed().await?;
        self.inner.write(bs).await
    }

    async fn close(&mut self) -> Result<Metadata> {
        self.ensure_passed().await?;
        self.inner.close().await
    }

    async fn abort(&mut self) -> Result<()> {
        self.inner.abort().await
    }
}

/// A copier that runs `preflight`, then creates the copier underneath with
/// `copier` and drives it to completion as the operator would. A copy that
/// fails is aborted.
pub(crate) fn preflight_copier(
    preflight: Preflight,
    copier: impl FnOnce() -> Result<oio::Copier> + Send + 'static,
) -> oio::OneShotCopier {
    oio::OneShotCopier::new(async move {
        preflight().await?;
        let mut copier = copier()?;
        match copier.close().await {
            Ok(metadata) => Ok(metadata),
            Err(error) => {
                let _ = copier.abort().await;
                Err(error)
            }
        }
    })
}
