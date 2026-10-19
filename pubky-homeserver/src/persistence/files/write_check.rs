//! Runs an asynchronous check before a write or copy reaches the backend.
//!
//! opendal creates writers and copiers synchronously, so a layer cannot check
//! a path against the database before it hands one out. Instead, the check
//! runs before the first byte, the close, or the copy goes to the layer
//! underneath. A refused write sends nothing to the backend, as long as
//! creating the backend's writer sends nothing either, which holds for the
//! backends the homeserver uses.

use std::future::Future;

use opendal::raw::oio::{self, Copy as _};
use opendal::raw::{OpCopy, Service as _, Servicer};
use opendal::{Buffer, Metadata, OperationContext, Result};

/// A check that a write or copy may go ahead. It must be safe to run more
/// than once: a refused check runs again on the next attempt.
pub(crate) trait WriteCheck: Unpin + Send + Sync + 'static {
    fn check(&self) -> impl Future<Output = Result<()>> + Send;
}

/// Writer that runs its check before anything reaches `inner`.
pub(crate) struct CheckedWriter<W, C> {
    inner: W,
    check: C,
    passed: bool,
}

impl<W, C: WriteCheck> CheckedWriter<W, C> {
    pub(crate) fn new(inner: W, check: C) -> Self {
        Self {
            inner,
            check,
            passed: false,
        }
    }

    /// Run the check unless it has passed.
    async fn ensure_passed(&mut self) -> Result<()> {
        if !self.passed {
            self.check.check().await?;
            self.passed = true;
        }
        Ok(())
    }
}

impl<W: oio::Write, C: WriteCheck> oio::Write for CheckedWriter<W, C> {
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

/// A copier that runs `check`, then copies `from` to `to` on `inner` and
/// drives the copy to completion as the operator would. A copy that fails is
/// aborted.
pub(crate) fn checked_copier(
    check: impl WriteCheck,
    inner: &Servicer,
    ctx: &OperationContext,
    from: &str,
    to: &str,
    args: OpCopy,
) -> oio::OneShotCopier {
    let (inner, ctx, from, to) = (inner.clone(), ctx.clone(), from.to_string(), to.to_string());
    oio::OneShotCopier::new(async move {
        check.check().await?;
        let mut copier = inner.copy(&ctx, &from, &to, args)?;
        match copier.close().await {
            Ok(metadata) => Ok(metadata),
            Err(error) => {
                // The copy's error is the one to report. A failed abort
                // leaves at most a partial copy, which the copy's own
                // error already covers.
                let _ = copier.abort().await;
                Err(error)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    use opendal::raw::oio::Write as _;
    use opendal::{ErrorKind, MetadataBuilder, Operator};

    use crate::persistence::files::test_support::get_fs_operator;

    use super::*;

    /// A check that counts its runs and refuses while told to.
    #[derive(Clone, Default)]
    struct StubCheck {
        refuse: Arc<AtomicBool>,
        runs: Arc<AtomicUsize>,
    }

    impl StubCheck {
        fn refusing() -> Self {
            let check = Self::default();
            check.refuse.store(true, Ordering::SeqCst);
            check
        }

        fn runs(&self) -> usize {
            self.runs.load(Ordering::SeqCst)
        }
    }

    impl WriteCheck for StubCheck {
        async fn check(&self) -> Result<()> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            if self.refuse.load(Ordering::SeqCst) {
                return Err(opendal::Error::new(ErrorKind::PermissionDenied, "refused"));
            }
            Ok(())
        }
    }

    /// A writer that records what reached it.
    #[derive(Default)]
    struct RecordingWriter {
        writes: usize,
        closes: usize,
        aborts: usize,
    }

    impl oio::Write for RecordingWriter {
        async fn write(&mut self, _bs: Buffer) -> Result<()> {
            self.writes += 1;
            Ok(())
        }

        async fn close(&mut self) -> Result<Metadata> {
            self.closes += 1;
            Ok(MetadataBuilder::unknown().build())
        }

        async fn abort(&mut self) -> Result<()> {
            self.aborts += 1;
            Ok(())
        }
    }

    fn checked(check: &StubCheck) -> CheckedWriter<RecordingWriter, StubCheck> {
        CheckedWriter::new(RecordingWriter::default(), check.clone())
    }

    #[tokio::test]
    async fn a_refused_write_never_reaches_the_inner_writer() {
        let check = StubCheck::refusing();
        let mut writer = checked(&check);

        let error = writer.write(Buffer::from("data")).await.unwrap_err();

        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(writer.inner.writes, 0);
    }

    #[tokio::test]
    async fn a_refused_close_never_reaches_the_inner_writer() {
        let check = StubCheck::refusing();
        let mut writer = checked(&check);

        let error = writer.close().await.unwrap_err();

        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert_eq!(writer.inner.closes, 0);
    }

    #[tokio::test]
    async fn a_refused_check_runs_again_on_the_next_call() {
        let check = StubCheck::refusing();
        let mut writer = checked(&check);

        writer.write(Buffer::from("data")).await.unwrap_err();
        writer.write(Buffer::from("data")).await.unwrap_err();
        writer.close().await.unwrap_err();

        assert_eq!(check.runs(), 3);
        assert_eq!((writer.inner.writes, writer.inner.closes), (0, 0));
    }

    #[tokio::test]
    async fn a_passed_check_runs_once() {
        let check = StubCheck::default();
        let mut writer = checked(&check);

        writer.write(Buffer::from("a")).await.unwrap();
        writer.write(Buffer::from("b")).await.unwrap();
        writer.close().await.unwrap();

        assert_eq!(check.runs(), 1);
        assert_eq!((writer.inner.writes, writer.inner.closes), (2, 1));
    }

    #[tokio::test]
    async fn abort_is_forwarded_without_the_check() {
        let check = StubCheck::refusing();
        let mut writer = checked(&check);

        writer.abort().await.unwrap();

        assert_eq!(check.runs(), 0);
        assert_eq!(writer.inner.aborts, 1);
    }

    /// Copy `from` to `to` on `backend` through a checked copier.
    async fn checked_copy(
        check: StubCheck,
        backend: Operator,
        from: &str,
        to: &str,
    ) -> Result<Metadata> {
        let (ctx, inner) = backend.into_parts();
        checked_copier(check, &inner, &ctx, from, to, OpCopy::default())
            .close()
            .await
    }

    #[tokio::test]
    async fn a_refused_copy_never_reaches_the_backend() {
        let (backend, _tmp_dir) = get_fs_operator();
        backend.write("from.txt", "data").await.unwrap();

        let error = checked_copy(StubCheck::refusing(), backend.clone(), "from.txt", "to.txt")
            .await
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert!(!backend.exists("to.txt").await.unwrap());
    }

    #[tokio::test]
    async fn a_passed_copy_reaches_the_backend() {
        let (backend, _tmp_dir) = get_fs_operator();
        backend.write("from.txt", "data").await.unwrap();

        checked_copy(StubCheck::default(), backend.clone(), "from.txt", "to.txt")
            .await
            .unwrap();

        let copied = backend.read("to.txt").await.unwrap();
        assert_eq!(copied.to_vec(), b"data");
    }

    #[tokio::test]
    async fn a_failed_copy_returns_the_backend_error() {
        let (backend, _tmp_dir) = get_fs_operator();

        let error = checked_copy(StubCheck::default(), backend, "missing.txt", "to.txt")
            .await
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::NotFound);
    }
}
