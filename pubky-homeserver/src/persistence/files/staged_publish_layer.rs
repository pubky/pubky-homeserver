//! Publishes a write by a conditional copy from a staging object, and deletes
//! under a condition, for a backend whose publish must be told what it is
//! replacing.
//!
//! An object store executes a request whenever it gets to it, so a publish or
//! delete the homeserver gave up on can still run long after, when the lock
//! it was made under has moved on, on top of a newer write. Here every
//! publish and delete carries the generation of the object it was made
//! against, and the backend refuses a request that finds another. A stale
//! request lands only if nothing has been written since, so it can never
//! replace a newer write. A write being finalized wins over it, unless it
//! lands after the generation was read: then the write is refused with a
//! conflict, and its client reads again and retries, see
//! [`write_lock`](super::write_finalization_layer::write_lock). A path
//! deleted since can receive it as an unreferenced blob, which the next
//! write or delete on the path clears.
//!
//! The generation is read by the finalization, inside its transaction and
//! under the user row, with the transaction proven alive after the read, see
//! `generation_under_lock` in the finalization layer. Only then does it
//! predate every change a later holder may make. This layer does not read
//! it: it publishes and deletes under the generation it is given, and
//! refuses to do either without one.
//!
//! The price is three more requests per write, a stat, a copy and a delete,
//! on top of the upload itself.
//!
//! Google Cloud Storage takes that condition on a single-request upload, a
//! copy and a delete, but not on a multipart upload. So the upload itself
//! goes, whatever its size and with no condition, to a staging object under
//! [`STAGING_PREFIX`], and the publish is one server-side copy from there to
//! the real path, carrying the condition. The staging object is removed once
//! the copy has answered. An upload that lands late lands on its own unique
//! staging name, where it is harmless. A crash between the upload and the
//! copy, or a failed removal, leaves a staging object behind: a lifecycle
//! rule on the prefix is the cheap way to sweep those.
//!
//! The condition travels to the request as a task-local, set by the
//! finalization around the publish or delete and read by the backend's HTTP
//! client when it sends the copy or delete, see [`expected_generation`]. The
//! layer is generic and does nothing backend-specific itself.

use std::sync::Arc;

use opendal::raw::oio::{self, Copy as _, Delete as _};
use opendal::raw::{
    Access, Layer, LayeredAccess, OpCopier, OpCopy, OpDelete, OpList, OpRead, OpStat, OpWrite,
    RpDelete, RpList, RpRead, RpWrite,
};
use opendal::{ErrorKind, Metadata, Result};

use super::layer_domain_error::LayerDomainError;

/// Where uploads are staged. Never a user path: a user path begins with a
/// public key, which cannot start with a dot.
const STAGING_PREFIX: &str = ".staging/";

/// What a publish or delete must find at the real path to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExpectedGeneration {
    /// No object: the request must create it.
    Absent,
    /// The object at this generation.
    Known(u64),
}

impl ExpectedGeneration {
    /// The value an `ifGenerationMatch` condition takes. Zero asks for no
    /// live object.
    pub(crate) fn if_generation_match(self) -> u64 {
        match self {
            Self::Absent => 0,
            Self::Known(generation) => generation,
        }
    }
}

tokio::task_local! {
    static EXPECTED_GENERATION: ExpectedGeneration;
}

/// The generation the current task's backend request must find, if it is a
/// publish or delete made under one.
pub(crate) fn expected_generation() -> Option<ExpectedGeneration> {
    EXPECTED_GENERATION.try_with(|expected| *expected).ok()
}

/// Run `request`, a publish or delete, under `expected`.
pub(crate) async fn under_expected_generation<T>(
    expected: ExpectedGeneration,
    request: impl std::future::Future<Output = T>,
) -> T {
    EXPECTED_GENERATION.scope(expected, request).await
}

/// The generation the object at `path` has now. `None` on a backend that
/// reports no usable generation: a publish or delete under `None` is refused
/// by this layer, see [`StagedWriter`].
pub(crate) async fn live_generation<A: Access>(
    backend: &A,
    path: &str,
) -> Result<Option<ExpectedGeneration>> {
    match backend.stat(path, OpStat::new()).await {
        Ok(stat) => Ok(stat
            .into_metadata()
            .version()
            .and_then(|version| version.parse().ok())
            .map(ExpectedGeneration::Known)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Some(ExpectedGeneration::Absent)),
        Err(error) => Err(error),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StagedPublishLayer;

impl<A: Access> Layer<A> for StagedPublishLayer {
    type LayeredAccess = StagedPublishAccessor<A>;

    fn layer(&self, inner: A) -> Self::LayeredAccess {
        StagedPublishAccessor {
            inner: Arc::new(inner),
        }
    }
}

#[derive(Debug)]
pub struct StagedPublishAccessor<A: Access> {
    inner: Arc<A>,
}

impl<A: Access> LayeredAccess for StagedPublishAccessor<A> {
    type Inner = A;
    type Reader = A::Reader;
    type Writer = StagedWriter<A>;
    type Lister = A::Lister;
    type Deleter = ConditionalDeleter<A>;
    type Copier = A::Copier;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    async fn read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::Reader)> {
        self.inner.read(path, args).await
    }

    async fn write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::Writer)> {
        let staging = format!("{STAGING_PREFIX}{}", uuid::Uuid::new_v4());
        let (rp, writer) = self.inner.write(&staging, args).await?;
        Ok((
            rp,
            StagedWriter {
                inner: self.inner.clone(),
                writer,
                staging,
                path: path.to_string(),
                upload: Upload::Open,
            },
        ))
    }

    async fn delete(&self) -> Result<(RpDelete, Self::Deleter)> {
        Ok((
            RpDelete::default(),
            ConditionalDeleter {
                inner: self.inner.clone(),
            },
        ))
    }

    async fn list(&self, path: &str, args: OpList) -> Result<(RpList, Self::Lister)> {
        self.inner.list(path, args).await
    }
}

/// Where the staged upload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Upload {
    /// Still being written; the backend writer owns it.
    Open,
    /// Closed, so the staging object exists and is ours to remove.
    Staged,
    /// Nothing left to do: published and removed, aborted, or closed
    /// without an answer, when the backend may still finish it and a late
    /// abort could cancel a completed upload.
    Done,
}

/// Writer that uploads to a staging object and publishes it on close, under
/// the generation the task provides.
pub struct StagedWriter<A: Access> {
    inner: Arc<A>,
    writer: A::Writer,
    staging: String,
    path: String,
    upload: Upload,
}

impl<A: Access> oio::Write for StagedWriter<A> {
    async fn write(&mut self, bs: opendal::Buffer) -> Result<()> {
        self.writer.write(bs).await
    }

    /// Finish the upload and publish it: one copy, conditional on the
    /// generation the task provides.
    async fn close(&mut self) -> Result<Metadata> {
        // An upload the backend did not confirm may still have made the
        // staging object. It is not ours to reason about: the sweep gets it.
        if let Err(error) = self.writer.close().await {
            self.upload = Upload::Done;
            return Err(error);
        }
        self.upload = Upload::Staged;

        let published = match expected_generation() {
            Some(expected) => {
                let published = publish(self.inner.as_ref(), &self.staging, &self.path).await;
                refused_as_conflict(published, &self.path, expected)
            }
            None => Err(no_generation(&self.path)),
        };
        self.remove_staging().await;
        published
    }

    /// Discard the upload: the backend's staged bytes while it is open, the
    /// staging object once it is closed.
    async fn abort(&mut self) -> Result<()> {
        match self.upload {
            Upload::Open => {
                self.upload = Upload::Done;
                self.writer.abort().await
            }
            Upload::Staged => {
                self.remove_staging().await;
                Ok(())
            }
            Upload::Done => Ok(()),
        }
    }
}

impl<A: Access> StagedWriter<A> {
    /// Remove the staging object, if there is one. Best effort: a leftover
    /// is for the sweep, and must not fail the publish it follows.
    async fn remove_staging(&mut self) {
        if self.upload != Upload::Staged {
            return;
        }
        self.upload = Upload::Done;
        if let Err(error) = remove(self.inner.as_ref(), &self.staging, OpDelete::new()).await {
            tracing::warn!(
                staging = %self.staging,
                path = %self.path,
                %error,
                "Failed to remove a staging object"
            );
        }
    }
}

/// Deleter that removes each object under the generation the task provides,
/// so a delete executed late finds a changed object and is refused.
pub struct ConditionalDeleter<A: Access> {
    inner: Arc<A>,
}

impl<A: Access> oio::Delete for ConditionalDeleter<A> {
    /// Sent at once rather than queued, on a backend deleter of its own: the
    /// condition is per object and carried by the request for that one
    /// object. A batch of several would carry none, see the backend's HTTP
    /// client, and a backend deleter keeps a refused path to resend it with
    /// the next.
    async fn delete(&mut self, path: &str, args: OpDelete) -> Result<()> {
        let Some(expected) = expected_generation() else {
            return Err(no_generation(path));
        };
        let deleted = remove(self.inner.as_ref(), path, args).await;
        refused_as_conflict(deleted, path, expected)
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Copy `from` onto `to`, as the operator would.
async fn publish<A: Access>(inner: &A, from: &str, to: &str) -> Result<Metadata> {
    let (_, mut copier) = inner.copy(from, to, OpCopy::new(), OpCopier::new()).await?;
    match copier.close().await {
        Ok(metadata) => Ok(metadata),
        Err(error) => {
            let _ = copier.abort().await;
            Err(error)
        }
    }
}

/// Remove `path` on a backend deleter of its own, flushed at once.
async fn remove<A: Access>(inner: &A, path: &str, args: OpDelete) -> Result<()> {
    let (_, mut deleter) = inner.delete().await?;
    deleter.delete(path, args).await?;
    deleter.close().await
}

/// Pass `result` on, turning a refusal of the condition into a publish
/// conflict. The backend found another object than `expected`: a stale
/// request was about to land, or something wrote past the entry row.
fn refused_as_conflict<T>(
    result: Result<T>,
    path: &str,
    expected: ExpectedGeneration,
) -> Result<T> {
    match result {
        Err(error) if error.kind() == ErrorKind::ConditionNotMatch => {
            tracing::warn!(
                path = %path,
                ?expected,
                %error,
                "Refused by the backend: the object is not the one the change was made against"
            );
            Err(publish_conflict(path, error))
        }
        result => result,
    }
}

/// The change was not made under a generation: the finalization read none,
/// because the backend reports none. Going ahead would publish unconditionally.
fn no_generation(path: &str) -> opendal::Error {
    opendal::Error::new(
        ErrorKind::Unsupported,
        format!("No generation to change {path} under: the backend reports none"),
    )
}

fn publish_conflict(path: &str, error: opendal::Error) -> opendal::Error {
    opendal::Error::new(
        ErrorKind::ConditionNotMatch,
        format!("The object at {path} is not the one the change was made against: {error}"),
    )
    .set_source(LayerDomainError::PublishConflict)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use opendal::raw::{OpCopier, RpStat};
    use opendal::Operator;
    use tempfile::TempDir;
    use tokio::sync::oneshot;

    use super::*;
    use crate::persistence::files::write_finalization_layer::test_support::{
        create_user, test_operator_over,
    };
    use crate::persistence::files::FileIoError;
    use crate::persistence::sql::{entry::EntryRepository, SqlDb};
    use crate::shared::webdav::{EntryPath, StoragePath};

    /// A backend that reports a generation on stat, records the condition
    /// each copy and delete of a real path ran under, refuses copies or
    /// deletes as an object store does when the condition fails, can hold a
    /// stat back until told to go on, and deletes through a batching
    /// deleter, as an object store does.
    #[derive(Debug, Clone, Default)]
    struct Versioned {
        generation: &'static str,
        seen: Arc<Mutex<Vec<Option<ExpectedGeneration>>>>,
        refuse_copies: Arc<AtomicBool>,
        refuse_deletes: Arc<AtomicBool>,
        batched: Arc<AtomicBool>,
        stall_stat: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
        stat_stalled: Arc<AtomicBool>,
    }

    impl Versioned {
        /// Hold the next stat back until the returned sender is used.
        fn stall_next_stat(&self) -> oneshot::Sender<()> {
            let (release, stalled) = oneshot::channel();
            *self.stall_stat.lock().unwrap() = Some(stalled);
            release
        }

        async fn until_stat_stalled(&self) {
            for _ in 0..500 {
                if self.stat_stalled.load(Ordering::SeqCst) {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            panic!("the stat never stalled");
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
    struct VersionedAccessor<A> {
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

        async fn read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::Reader)> {
            self.inner.read(path, args).await
        }

        async fn write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::Writer)> {
            self.inner.write(path, args).await
        }

        async fn list(&self, path: &str, args: OpList) -> Result<(RpList, Self::Lister)> {
            self.inner.list(path, args).await
        }

        async fn stat(&self, path: &str, args: OpStat) -> Result<RpStat> {
            let stalled = self.backend.stall_stat.lock().unwrap().take();
            if let Some(stalled) = stalled {
                self.backend.stat_stalled.store(true, Ordering::SeqCst);
                stalled.await.expect("the test lets the stat go on");
            }
            let mut metadata = self.inner.stat(path, args).await?.into_metadata();
            metadata.set_version(self.backend.generation);
            Ok(RpStat::new(metadata))
        }

        async fn copy(
            &self,
            from: &str,
            to: &str,
            args: OpCopy,
            opts: OpCopier,
        ) -> Result<(opendal::raw::RpCopy, Self::Copier)> {
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

    fn refusal() -> opendal::Error {
        opendal::Error::new(ErrorKind::ConditionNotMatch, "412 Precondition Failed")
    }

    /// Deletes one path at a time as told, and notes a batch, which an object
    /// store would run without any condition.
    struct RecordingBatchDelete<A> {
        inner: Arc<A>,
        backend: Versioned,
    }

    impl<A: Access> oio::BatchDelete for RecordingBatchDelete<A> {
        async fn delete_once(&self, path: String, args: OpDelete) -> Result<()> {
            if !path.starts_with(STAGING_PREFIX) {
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

    /// The filesystem backend, which supports copy and abort as an object
    /// store does; the in-memory one supports neither.
    fn plain_fs() -> (Operator, TempDir) {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path().join("files");
        let atomic = tmp_dir.path().join("atomic");
        let builder = opendal::services::Fs::default()
            .root(root.to_str().unwrap())
            .atomic_write_dir(atomic.to_str().unwrap());
        (Operator::new(builder).unwrap().finish(), tmp_dir)
    }

    /// The filesystem backend reporting generation 7 for every object, under
    /// the staged publish. The versioned backend is returned to steer it.
    fn staged_fs() -> (Operator, Versioned, TempDir) {
        let (backend, tmp_dir) = plain_fs();
        let versioned = Versioned {
            generation: "7",
            ..Versioned::default()
        };
        let operator = backend.layer(versioned.clone()).layer(StagedPublishLayer);
        (operator, versioned, tmp_dir)
    }

    /// Run `request` as the finalization would: under generation 7.
    async fn under_7<T>(request: impl std::future::Future<Output = T>) -> T {
        under_expected_generation(ExpectedGeneration::Known(7), request).await
    }

    /// Staging objects left behind. The listing names the prefix itself too.
    async fn staging_objects(operator: &Operator) -> usize {
        operator.list(STAGING_PREFIX).await.map_or(0, |entries| {
            entries
                .iter()
                .filter(|entry| entry.metadata().is_file())
                .count()
        })
    }

    #[tokio::test]
    async fn write_publishes_from_a_staging_object_and_removes_it() {
        let (operator, versioned, _tmp_dir) = staged_fs();
        let path = "pk/pub/a.txt";

        under_7(operator.write(path, b"first".to_vec()))
            .await
            .unwrap();
        assert_eq!(operator.read(path).await.unwrap().to_vec(), b"first");
        assert_eq!(staging_objects(&operator).await, 0);

        under_7(operator.write(path, b"second".to_vec()))
            .await
            .unwrap();
        assert_eq!(operator.read(path).await.unwrap().to_vec(), b"second");
        assert_eq!(staging_objects(&operator).await, 0);
        assert_eq!(
            *versioned.seen.lock().unwrap(),
            vec![
                Some(ExpectedGeneration::Known(7)),
                Some(ExpectedGeneration::Known(7))
            ],
            "each publish ran under the generation it was given"
        );
    }

    /// Without a generation nothing is published or deleted: the layer must
    /// not fall back to an unconditional change.
    #[tokio::test]
    async fn write_and_delete_are_refused_without_a_generation() {
        let (operator, versioned, _tmp_dir) = staged_fs();
        let path = "pk/pub/a.txt";

        let refused = operator
            .write(path, b"unconditional".to_vec())
            .await
            .expect_err("a publish without a generation is refused");
        assert_eq!(refused.kind(), ErrorKind::Unsupported);
        assert!(!operator.exists(path).await.unwrap());
        assert_eq!(staging_objects(&operator).await, 0);

        under_7(operator.write(path, b"kept".to_vec()))
            .await
            .unwrap();
        let refused = operator
            .delete(path)
            .await
            .expect_err("a delete without a generation is refused");
        assert_eq!(refused.kind(), ErrorKind::Unsupported);
        assert!(operator.exists(path).await.unwrap());
        assert_eq!(versioned.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn aborted_upload_leaves_nothing_behind() {
        let (operator, _versioned, _tmp_dir) = staged_fs();
        let path = "pk/pub/a.txt";
        under_7(operator.write(path, b"kept".to_vec()))
            .await
            .unwrap();

        let mut writer = operator.writer(path).await.unwrap();
        writer.write(b"dropped".to_vec()).await.unwrap();
        writer.abort().await.unwrap();

        assert_eq!(operator.read(path).await.unwrap().to_vec(), b"kept");
        assert_eq!(staging_objects(&operator).await, 0);
    }

    #[tokio::test]
    async fn delete_removes_the_object_under_its_generation() {
        let (operator, versioned, _tmp_dir) = staged_fs();
        let path = "pk/pub/a.txt";
        under_7(operator.write(path, b"gone".to_vec()))
            .await
            .unwrap();

        under_7(operator.delete(path)).await.unwrap();
        assert!(!operator.exists(path).await.unwrap());
        assert_eq!(
            versioned.seen.lock().unwrap().last(),
            Some(&Some(ExpectedGeneration::Known(7)))
        );
    }

    /// Several deletes queued on one deleter go to the backend one at a
    /// time: the condition is carried per request, and a batch would carry
    /// none.
    #[tokio::test]
    async fn queued_deletes_are_flushed_one_at_a_time() {
        let (operator, versioned, _tmp_dir) = staged_fs();
        under_7(operator.write("pk/pub/a.txt", b"a".to_vec()))
            .await
            .unwrap();
        under_7(operator.write("pk/pub/b.txt", b"b".to_vec()))
            .await
            .unwrap();

        let accessor = operator.clone().into_inner();
        under_7(async {
            let (_, mut deleter) = accessor.delete().await.unwrap();
            deleter
                .delete("pk/pub/a.txt", OpDelete::new())
                .await
                .unwrap();
            deleter
                .delete("pk/pub/b.txt", OpDelete::new())
                .await
                .unwrap();
            deleter.close().await.unwrap();
        })
        .await;

        assert!(!operator.exists("pk/pub/a.txt").await.unwrap());
        assert!(!operator.exists("pk/pub/b.txt").await.unwrap());
        assert_eq!(versioned.seen.lock().unwrap().len(), 4);
        assert!(!versioned.batched.load(Ordering::SeqCst));
    }

    /// A delete the backend refused is not kept by the backend's deleter and
    /// resent, unconditionally and in a batch, with the next delete.
    #[tokio::test]
    async fn refused_delete_is_not_resent_with_the_next() {
        let (operator, versioned, _tmp_dir) = staged_fs();
        under_7(operator.write("pk/pub/a.txt", b"a".to_vec()))
            .await
            .unwrap();
        under_7(operator.write("pk/pub/b.txt", b"b".to_vec()))
            .await
            .unwrap();

        let accessor = operator.clone().into_inner();
        under_7(async {
            let (_, mut deleter) = accessor.delete().await.unwrap();
            versioned.refuse_deletes.store(true, Ordering::SeqCst);
            let refused = deleter
                .delete("pk/pub/a.txt", OpDelete::new())
                .await
                .expect_err("the backend refused the delete");
            assert!(matches!(
                FileIoError::from(refused),
                FileIoError::PublishConflict
            ));
            versioned.refuse_deletes.store(false, Ordering::SeqCst);
            deleter
                .delete("pk/pub/b.txt", OpDelete::new())
                .await
                .unwrap();
            deleter.close().await.unwrap();
        })
        .await;

        assert!(operator.exists("pk/pub/a.txt").await.unwrap());
        assert!(!operator.exists("pk/pub/b.txt").await.unwrap());
        assert!(!versioned.batched.load(Ordering::SeqCst));
        assert_eq!(versioned.seen.lock().unwrap().len(), 4);
    }

    /// A publish the backend refuses on its condition is a conflict, lands
    /// nothing, and leaves no staging object.
    #[tokio::test]
    async fn refused_publish_is_a_conflict_and_leaves_nothing_behind() {
        let (operator, versioned, _tmp_dir) = staged_fs();
        let path = "pk/pub/a.txt";
        under_7(operator.write(path, b"kept".to_vec()))
            .await
            .unwrap();

        versioned.refuse_copies.store(true, Ordering::SeqCst);
        let refused = under_7(operator.write(path, b"refused".to_vec()))
            .await
            .expect_err("the backend refused the publish");
        assert!(matches!(
            FileIoError::from(refused),
            FileIoError::PublishConflict
        ));
        assert_eq!(operator.read(path).await.unwrap().to_vec(), b"kept");
        assert_eq!(staging_objects(&operator).await, 0);
    }

    #[tokio::test]
    async fn generation_is_read_from_the_live_object() {
        let path = "pk/pub/a.txt";
        let (backend, _tmp_dir) = plain_fs();
        let plain = backend.clone().into_inner();
        let versioned = backend
            .layer(Versioned {
                generation: "7",
                ..Versioned::default()
            })
            .into_inner();
        assert_eq!(
            live_generation(&versioned, path).await.unwrap(),
            Some(ExpectedGeneration::Absent)
        );

        Operator::from_inner(plain.clone())
            .write(path, b"x".to_vec())
            .await
            .unwrap();
        assert_eq!(
            live_generation(&versioned, path).await.unwrap(),
            Some(ExpectedGeneration::Known(7))
        );
        // The filesystem backend reports no generation.
        assert_eq!(live_generation(&plain, path).await.unwrap(), None);
    }

    /// The whole stack over a staged publish: the finalization reads the
    /// generation and a locked write and delete run under it, as over any
    /// backend, leaving no staging object.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn finalization_runs_over_a_staged_publish() {
        let db = SqlDb::test().await;
        let (backend, versioned, _tmp_dir) = staged_fs();
        let operator = test_operator_over(&db, backend.clone());
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey, StoragePath::new("/pub/a.txt").unwrap());

        operator
            .write(entry_path.as_str(), b"published".to_vec())
            .await
            .unwrap();
        assert_eq!(
            operator.read(entry_path.as_str()).await.unwrap().to_vec(),
            b"published"
        );
        let entry = EntryRepository::get_by_path(&entry_path, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(entry.content_length, 9);
        assert_eq!(staging_objects(&backend).await, 0);

        operator.delete(entry_path.as_str()).await.unwrap();
        assert!(!operator.exists(entry_path.as_str()).await.unwrap());
        assert!(matches!(
            EntryRepository::get_by_path(&entry_path, &mut db.pool().into()).await,
            Err(sqlx::Error::RowNotFound)
        ));
        assert_eq!(
            *versioned.seen.lock().unwrap(),
            vec![
                Some(ExpectedGeneration::Absent),
                Some(ExpectedGeneration::Known(7))
            ],
            "the publish ran under no object, the delete under the live one"
        );
    }

    /// End every other connection to the test database: the finalization's
    /// transaction among them.
    async fn kill_other_connections(db: &SqlDb) {
        sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = current_database() AND pid <> pg_backend_pid()",
        )
        .execute(db.pool())
        .await
        .unwrap();
    }

    /// The race the generation read guards against: the finalization's
    /// transaction dies while the generation lookup is pending, the lock
    /// passes to someone who writes, and the lookup returns their generation.
    /// A publish under it would replace their write and pass the condition.
    /// The finalization must find its transaction gone before publishing.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn write_whose_transaction_died_during_the_generation_read_is_refused() {
        let db = SqlDb::test().await;
        let (backend, versioned, _tmp_dir) = staged_fs();
        let operator = test_operator_over(&db, backend);
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey, StoragePath::new("/pub/a.txt").unwrap());

        let release = versioned.stall_next_stat();
        let write = tokio::spawn({
            let (operator, entry_path) = (operator.clone(), entry_path.clone());
            async move { operator.write(entry_path.as_str(), b"late".to_vec()).await }
        });
        versioned.until_stat_stalled().await;
        kill_other_connections(&db).await;
        release.send(()).unwrap();

        write
            .await
            .unwrap()
            .expect_err("the write must be refused once its transaction is gone");
        assert!(
            versioned.seen.lock().unwrap().is_empty(),
            "nothing may be published under a generation read after the transaction died"
        );
        assert!(!operator.exists(entry_path.as_str()).await.unwrap());
        assert!(matches!(
            EntryRepository::get_by_path(&entry_path, &mut db.pool().into()).await,
            Err(sqlx::Error::RowNotFound)
        ));
    }

    /// The same ordering on the delete path: the blob removal's transaction
    /// dies during the generation lookup. The blob must be left alone.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn blob_removal_whose_transaction_died_during_the_generation_read_is_refused() {
        let db = SqlDb::test().await;
        let (backend, versioned, _tmp_dir) = staged_fs();
        let operator = test_operator_over(&db, backend.clone());
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey, StoragePath::new("/pub/a.txt").unwrap());
        operator
            .write(entry_path.as_str(), b"kept".to_vec())
            .await
            .unwrap();

        let release = versioned.stall_next_stat();
        let delete = tokio::spawn({
            let (operator, entry_path) = (operator.clone(), entry_path.clone());
            async move { operator.delete(entry_path.as_str()).await }
        });
        versioned.until_stat_stalled().await;
        kill_other_connections(&db).await;
        release.send(()).unwrap();

        delete
            .await
            .unwrap()
            .expect_err("the removal must be refused once its transaction is gone");
        assert_eq!(
            versioned.seen.lock().unwrap().len(),
            1,
            "only the publish was sent; no delete under a stale generation"
        );
        assert!(backend.exists(entry_path.as_str()).await.unwrap());
    }

    #[test]
    fn condition_value_follows_the_expectation() {
        assert_eq!(ExpectedGeneration::Absent.if_generation_match(), 0);
        assert_eq!(ExpectedGeneration::Known(7).if_generation_match(), 7);
        assert_eq!(expected_generation(), None);
    }

    #[tokio::test]
    async fn expected_generation_reaches_the_request_only_while_it_runs() {
        under_expected_generation(ExpectedGeneration::Known(3), async {
            assert_eq!(expected_generation(), Some(ExpectedGeneration::Known(3)));
        })
        .await;
        assert_eq!(expected_generation(), None);
    }

    #[test]
    fn publish_conflict_is_recognised() {
        let conflict = publish_conflict(
            "pk/pub/a.txt",
            opendal::Error::new(ErrorKind::ConditionNotMatch, "412"),
        );
        assert!(matches!(
            LayerDomainError::of(&conflict),
            Some(LayerDomainError::PublishConflict)
        ));
        assert_eq!(conflict.kind(), ErrorKind::ConditionNotMatch);
    }
}
