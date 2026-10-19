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
//! The finalization hands the generation down as a task-local, set around
//! the publish or delete, see [`under_expected_generation`]. This layer puts
//! it on the copy or delete as opendal's `if_version_match` condition, which
//! the GCS service sends as `ifGenerationMatch`. The layer is generic: any
//! backend that supports version conditions on copy and delete can run under
//! it.

use std::sync::Arc;

use opendal::options::DeleteOptions;
use opendal::raw::oio;
use opendal::raw::{
    Layer, OpCopy, OpCreateDir, OpDelete, OpList, OpPresign, OpRead, OpRename, OpStat, OpWrite,
    RpCreateDir, RpPresign, RpRename, RpStat, Service, ServiceInfo, Servicer,
};
use opendal::{Capability, ErrorKind, Metadata, OperationContext, Operator, Result};

use super::layer_domain_error::LayerDomainError;

/// Where uploads are staged. Never a user path: a user path begins with a
/// public key, which cannot start with a dot.
pub(crate) const STAGING_PREFIX: &str = ".staging/";

/// What a publish or delete must find at the real path to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExpectedGeneration {
    /// No object: the request must create it.
    Absent,
    /// The object at this generation.
    Known(u64),
}

/// The generation GCS reads as "no live object". A request that must create
/// its object carries it as `if_version_match`, because opendal cannot send
/// `if_not_exists` on a GCS copy.
const NO_OBJECT_GENERATION: u64 = 0;

impl ExpectedGeneration {
    /// The version the request is conditional on, as opendal's
    /// `if_version_match` takes it.
    pub(crate) fn version_condition(self) -> String {
        match self {
            Self::Absent => NO_OBJECT_GENERATION,
            Self::Known(generation) => generation,
        }
        .to_string()
    }

    /// The expectation a request's `if_version_match` carries, the reverse
    /// of [`Self::version_condition`].
    #[cfg(test)]
    pub(crate) fn from_version_condition(condition: &str) -> Self {
        match condition.parse().expect("a generation is a number") {
            NO_OBJECT_GENERATION => Self::Absent,
            generation => Self::Known(generation),
        }
    }
}

tokio::task_local! {
    static EXPECTED_GENERATION: ExpectedGeneration;
}

/// The generation the current task's publish or delete must find, if it
/// runs under one.
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
/// reports no generation: a publish or delete under `None` is refused by
/// this layer, see [`StagedWriter`].
pub(crate) async fn live_generation(
    backend: &Operator,
    path: &str,
) -> Result<Option<ExpectedGeneration>> {
    match backend.stat(path).await {
        Ok(metadata) => metadata
            .version()
            .map(|version| parse_generation(path, version))
            .transpose(),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Some(ExpectedGeneration::Absent)),
        Err(error) => Err(error),
    }
}

fn parse_generation(path: &str, version: &str) -> Result<ExpectedGeneration> {
    let generation = version.parse().map_err(|_| {
        opendal::Error::new(
            ErrorKind::Unexpected,
            format!("The backend reports generation {version:?} for {path}, not a number"),
        )
    })?;
    Ok(ExpectedGeneration::Known(generation))
}

#[derive(Debug, Clone, Copy)]
pub struct StagedPublishLayer;

impl Layer for StagedPublishLayer {
    fn apply_service(&self, inner: Servicer) -> Servicer {
        Arc::new(StagedPublishService { inner })
    }
}

#[derive(Debug)]
pub struct StagedPublishService {
    inner: Servicer,
}

impl StagedPublishService {
    /// The backend underneath, for a request made in `ctx`.
    fn backend(&self, ctx: &OperationContext) -> Operator {
        Operator::from_parts(ctx.clone(), self.inner.clone())
    }
}

impl Service for StagedPublishService {
    type Reader = oio::Reader;
    type Writer = StagedWriter;
    type Lister = oio::Lister;
    type Deleter = ConditionalDeleter;
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
        self.inner.read(ctx, path, args)
    }

    fn write(&self, ctx: &OperationContext, path: &str, args: OpWrite) -> Result<Self::Writer> {
        let staging = format!("{STAGING_PREFIX}{}", uuid::Uuid::new_v4());
        let writer = self.inner.write(ctx, &staging, args)?;
        Ok(StagedWriter {
            backend: self.backend(ctx),
            writer,
            staging,
            path: path.to_string(),
            upload: Upload::Open,
        })
    }

    fn delete(&self, ctx: &OperationContext) -> Result<Self::Deleter> {
        Ok(ConditionalDeleter {
            inner: self.inner.clone(),
            ctx: ctx.clone(),
        })
    }

    fn list(&self, ctx: &OperationContext, path: &str, args: OpList) -> Result<Self::Lister> {
        self.inner.list(ctx, path, args)
    }

    /// Refused: a copy would land on the real path unconditionally, past the
    /// generation condition, and create no entry. Files are published by
    /// writes only.
    fn copy(
        &self,
        _ctx: &OperationContext,
        _from: &str,
        _to: &str,
        _args: OpCopy,
    ) -> Result<Self::Copier> {
        Err(opendal::Error::new(
            ErrorKind::Unsupported,
            "Copy is not supported: files are published by writes only",
        ))
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

/// Where the staged upload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Upload {
    /// Still being written; the backend writer owns it.
    Open,
    /// Closed: the staging object exists, until the publish is over.
    Staged,
    /// Nothing left to do: published and removed, aborted, or closed
    /// without an answer, when the backend may still finish it and a late
    /// abort could cancel a completed upload.
    Done,
}

/// Writer that uploads to a staging object and publishes it on close, under
/// the generation the task provides.
pub struct StagedWriter {
    backend: Operator,
    writer: oio::Writer,
    staging: String,
    path: String,
    upload: Upload,
}

impl oio::Write for StagedWriter {
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

        // The generation is only available now: the finalization reads it
        // under the lock and sets it around the close. So a write without
        // one still costs a staged upload, which is removed below.
        let published = match expected_generation() {
            Some(expected) => {
                let published = self
                    .backend
                    .copy_with(&self.staging, &self.path)
                    .if_version_match(&expected.version_condition())
                    .await;
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

impl StagedWriter {
    /// Remove the staging object, if there is one. Best effort: a leftover
    /// is for the sweep, and must not fail the publish it follows. With no
    /// condition: the generation the task runs under is the real path's.
    async fn remove_staging(&mut self) {
        if self.upload != Upload::Staged {
            return;
        }
        self.upload = Upload::Done;
        if let Err(error) = self.backend.delete(&self.staging).await {
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
pub struct ConditionalDeleter {
    inner: Servicer,
    ctx: OperationContext,
}

impl oio::Delete for ConditionalDeleter {
    /// Sent at once rather than queued, on a backend deleter of its own: the
    /// condition belongs to this one path, and a backend deleter keeps a
    /// refused path to resend it with the next.
    async fn delete(&mut self, path: &str, args: OpDelete) -> Result<()> {
        let Some(expected) = expected_generation() else {
            return Err(no_generation(path));
        };
        let args = conditional_on(args, expected, &self.inner.capability())?;
        let mut deleter = self.inner.delete(&self.ctx)?;
        let deleted = match deleter.delete(path, args).await {
            Ok(()) => deleter.close().await,
            Err(error) => Err(error),
        };
        refused_as_conflict(deleted, path, expected)
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

/// `args` with the condition that the object is at `expected`.
fn conditional_on(
    args: OpDelete,
    expected: ExpectedGeneration,
    capability: &Capability,
) -> Result<OpDelete> {
    let options = DeleteOptions {
        version: args.version().map(str::to_string),
        recursive: args.recursive(),
        if_version_match: Some(expected.version_condition()),
        ..DeleteOptions::default()
    };
    OpDelete::from_options(capability, options)
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

/// Staging objects left behind on `operator`. The listing names the prefix
/// itself too.
#[cfg(test)]
pub(crate) async fn staging_objects(operator: &Operator) -> usize {
    operator
        .list(STAGING_PREFIX)
        .await
        .unwrap()
        .iter()
        .filter(|entry| entry.metadata().is_file())
        .count()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use opendal::raw::oio::Delete as _;
    use opendal::Operator;
    use tempfile::TempDir;

    use super::*;
    use crate::persistence::files::test_support::Versioned;
    use crate::persistence::files::write_finalization_layer::test_support::{
        create_user, test_operator_over,
    };
    use crate::persistence::files::FileIoError;
    use crate::persistence::sql::{entry::EntryRepository, SqlDb};
    use crate::shared::webdav::{EntryPath, StoragePath};

    /// The filesystem backend, which supports copy and abort as an object
    /// store does; the in-memory one supports neither.
    fn plain_fs() -> (Operator, TempDir) {
        let tmp_dir = tempfile::tempdir().unwrap();
        let root = tmp_dir.path().join("files");
        let atomic = tmp_dir.path().join("atomic");
        let builder = opendal::services::Fs::default()
            .root(root.to_str().unwrap())
            .atomic_write_dir(atomic.to_str().unwrap());
        (Operator::new(builder).unwrap(), tmp_dir)
    }

    /// The filesystem backend reporting generation 7 for every object, under
    /// the staged publish. The versioned backend is returned to steer it.
    fn staged_fs() -> (Operator, Versioned, TempDir) {
        let (backend, tmp_dir) = plain_fs();
        let versioned = Versioned::new("7");
        let operator = backend.layer(versioned.clone()).layer(StagedPublishLayer);
        (operator, versioned, tmp_dir)
    }

    /// Run `request` as the finalization would: under generation 7.
    async fn under_7<T>(request: impl std::future::Future<Output = T>) -> T {
        under_expected_generation(ExpectedGeneration::Known(7), request).await
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

    /// A copy is refused: it would land without the generation condition.
    #[tokio::test]
    async fn copy_is_refused() {
        let (operator, versioned, _tmp_dir) = staged_fs();
        under_7(operator.write("pk/pub/a.txt", b"a".to_vec()))
            .await
            .unwrap();

        let refused = under_7(operator.copy("pk/pub/a.txt", "pk/pub/b.txt"))
            .await
            .expect_err("a copy is refused");
        assert_eq!(refused.kind(), ErrorKind::Unsupported);
        assert!(!operator.exists("pk/pub/b.txt").await.unwrap());
        assert_eq!(
            versioned.seen.lock().unwrap().len(),
            1,
            "only the write's publish"
        );
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
    /// time, each with its own condition, never in a batch.
    #[tokio::test]
    async fn queued_deletes_are_flushed_one_at_a_time() {
        let (operator, versioned, _tmp_dir) = staged_fs();
        under_7(operator.write("pk/pub/a.txt", b"a".to_vec()))
            .await
            .unwrap();
        under_7(operator.write("pk/pub/b.txt", b"b".to_vec()))
            .await
            .unwrap();

        let (ctx, service) = operator.clone().into_parts();
        under_7(async {
            let mut deleter = service.delete(&ctx).unwrap();
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

        let (ctx, service) = operator.clone().into_parts();
        under_7(async {
            let mut deleter = service.delete(&ctx).unwrap();
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
        let (plain, _tmp_dir) = plain_fs();
        let versioned = plain.clone().layer(Versioned::new("7"));
        assert_eq!(
            live_generation(&versioned, path).await.unwrap(),
            Some(ExpectedGeneration::Absent)
        );

        plain.write(path, b"x".to_vec()).await.unwrap();
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

    #[test]
    fn condition_value_follows_the_expectation() {
        assert_eq!(ExpectedGeneration::Absent.version_condition(), "0");
        assert_eq!(ExpectedGeneration::Known(7).version_condition(), "7");
        for expected in [ExpectedGeneration::Absent, ExpectedGeneration::Known(7)] {
            assert_eq!(
                ExpectedGeneration::from_version_condition(&expected.version_condition()),
                expected
            );
        }
    }

    #[tokio::test]
    async fn a_generation_that_is_not_a_number_is_an_error() {
        let path = "pk/pub/a.txt";
        let (plain, _tmp_dir) = plain_fs();
        plain.write(path, b"x".to_vec()).await.unwrap();
        let versioned = plain.layer(Versioned::new("not-a-number"));

        let error = live_generation(&versioned, path).await.unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Unexpected);
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
