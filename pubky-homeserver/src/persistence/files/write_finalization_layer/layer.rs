use std::{future::Future, sync::Arc};

use crate::persistence::files::{
    events::EventsService,
    layer_domain_error::LayerDomainError,
    staged_publish_layer::{live_generation, under_expected_generation, ExpectedGeneration},
    write_check::{checked_copier, CheckedWriter, WriteCheck},
};
use crate::persistence::sql::{entry::EntryRepository, SqlDb, UnifiedExecutor};
use crate::services::user_service::UserService;
use crate::shared::webdav::EntryPath;
use opendal::raw::*;
use opendal::{Capability, OperationContext, Operator, Result};
use tracing::Instrument;

use super::{write_lock, WriteFinalizationDeleter, WriteFinalizationWriter};

/// Keeps file entries, events, and user quotas in sync with blob writes and deletes.
///
/// The related database changes are committed together in one transaction.
/// App-facing operators also reject path collisions; admin operators allow them
/// so they can repair legacy data. A write or copy is checked for a collision
/// before its first byte, its close, or the copy reaches the layers
/// underneath, see [`write_check`](crate::persistence::files::write_check).
///
/// Blob storage cannot be part of the database transaction. The ways the two
/// can still diverge are described in the [`files`](crate::persistence::files)
/// module docs.
#[derive(Debug, Clone)]
pub struct WriteFinalizationLayer {
    finalizer: Arc<Finalizer>,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum CollisionPolicy {
    Enforce,
    AllowLegacyAdminRepair,
}

impl CollisionPolicy {
    fn from_enforcement(enforce: bool) -> Self {
        if enforce {
            Self::Enforce
        } else {
            Self::AllowLegacyAdminRepair
        }
    }

    pub(super) fn enforces_collisions(self) -> bool {
        matches!(self, Self::Enforce)
    }
}

#[derive(Debug)]
pub(super) struct Finalizer {
    pub(super) user_service: UserService,
    pub(super) sql_db: SqlDb,
    pub(super) events_service: EventsService,
    pub(super) default_storage_mb: Option<u64>,
    pub(super) collision_policy: CollisionPolicy,
}

impl WriteFinalizationLayer {
    pub fn new(
        user_service: UserService,
        sql_db: SqlDb,
        events_service: EventsService,
        default_storage_mb: Option<u64>,
        enforce_path_collisions: bool,
    ) -> Self {
        Self {
            finalizer: Arc::new(Finalizer::new(
                user_service,
                sql_db,
                events_service,
                default_storage_mb,
                CollisionPolicy::from_enforcement(enforce_path_collisions),
            )),
        }
    }
}

pub(super) fn unexpected(
    context: impl std::fmt::Display,
    error: impl std::fmt::Display,
) -> opendal::Error {
    opendal::Error::new(
        opendal::ErrorKind::Unexpected,
        format!("{context}: {error}"),
    )
}

/// The error for using a writer or deleter after it was closed or aborted.
pub(super) fn already_closed(subject: &str) -> opendal::Error {
    opendal::Error::new(
        opendal::ErrorKind::Unexpected,
        format!("{subject} was already closed or aborted"),
    )
}

/// Run a finalization step to completion on its own task, so a caller dropped
/// mid-step (a client disconnect) cannot leave the entry row and the blob
/// disagreeing. Why that matters is described in the
/// [`files`](crate::persistence::files) module docs.
///
/// The task runs in the caller's tracing span, so whatever the finalization
/// logs still carries the request's context. The lock the caller runs under is
/// carried over the same way, see [`write_lock`].
pub(super) async fn spawn_finalization<T: Send + 'static>(
    finalization: impl Future<Output = Result<T>> + Send + 'static,
) -> Result<T> {
    match tokio::spawn(write_lock::carry(finalization).in_current_span()).await {
        Ok(result) => result,
        Err(error) => Err(opendal::Error::new(
            opendal::ErrorKind::Unexpected,
            "Finalization task did not complete",
        )
        .set_source(error)),
    }
}

/// The generation the object at `entry_path` has now, for a publish or
/// delete under it, read inside the finalization transaction with the
/// transaction proven alive after the read.
///
/// The user row the transaction holds keeps every other change to the path
/// out until the transaction ends. A generation read while the transaction
/// lives therefore predates any change a later holder makes, and a publish
/// under it cannot replace one. The proof is a round trip on the
/// transaction's own connection, which fails if the transaction has died
/// meanwhile: without it, a lookup still pending when the transaction died
/// could return the generation of a later holder's write and let the
/// publish replace it. `None` on a backend without generations.
pub(super) async fn generation_under_lock(
    backend: &Operator,
    entry_path: &EntryPath,
    executor: &mut UnifiedExecutor<'_>,
) -> Result<Option<ExpectedGeneration>> {
    let generation = live_generation(backend, entry_path.as_str()).await?;
    let lost = |error| {
        unexpected(
            format!("Finalization transaction of {entry_path} lost after reading the generation"),
            error,
        )
    };
    let con = executor.get_con().await.map_err(lost)?;
    sqlx::query("SELECT 1").execute(con).await.map_err(lost)?;
    Ok(generation)
}

/// Run `request`, a publish or delete, under `generation` if there is one.
pub(super) async fn under_generation<T>(
    generation: Option<ExpectedGeneration>,
    request: impl Future<Output = T>,
) -> T {
    match generation {
        Some(generation) => under_expected_generation(generation, request).await,
        None => request.await,
    }
}

fn path_collision_error(entry_path: &EntryPath) -> opendal::Error {
    opendal::Error::new(
        opendal::ErrorKind::AlreadyExists,
        format!("File/folder path collision for {entry_path}"),
    )
    .set_source(LayerDomainError::PathCollision)
}

pub(super) async fn check_no_path_collision(
    entry_path: &EntryPath,
    executor: &mut UnifiedExecutor<'_>,
) -> Result<()> {
    let has_collision = EntryRepository::has_file_folder_collision(entry_path, executor)
        .await
        .map_err(|error| {
            unexpected(
                format!("Failed to check path collision for {entry_path}"),
                error,
            )
        })?;

    if has_collision {
        return Err(path_collision_error(entry_path));
    }

    Ok(())
}

impl Layer for WriteFinalizationLayer {
    fn apply_service(&self, inner: Servicer) -> Servicer {
        Arc::new(WriteFinalizationService {
            inner,
            finalizer: self.finalizer.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WriteFinalizationService {
    inner: Servicer,
    finalizer: Arc<Finalizer>,
}

impl WriteFinalizationService {
    /// The backend underneath, for a request made in `ctx`: the finalization
    /// reads the generation of the object it changes from it.
    fn backend(&self, ctx: &OperationContext) -> Operator {
        Operator::from_parts(ctx.clone(), self.inner.clone())
    }

    fn collision_check(&self, entry_path: EntryPath) -> CollisionCheck {
        CollisionCheck {
            finalizer: self.finalizer.clone(),
            entry_path,
        }
    }
}

/// Rejects a write or copy to `entry_path` early if it would collide with a
/// file or folder. The finalization checks again under the lock.
pub(crate) struct CollisionCheck {
    finalizer: Arc<Finalizer>,
    entry_path: EntryPath,
}

impl WriteCheck for CollisionCheck {
    async fn check(&self) -> Result<()> {
        self.finalizer.collision_preflight(&self.entry_path).await
    }
}

impl Service for WriteFinalizationService {
    type Reader = oio::Reader;
    type Writer = CheckedWriter<WriteFinalizationWriter<oio::Writer>, CollisionCheck>;
    type Lister = oio::Lister;
    type Deleter = WriteFinalizationDeleter<oio::Deleter>;
    type Copier = oio::OneShotCopier;
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
        let entry_path = EntryPath::parse_opendal(path)?;
        self.finalizer.collision_preflight(&entry_path).await?;
        self.inner.create_dir(ctx, entry_path.as_str(), args).await
    }

    fn read(&self, ctx: &OperationContext, path: &str, args: OpRead) -> Result<Self::Reader> {
        self.inner.read(ctx, path, args)
    }

    fn write(&self, ctx: &OperationContext, path: &str, args: OpWrite) -> Result<Self::Writer> {
        let entry_path = EntryPath::parse_opendal(path)?;
        let writer = self.inner.write(ctx, entry_path.as_str(), args)?;
        let writer = WriteFinalizationWriter::new(
            writer,
            self.backend(ctx),
            self.finalizer.clone(),
            entry_path.clone(),
        );
        Ok(CheckedWriter::new(writer, self.collision_check(entry_path)))
    }

    fn copy(
        &self,
        ctx: &OperationContext,
        from: &str,
        to: &str,
        args: OpCopy,
    ) -> Result<Self::Copier> {
        let from = EntryPath::parse_opendal(from)?;
        let to = EntryPath::parse_opendal(to)?;
        let check = self.collision_check(to.clone());
        Ok(checked_copier(
            check,
            &self.inner,
            ctx,
            from.as_str(),
            to.as_str(),
            args,
        ))
    }

    async fn rename(
        &self,
        ctx: &OperationContext,
        from: &str,
        to: &str,
        args: OpRename,
    ) -> Result<RpRename> {
        let from = EntryPath::parse_opendal(from)?;
        let to = EntryPath::parse_opendal(to)?;
        self.finalizer.collision_preflight(&to).await?;
        self.inner
            .rename(ctx, from.as_str(), to.as_str(), args)
            .await
    }

    async fn stat(&self, ctx: &OperationContext, path: &str, args: OpStat) -> Result<RpStat> {
        self.inner.stat(ctx, path, args).await
    }

    fn delete(&self, ctx: &OperationContext) -> Result<Self::Deleter> {
        Ok(WriteFinalizationDeleter::new(
            self.inner.delete(ctx)?,
            self.backend(ctx),
            self.finalizer.clone(),
        ))
    }

    fn list(&self, ctx: &OperationContext, path: &str, args: OpList) -> Result<Self::Lister> {
        self.inner.list(ctx, path, args)
    }

    async fn presign(
        &self,
        ctx: &OperationContext,
        path: &str,
        args: OpPresign,
    ) -> Result<RpPresign> {
        let entry_path = EntryPath::parse_opendal(path)?;
        self.inner.presign(ctx, entry_path.as_str(), args).await
    }
}

impl Finalizer {
    fn new(
        user_service: UserService,
        sql_db: SqlDb,
        events_service: EventsService,
        default_storage_mb: Option<u64>,
        collision_policy: CollisionPolicy,
    ) -> Self {
        Self {
            user_service,
            sql_db,
            events_service,
            default_storage_mb,
            collision_policy,
        }
    }

    async fn collision_preflight(&self, entry_path: &EntryPath) -> Result<()> {
        if !self.collision_policy.enforces_collisions() {
            return Ok(());
        }

        check_no_path_collision(entry_path, &mut self.sql_db.pool().into()).await
    }

    pub(super) fn notify_event(&self) {
        let events_service = self.events_service.clone();
        drop(tokio::spawn(async move {
            events_service.notify_event().await;
        }));
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::future::Future;
    use std::time::Duration;

    use pubky_common::crypto::Keypair;
    use tempfile::TempDir;

    use crate::persistence::files::{
        events::{EventEntity, EventRepository, EventVisibility},
        test_support::{get_fs_operator, get_memory_operator},
    };
    use crate::persistence::sql::SqlDb;

    use super::*;

    pub(in super::super) fn test_finalizer(db: &SqlDb) -> Finalizer {
        Finalizer::new(
            UserService::new(db.clone()),
            db.clone(),
            EventsService::new(db.clone(), 100),
            None,
            CollisionPolicy::Enforce,
        )
    }

    pub(in super::super) fn test_operator(db: &SqlDb) -> opendal::Operator {
        test_operator_over(db, get_memory_operator())
    }

    /// Like [`test_operator`], on the filesystem backend so staged uploads
    /// can be observed with [`staged_count`] on the returned directory.
    pub(in super::super) fn test_fs_operator(db: &SqlDb) -> (opendal::Operator, TempDir) {
        let (backend, tmp_dir) = get_fs_operator();
        (test_operator_over(db, backend), tmp_dir)
    }

    /// A backend without generations, for a finalization under test.
    pub(in super::super) fn memory_backend() -> opendal::Operator {
        get_memory_operator()
    }

    /// Like [`test_operator`], with the backend it writes to, for a
    /// finalization under test that must find the files the operator wrote.
    pub(in super::super) fn test_operator_with_backend(
        db: &SqlDb,
    ) -> (opendal::Operator, opendal::Operator) {
        let backend = get_memory_operator();
        (test_operator_over(db, backend.clone()), backend)
    }

    pub(crate) fn test_operator_over(db: &SqlDb, backend: opendal::Operator) -> opendal::Operator {
        backend.layer(WriteFinalizationLayer::new(
            UserService::new(db.clone()),
            db.clone(),
            EventsService::new(db.clone(), 100),
            None,
            true,
        ))
    }

    /// The error of a backend that throttled a mutation, as an object store
    /// does for a second mutation of one object within a second.
    pub(in super::super) fn backend_throttle() -> opendal::Error {
        opendal::Error::new(
            opendal::ErrorKind::RateLimited,
            "object mutation rate limit exceeded",
        )
        .set_temporary()
    }

    pub(in super::super) fn test_user_service(db: &SqlDb) -> UserService {
        UserService::new(db.clone())
    }

    pub(crate) async fn create_user(db: &SqlDb) -> pubky_common::crypto::PublicKey {
        let pubkey = Keypair::random().public_key();
        let user_service = test_user_service(db);
        user_service.create(&pubkey).await.unwrap();
        pubkey
    }

    pub(in super::super) async fn user_usage(
        db: &SqlDb,
        pubkey: &pubky_common::crypto::PublicKey,
    ) -> u64 {
        let user_service = test_user_service(db);
        user_service.get(pubkey).await.unwrap().used_bytes
    }

    /// Install a plpgsql trigger called `name` that runs `body` before every
    /// insert into the events table. `body` may raise to fail the insert.
    pub(in super::super) async fn install_events_insert_trigger(
        db: &SqlDb,
        name: &str,
        body: &str,
    ) {
        let function = format!(
            "CREATE FUNCTION {name}() RETURNS trigger AS $$ \
             BEGIN {body} RETURN NEW; END; \
             $$ LANGUAGE plpgsql"
        );
        sqlx::query(&function).execute(db.pool()).await.unwrap();
        let trigger = format!(
            "CREATE TRIGGER {name}_trigger BEFORE INSERT ON events \
             FOR EACH ROW EXECUTE FUNCTION {name}()"
        );
        sqlx::query(&trigger).execute(db.pool()).await.unwrap();
    }

    /// Poll until `condition` holds, for a few seconds at most.
    pub(in super::super) async fn wait_until<F, Fut>(condition: F, message: &str)
    where
        F: Fn() -> Fut,
        Fut: Future<Output = bool>,
    {
        for _ in 0..500 {
            if condition().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{message}");
    }

    /// Hold every event insert for a second, so a caller can be dropped while
    /// its finalization transaction is open.
    pub(in super::super) async fn install_slow_event_insert(db: &SqlDb) {
        install_events_insert_trigger(db, "slow_event_insert", "PERFORM pg_sleep(1);").await;
    }

    /// Poll until an insert held by [`install_slow_event_insert`] is running.
    pub(in super::super) async fn wait_for_slow_event_insert(db: &SqlDb) {
        wait_for_active_query(db, "%INSERT INTO \"events\"%").await;
    }

    /// Poll until a statement matching `pattern` is executing on this database.
    async fn wait_for_active_query(db: &SqlDb, pattern: &str) {
        wait_until(
            || async {
                let (active,): (i64,) = sqlx::query_as(
                    "SELECT count(*) FROM pg_stat_activity \
                     WHERE datname = current_database() AND state = 'active' AND query LIKE $1",
                )
                .bind(pattern)
                .fetch_one(db.pool())
                .await
                .unwrap();
                active > 0
            },
            &format!("no active query matching {pattern:?}"),
        )
        .await;
    }

    /// Uploads currently staged by a [`test_fs_operator`] in `tmp_dir`.
    pub(in super::super) fn staged_count(tmp_dir: &TempDir) -> usize {
        std::fs::read_dir(tmp_dir.path().join("files-tmp")).map_or(0, Iterator::count)
    }

    pub(in super::super) async fn wait_for_staged_count(
        tmp_dir: &TempDir,
        expected: usize,
        message: &str,
    ) {
        wait_until(|| async { staged_count(tmp_dir) == expected }, message).await;
    }

    pub(in super::super) async fn all_events(db: &SqlDb) -> Vec<EventEntity> {
        EventRepository::get_by_cursor(
            None,
            Some(9999),
            EventVisibility::All,
            &mut db.pool().into(),
        )
        .await
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::persistence::files::events::EventType;
    use crate::persistence::files::staged_publish_layer::StagedPublishLayer;
    use crate::persistence::files::test_support::{get_fs_operator, Versioned};
    use crate::persistence::sql::{entry::EntryRepository, SqlDb};
    use crate::services::user_service::FILE_METADATA_SIZE;
    use crate::shared::webdav::{EntryPath, StoragePath};
    use tempfile::TempDir;

    use super::test_support::{
        all_events, create_user, test_operator, test_operator_over, user_usage,
    };

    /// The finalization over a staged publish on a versioned backend, which
    /// is returned to steer it, with the backend's directory.
    fn staged_operator(db: &SqlDb) -> (opendal::Operator, opendal::Operator, Versioned, TempDir) {
        let (fs, tmp_dir) = get_fs_operator();
        let versioned = Versioned::new("7");
        let backend = fs.layer(versioned.clone()).layer(StagedPublishLayer);
        (
            test_operator_over(db, backend.clone()),
            backend,
            versioned,
            tmp_dir,
        )
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
        let (operator, _backend, versioned, _tmp_dir) = staged_operator(&db);
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
        let (operator, backend, versioned, _tmp_dir) = staged_operator(&db);
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

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn write_overwrite_and_delete_finalize_all_database_effects() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey.clone(), StoragePath::new("/test.txt").unwrap());

        operator
            .write(entry_path.as_str(), vec![1; 10])
            .await
            .unwrap();
        let entry = EntryRepository::get_by_path(&entry_path, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(entry.content_length, 10);
        assert_eq!(user_usage(&db, &pubkey).await, 10 + FILE_METADATA_SIZE);

        operator
            .write(entry_path.as_str(), vec![2; 20])
            .await
            .unwrap();
        let entry = EntryRepository::get_by_path(&entry_path, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(entry.content_length, 20);
        assert_eq!(user_usage(&db, &pubkey).await, 20 + FILE_METADATA_SIZE);

        operator.delete(entry_path.as_str()).await.unwrap();
        EntryRepository::get_by_path(&entry_path, &mut db.pool().into())
            .await
            .expect_err("entry should be deleted");
        assert_eq!(user_usage(&db, &pubkey).await, 0);

        let events = all_events(&db).await;
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0].event_type, EventType::Put { .. }));
        assert!(matches!(events[1].event_type, EventType::Put { .. }));
        assert_eq!(events[2].event_type, EventType::Delete);
    }
}
