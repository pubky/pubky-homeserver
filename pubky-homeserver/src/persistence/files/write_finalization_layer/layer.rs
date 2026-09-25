use std::{future::Future, sync::Arc};

use crate::persistence::files::{events::EventsService, layer_domain_error::LayerDomainError};
use crate::persistence::sql::{entry::EntryRepository, SqlDb, UnifiedExecutor};
use crate::services::user_service::UserService;
use crate::shared::webdav::EntryPath;
use opendal::raw::*;
use opendal::Result;
use tracing::Instrument;

use super::{WriteFinalizationDeleter, WriteFinalizationWriter};

/// Keeps file entries, events, and user quotas in sync with blob writes and deletes.
///
/// The related database changes are committed together in one transaction.
/// App-facing operators also reject path collisions; admin operators allow them
/// so they can repair legacy data.
///
/// Blob storage cannot be part of the database transaction. The ways the two
/// can still diverge are described in the [`files`](crate::persistence::files)
/// module docs.
#[derive(Clone)]
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
/// logs still carries the request's context.
pub(super) async fn spawn_finalization<T: Send + 'static>(
    finalization: impl Future<Output = Result<T>> + Send + 'static,
) -> Result<T> {
    match tokio::spawn(finalization.in_current_span()).await {
        Ok(result) => result,
        Err(error) => Err(opendal::Error::new(
            opendal::ErrorKind::Unexpected,
            "Finalization task did not complete",
        )
        .set_source(error)),
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

// Finalization runs on spawned tasks that own the backend writer or deleter,
// hence the `'static` bounds.
impl<A: Access> Layer<A> for WriteFinalizationLayer
where
    A::Writer: 'static,
    A::Deleter: 'static,
{
    type LayeredAccess = WriteFinalizationAccessor<A>;

    fn layer(&self, inner: A) -> Self::LayeredAccess {
        WriteFinalizationAccessor {
            inner: Arc::new(inner),
            finalizer: self.finalizer.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WriteFinalizationAccessor<A: Access> {
    inner: Arc<A>,
    finalizer: Arc<Finalizer>,
}

impl<A: Access> LayeredAccess for WriteFinalizationAccessor<A>
where
    A::Writer: 'static,
    A::Deleter: 'static,
{
    type Inner = A;
    type Reader = A::Reader;
    type Writer = WriteFinalizationWriter<A::Writer>;
    type Lister = A::Lister;
    type Deleter = WriteFinalizationDeleter<A::Deleter>;
    type Copier = A::Copier;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    async fn create_dir(&self, path: &str, args: OpCreateDir) -> Result<RpCreateDir> {
        let entry_path = EntryPath::parse_opendal(path)?;
        self.finalizer.collision_preflight(&entry_path).await?;
        self.inner.create_dir(entry_path.as_str(), args).await
    }

    async fn read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::Reader)> {
        self.inner.read(path, args).await
    }

    async fn write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::Writer)> {
        let entry_path = EntryPath::parse_opendal(path)?;
        self.finalizer.collision_preflight(&entry_path).await?;
        let (rp, writer) = self.inner.write(entry_path.as_str(), args).await?;
        Ok((
            rp,
            WriteFinalizationWriter::new(writer, self.finalizer.clone(), entry_path),
        ))
    }

    async fn copy(
        &self,
        from: &str,
        to: &str,
        args: OpCopy,
        opts: OpCopier,
    ) -> Result<(RpCopy, Self::Copier)> {
        let from = EntryPath::parse_opendal(from)?;
        let to = EntryPath::parse_opendal(to)?;
        self.finalizer.collision_preflight(&to).await?;
        self.inner
            .copy(from.as_str(), to.as_str(), args, opts)
            .await
    }

    async fn rename(&self, from: &str, to: &str, args: OpRename) -> Result<RpRename> {
        let from = EntryPath::parse_opendal(from)?;
        let to = EntryPath::parse_opendal(to)?;
        self.finalizer.collision_preflight(&to).await?;
        self.inner.rename(from.as_str(), to.as_str(), args).await
    }

    async fn stat(&self, path: &str, args: OpStat) -> Result<RpStat> {
        self.inner.stat(path, args).await
    }

    async fn delete(&self) -> Result<(RpDelete, Self::Deleter)> {
        let (rp, deleter) = self.inner.delete().await?;
        Ok((
            rp,
            WriteFinalizationDeleter::new(deleter, self.finalizer.clone()),
        ))
    }

    async fn list(&self, path: &str, args: OpList) -> Result<(RpList, Self::Lister)> {
        self.inner.list(path, args).await
    }

    async fn presign(&self, path: &str, args: OpPresign) -> Result<RpPresign> {
        let entry_path = EntryPath::parse_opendal(path)?;
        self.inner.presign(entry_path.as_str(), args).await
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
pub(super) mod test_support {
    use std::future::Future;
    use std::time::Duration;

    use pubky_common::crypto::Keypair;
    use tempfile::TempDir;

    use crate::persistence::files::{
        events::{EventEntity, EventRepository, EventVisibility},
        opendal::opendal_test_operators::{get_fs_operator, get_memory_operator},
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

    fn test_operator_over(db: &SqlDb, backend: opendal::Operator) -> opendal::Operator {
        backend.layer(WriteFinalizationLayer::new(
            UserService::new(db.clone()),
            db.clone(),
            EventsService::new(db.clone(), 100),
            None,
            true,
        ))
    }

    pub(in super::super) fn test_user_service(db: &SqlDb) -> UserService {
        UserService::new(db.clone())
    }

    pub(in super::super) async fn create_user(db: &SqlDb) -> pubky_common::crypto::PublicKey {
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
    use crate::persistence::sql::{entry::EntryRepository, SqlDb};
    use crate::services::user_service::FILE_METADATA_SIZE;
    use crate::shared::webdav::{EntryPath, StoragePath};

    use super::test_support::{all_events, create_user, test_operator, user_usage};

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
