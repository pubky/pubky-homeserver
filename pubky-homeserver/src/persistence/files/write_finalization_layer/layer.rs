use std::sync::Arc;

use crate::persistence::files::{
    events::{EventType, EventsService},
    layer_domain_error::LayerDomainError,
    WritePreconditions,
};
use crate::persistence::sql::{entry::EntryRepository, SqlDb, UnifiedExecutor};
use crate::services::user_service::UserService;
use crate::shared::webdav::EntryPath;
use opendal::raw::*;
use opendal::Result;

use super::{WriteFinalizationDeleter, WriteFinalizationWriter};

/// Keeps file entries, events, and user quotas in sync with blob writes and deletes.
///
/// The related database changes are committed together in one transaction.
/// App-facing operators also reject path collisions; admin operators allow them
/// so they can repair legacy data.
///
/// Blob storage cannot be part of the database transaction. A write commits
/// its database effects only after the blob is published, so a failed commit
/// or a crash in between leaves the entry row describing the previous
/// content. Conditional writes and deletes verify the row against the blob
/// before evaluating their precondition and repair it if needed (see
/// [`verify`](super::verify)). If deleting a blob fails after its database
/// update, an unreferenced blob may remain.
#[derive(Clone)]
pub struct WriteFinalizationLayer {
    user_service: UserService,
    sql_db: SqlDb,
    events_service: EventsService,
    default_storage_mb: Option<u64>,
    collision_policy: CollisionPolicy,
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
    /// The backend beneath this layer, for verifying blobs against entry rows.
    pub(super) probe: Accessor,
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
            user_service,
            sql_db,
            events_service,
            default_storage_mb,
            collision_policy: CollisionPolicy::from_enforcement(enforce_path_collisions),
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

fn path_collision_error(entry_path: &EntryPath) -> opendal::Error {
    opendal::Error::new(
        opendal::ErrorKind::AlreadyExists,
        format!("File/folder path collision for {entry_path}"),
    )
    .set_source(LayerDomainError::PathCollision)
}

pub(super) fn precondition_failed_error(entry_path: &EntryPath) -> opendal::Error {
    opendal::Error::new(
        opendal::ErrorKind::ConditionNotMatch,
        format!("Write precondition failed for {entry_path}"),
    )
    .set_source(LayerDomainError::PreconditionFailed)
}

/// Whether `error` came from [`precondition_failed_error`].
pub(super) fn is_precondition_failure(error: &opendal::Error) -> bool {
    std::error::Error::source(error)
        .and_then(|source| source.downcast_ref::<LayerDomainError>())
        .is_some_and(|domain| matches!(domain, LayerDomainError::PreconditionFailed))
}

/// Rebuild `args` without its entity-tag conditions.
///
/// Conditions are enforced by the finalizer against entry content hashes, so
/// they must not reach the backend: OpenDAL's correctness check rejects them
/// for backends without native support, and backends with support would
/// compare them against their own ETags. `OpWrite` has no way to unset them.
///
/// The copied field list is exhaustive for opendal 0.54.1; re-check it when
/// bumping the dependency, and extend `strip_preconditions_tests` with any
/// field the bump adds.
fn strip_preconditions(args: &OpWrite) -> OpWrite {
    let mut stripped = OpWrite::new()
        .with_append(args.append())
        .with_concurrent(args.concurrent())
        .with_if_not_exists(args.if_not_exists());
    if let Some(value) = args.content_type() {
        stripped = stripped.with_content_type(value);
    }
    if let Some(value) = args.content_disposition() {
        stripped = stripped.with_content_disposition(value);
    }
    if let Some(value) = args.content_encoding() {
        stripped = stripped.with_content_encoding(value);
    }
    if let Some(value) = args.cache_control() {
        stripped = stripped.with_cache_control(value);
    }
    if let Some(metadata) = args.user_metadata() {
        stripped = stripped.with_user_metadata(metadata.clone());
    }
    stripped
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

/// Layered over the type-erased accessor an `Operator` holds, so the
/// finalizer can keep a handle to the backend for verifying blobs.
impl Layer<Accessor> for WriteFinalizationLayer {
    type LayeredAccess = WriteFinalizationAccessor<Accessor>;

    fn layer(&self, inner: Accessor) -> Self::LayeredAccess {
        let finalizer = Finalizer::new(
            self.user_service.clone(),
            self.sql_db.clone(),
            self.events_service.clone(),
            self.default_storage_mb,
            self.collision_policy,
            inner.clone(),
        );
        WriteFinalizationAccessor {
            inner: Arc::new(inner),
            finalizer: Arc::new(finalizer),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WriteFinalizationAccessor<A: Access> {
    inner: Arc<A>,
    finalizer: Arc<Finalizer>,
}

impl<A: Access> LayeredAccess for WriteFinalizationAccessor<A> {
    type Inner = A;
    type Reader = A::Reader;
    type Writer = WriteFinalizationWriter<A::Writer>;
    type Lister = A::Lister;
    type Deleter = WriteFinalizationDeleter<A::Deleter>;

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
        let preconditions = WritePreconditions::parse(args.if_match(), args.if_none_match())
            .map_err(|error| {
                unexpected(
                    format!("Invalid write precondition for {entry_path}"),
                    error,
                )
            })?;
        self.finalizer.collision_preflight(&entry_path).await?;
        self.finalizer
            .precondition_preflight(&entry_path, &preconditions)
            .await?;
        let (rp, writer) = self
            .inner
            .write(entry_path.as_str(), strip_preconditions(&args))
            .await?;
        Ok((
            rp,
            WriteFinalizationWriter::new(writer, self.finalizer.clone(), entry_path, preconditions),
        ))
    }

    async fn copy(&self, from: &str, to: &str, args: OpCopy) -> Result<RpCopy> {
        let from = EntryPath::parse_opendal(from)?;
        let to = EntryPath::parse_opendal(to)?;
        self.finalizer.collision_preflight(&to).await?;
        self.inner.copy(from.as_str(), to.as_str(), args).await
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
        probe: Accessor,
    ) -> Self {
        Self {
            user_service,
            sql_db,
            events_service,
            default_storage_mb,
            collision_policy,
            probe,
        }
    }

    async fn collision_preflight(&self, entry_path: &EntryPath) -> Result<()> {
        if !self.collision_policy.enforces_collisions() {
            return Ok(());
        }

        check_no_path_collision(entry_path, &mut self.sql_db.pool().into()).await
    }

    /// Reject a write whose precondition already fails before any bytes are
    /// accepted. The authoritative check runs again under the user lock in
    /// [`prepare_write`](Finalizer::prepare_write).
    async fn precondition_preflight(
        &self,
        entry_path: &EntryPath,
        preconditions: &WritePreconditions,
    ) -> Result<()> {
        if preconditions.is_empty() {
            return Ok(());
        }

        let current_hash =
            match EntryRepository::get_by_path(entry_path, &mut self.sql_db.pool().into()).await {
                Ok(entry) => self.verified_content_hash(entry).await?,
                Err(sqlx::Error::RowNotFound) => None,
                Err(error) => {
                    return Err(unexpected(
                        format!("Failed to load existing entry {entry_path}"),
                        error,
                    ));
                }
            };
        if !preconditions.is_satisfied_by(current_hash.as_ref()) {
            return Err(precondition_failed_error(entry_path));
        }

        Ok(())
    }

    /// Insert an event. Its insert takes a homeserver-wide advisory lock that
    /// is held until commit, so callers place it as late in a transaction as
    /// possible and never before a backend operation.
    pub(super) async fn record_event(
        &self,
        user_id: i32,
        event: EventType,
        entry_path: &EntryPath,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<()> {
        self.events_service
            .create_event(user_id, event, entry_path, executor)
            .await
            .map(|_| ())
            .map_err(|error| unexpected(format!("Failed to create event for {entry_path}"), error))
    }

    pub(super) fn notify_event(&self) {
        let events_service = self.events_service.clone();
        drop(tokio::spawn(async move {
            events_service.notify_event().await;
        }));
    }
}

#[cfg(test)]
mod strip_preconditions_tests {
    use std::collections::HashMap;

    use opendal::raw::OpWrite;

    use super::strip_preconditions;

    /// Every field but the two conditions must survive the copy. This cannot
    /// notice a field a dependency bump adds; add it here when it does.
    #[test]
    fn keeps_every_field_but_the_conditions() {
        let metadata = HashMap::from([("key".to_string(), "value".to_string())]);
        let args = OpWrite::new()
            .with_append(true)
            .with_concurrent(3)
            .with_if_not_exists(true)
            .with_content_type("text/plain")
            .with_content_disposition("attachment")
            .with_content_encoding("gzip")
            .with_cache_control("no-store")
            .with_user_metadata(metadata.clone())
            .with_if_match("\"a\"")
            .with_if_none_match("\"b\"");

        let stripped = strip_preconditions(&args);

        assert_eq!(stripped.if_match(), None);
        assert_eq!(stripped.if_none_match(), None);
        assert!(stripped.append());
        assert_eq!(stripped.concurrent(), 3);
        assert!(stripped.if_not_exists());
        assert_eq!(stripped.content_type(), Some("text/plain"));
        assert_eq!(stripped.content_disposition(), Some("attachment"));
        assert_eq!(stripped.content_encoding(), Some("gzip"));
        assert_eq!(stripped.cache_control(), Some("no-store"));
        assert_eq!(stripped.user_metadata(), Some(&metadata));
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use pubky_common::crypto::Keypair;

    use crate::persistence::files::{
        events::{EventEntity, EventRepository, EventVisibility},
        opendal::opendal_test_operators::{get_atomic_fs_operator, get_memory_operator},
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
            get_memory_operator().into_inner(),
        )
    }

    pub(crate) fn test_operator(db: &SqlDb) -> opendal::Operator {
        get_memory_operator().layer(WriteFinalizationLayer::new(
            UserService::new(db.clone()),
            db.clone(),
            EventsService::new(db.clone(), 100),
            None,
            true,
        ))
    }

    /// Filesystem-backed operator staging uploads like production does.
    /// The returned directory must outlive the operator.
    pub(in super::super) fn test_fs_operator(db: &SqlDb) -> (opendal::Operator, tempfile::TempDir) {
        let (backend, dir) = get_atomic_fs_operator();
        let operator = backend.layer(WriteFinalizationLayer::new(
            UserService::new(db.clone()),
            db.clone(),
            EventsService::new(db.clone(), 100),
            None,
            true,
        ));
        (operator, dir)
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

    pub(crate) async fn all_events(db: &SqlDb) -> Vec<EventEntity> {
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
