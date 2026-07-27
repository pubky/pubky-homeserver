use std::sync::Arc;

use crate::persistence::files::{
    entry::EntryService,
    events::{EventType, EventsService},
    layer_domain_error::LayerDomainError,
    FileMetadataBuilder,
};
use crate::persistence::sql::{entry::EntryRepository, UnifiedExecutor};
use crate::services::user_service::{UserService, FILE_METADATA_SIZE};
use crate::shared::webdav::EntryPath;
use opendal::raw::*;
use opendal::Result;
use std::mem::take;

/// Finalizes storage mutations whose database effects must share one transaction.
///
/// App-facing operators enable collision checks; admin operators do not.
/// The transaction makes the database effects atomic. The external blob backend
/// cannot join that transaction, so write-side backend changes cannot be rolled
/// back after a database failure, while delete-side backend failures may leave
/// an unreferenced blob.
#[derive(Clone)]
pub struct WriteFinalizationLayer {
    finalizer: Arc<Finalizer>,
}

#[derive(Debug, Clone, Copy)]
enum CollisionPolicy {
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

    fn enforces_collisions(self) -> bool {
        matches!(self, Self::Enforce)
    }
}

#[derive(Debug)]
struct Finalizer {
    user_service: UserService,
    events_service: EventsService,
    default_storage_mb: Option<u64>,
    collision_policy: CollisionPolicy,
}

impl WriteFinalizationLayer {
    pub fn new(
        user_service: UserService,
        events_service: EventsService,
        default_storage_mb: Option<u64>,
        enforce_path_collisions: bool,
    ) -> Self {
        Self {
            finalizer: Arc::new(Finalizer::new(
                user_service,
                events_service,
                default_storage_mb,
                CollisionPolicy::from_enforcement(enforce_path_collisions),
            )),
        }
    }
}

/// Check whether adding `bytes_delta` to `current_bytes` would exceed `max_bytes`.
/// `None` means unlimited storage.
pub(crate) fn would_exceed_limit(
    current_bytes: u64,
    bytes_delta: i64,
    max_bytes: Option<u64>,
) -> bool {
    let Some(max) = max_bytes else {
        return false;
    };
    let new_total = current_bytes as i128 + bytes_delta as i128;
    new_total > 0 && new_total > max as i128
}

/// Resolve the effective storage limit from the per-user override and system default.
pub(crate) fn resolve_storage_max_bytes(
    user: &crate::persistence::sql::user::UserEntity,
    default_storage_mb: Option<u64>,
) -> Option<u64> {
    user.quota()
        .storage_quota_mb
        .resolve_with_default(default_storage_mb)
        .map(|mb| mb.saturating_mul(1024 * 1024))
}

fn unexpected(context: impl std::fmt::Display, error: impl std::fmt::Display) -> opendal::Error {
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

async fn check_no_path_collision(
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

impl<A: Access> Layer<A> for WriteFinalizationLayer {
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
        self.finalizer.collision_preflight(&entry_path).await?;
        let (rp, writer) = self.inner.write(entry_path.as_str(), args).await?;
        Ok((
            rp,
            WriteFinalizationWriter {
                inner: writer,
                finalizer: self.finalizer.clone(),
                entry_path,
                metadata_builder: FileMetadataBuilder::default(),
            },
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
            WriteFinalizationDeleter {
                inner: deleter,
                finalizer: self.finalizer.clone(),
                delete_queue: Vec::new(),
            },
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

/// Writer that commits entry metadata, its event, and quota accounting together.
pub struct WriteFinalizationWriter<R> {
    inner: R,
    finalizer: Arc<Finalizer>,
    entry_path: EntryPath,
    metadata_builder: FileMetadataBuilder,
}

impl<R: oio::Write> oio::Write for WriteFinalizationWriter<R> {
    async fn write(&mut self, bs: opendal::Buffer) -> Result<()> {
        self.metadata_builder.update(&bs.to_vec());
        self.inner.write(bs).await
    }

    async fn abort(&mut self) -> Result<()> {
        self.inner.abort().await
    }

    async fn close(&mut self) -> Result<opendal::Metadata> {
        self.metadata_builder
            .guess_mime_type_from_path(self.entry_path.path().as_str());
        let file_metadata = self.metadata_builder.clone().finalize();
        let entry_service = EntryService::new();
        let mut tx = self
            .finalizer
            .user_service
            .pool()
            .begin()
            .await
            .map_err(|error| unexpected("Failed to begin write finalization transaction", error))?;

        let result = async {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            let mut user = self.finalizer.user_service.get_for_no_key_update(
                self.entry_path.pubkey(),
                &mut executor,
            )
            .await
            .map_err(|error| {
                unexpected(
                    format!("Failed to lock user {}", self.entry_path.pubkey()),
                    error,
                )
            })?;

            if self.finalizer.collision_policy.enforces_collisions() {
                check_no_path_collision(&self.entry_path, &mut executor).await?;
            }

            let existing_entry = match EntryRepository::get_by_path(&self.entry_path, &mut executor)
                .await
            {
                Ok(entry) => Some(entry),
                Err(sqlx::Error::RowNotFound) => None,
                Err(error) => {
                    return Err(unexpected(
                        format!("Failed to load existing entry {}", self.entry_path),
                        error,
                    ));
                }
            };
            let existing_bytes = existing_entry
                .as_ref()
                .map_or(0, |entry| entry.content_length);
            let metadata_bytes = if existing_entry.is_none() {
                FILE_METADATA_SIZE as i64
            } else {
                0
            };
            let bytes_delta = file_metadata.length as i64 - existing_bytes as i64 + metadata_bytes;
            let max_bytes =
                resolve_storage_max_bytes(&user, self.finalizer.default_storage_mb);
            if would_exceed_limit(user.used_bytes, bytes_delta, max_bytes) {
                return Err(opendal::Error::new(
                    opendal::ErrorKind::RateLimited,
                    "User quota exceeded",
                )
                .set_source(LayerDomainError::DiskSpaceQuotaExceeded));
            }

            let backend_metadata = self.inner.close().await?;
            entry_service
                .write_entry(
                    user.id,
                    existing_entry,
                    &self.entry_path,
                    &file_metadata,
                    &mut executor,
                )
                .await
                .map_err(|error| {
                    unexpected(
                        format!(
                            "Failed to write entry {} after backend close; potential orphaned file",
                            self.entry_path
                        ),
                        error,
                    )
                })?;
            self.finalizer
                .events_service
                .create_event(
                    user.id,
                    EventType::Put {
                        content_hash: file_metadata.hash,
                    },
                    &self.entry_path,
                    &mut executor,
                )
                .await
                .map_err(|error| {
                    unexpected(
                        format!(
                            "Failed to create event {} after backend close; potential orphaned file",
                            self.entry_path
                        ),
                        error,
                    )
                })?;
            user.used_bytes = user.used_bytes.saturating_add_signed(bytes_delta);
            self.finalizer
                .user_service
                .update(&user, &mut executor)
                .await
                .map_err(|error| {
                    unexpected(
                        format!("Failed to update quota for {}", self.entry_path.pubkey()),
                        error,
                    )
                })?;

            Ok(backend_metadata)
        }
        .await;

        let metadata = match result {
            Ok(metadata) => {
                tx.commit()
                    .await
                    .map_err(|error| unexpected("Failed to commit write finalization", error))?;
                metadata
            }
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::error!(
                        path = %self.entry_path,
                        error = %rollback_error,
                        "Failed to roll back write finalization transaction"
                    );
                }
                return Err(error);
            }
        };

        self.finalizer.notify_event();
        Ok(metadata)
    }
}

impl Finalizer {
    fn new(
        user_service: UserService,
        events_service: EventsService,
        default_storage_mb: Option<u64>,
        collision_policy: CollisionPolicy,
    ) -> Self {
        Self {
            user_service,
            events_service,
            default_storage_mb,
            collision_policy,
        }
    }

    async fn collision_preflight(&self, entry_path: &EntryPath) -> Result<()> {
        if !self.collision_policy.enforces_collisions() {
            return Ok(());
        }

        check_no_path_collision(entry_path, &mut self.user_service.pool().into()).await
    }

    /// Returns `false` when no entry existed, so duplicate deletes remain a no-op.
    async fn finalize_delete(&self, entry_path: &EntryPath) -> Result<bool> {
        let entry_service = EntryService::new();
        let mut tx = self.user_service.pool().begin().await.map_err(|error| {
            unexpected("Failed to begin delete finalization transaction", error)
        })?;

        let result = async {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            let mut user = match self
                .user_service
                .get_for_no_key_update(entry_path.pubkey(), &mut executor)
                .await
            {
                Ok(user) => user,
                Err(sqlx::Error::RowNotFound) => return Ok(false),
                Err(error) => {
                    return Err(unexpected(
                        format!("Failed to lock user {}", entry_path.pubkey()),
                        error,
                    ));
                }
            };

            let deleted_entry = match entry_service.delete_entry(entry_path, &mut executor).await {
                Ok(entry) => entry,
                Err(crate::persistence::files::FileIoError::NotFound) => return Ok(false),
                Err(error) => {
                    return Err(unexpected(
                        format!("Failed to delete entry {entry_path}"),
                        error,
                    ));
                }
            };

            self.events_service
                .create_event(user.id, EventType::Delete, entry_path, &mut executor)
                .await
                .map_err(|error| {
                    unexpected(
                        format!("Failed to create delete event for {entry_path}"),
                        error,
                    )
                })?;

            let bytes_delta = deleted_entry
                .content_length
                .saturating_add(FILE_METADATA_SIZE);
            user.used_bytes = user.used_bytes.saturating_sub(bytes_delta);
            self.user_service
                .update(&user, &mut executor)
                .await
                .map_err(|error| {
                    unexpected(
                        format!("Failed to update quota for {}", entry_path.pubkey()),
                        error,
                    )
                })?;

            Ok(true)
        }
        .await;

        match result {
            Ok(true) => {
                tx.commit()
                    .await
                    .map_err(|error| unexpected("Failed to commit delete finalization", error))?;
                Ok(true)
            }
            Ok(false) => {
                tx.rollback()
                    .await
                    .map_err(|error| unexpected("Failed to roll back empty delete", error))?;
                Ok(false)
            }
            Err(error) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::error!(
                        path = %entry_path,
                        error = %rollback_error,
                        "Failed to roll back delete finalization transaction"
                    );
                }
                Err(error)
            }
        }
    }

    fn notify_event(&self) {
        let pool = self.user_service.pool().clone();
        drop(tokio::spawn(async move {
            EventsService::notify_event(&pool).await;
        }));
    }
}

/// Deleter that commits entry deletion, its event, and quota accounting together.
pub struct WriteFinalizationDeleter<R> {
    inner: R,
    finalizer: Arc<Finalizer>,
    delete_queue: Vec<EntryPath>,
}

impl<R: oio::Delete> oio::Delete for WriteFinalizationDeleter<R> {
    fn delete(&mut self, path: &str, args: OpDelete) -> Result<()> {
        let entry_path = EntryPath::parse_opendal(path)?;
        self.inner.delete(entry_path.as_str(), args)?;
        self.delete_queue.push(entry_path);
        Ok(())
    }

    async fn flush(&mut self) -> Result<usize> {
        let mut should_notify = false;
        let mut first_error = None;
        let mut failed_paths = Vec::new();

        // Commit database effects before deleting blobs. If finalization fails,
        // the inner queue remains unflushed and the blob stays available.
        for entry_path in take(&mut self.delete_queue) {
            match self.finalizer.finalize_delete(&entry_path).await {
                Ok(path_should_notify) => should_notify |= path_should_notify,
                Err(error) => {
                    tracing::error!(
                        path = %entry_path,
                        error = %error,
                        "Failed to finalize deleted path"
                    );
                    failed_paths.push(entry_path);
                    first_error.get_or_insert(error);
                }
            }
        }
        self.delete_queue = failed_paths;

        if should_notify {
            self.finalizer.notify_event();
        }

        if let Some(error) = first_error {
            return Err(error);
        }

        self.inner.flush().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use opendal::raw::oio::Delete;
    use pubky_common::crypto::Keypair;
    use tokio::sync::Barrier;

    use crate::persistence::files::{
        events::{EventRepository, EventType, EventVisibility},
        opendal::opendal_test_operators::get_memory_operator,
        FileIoError,
    };
    use crate::persistence::sql::{user::UserRepository, SqlDb};
    use crate::shared::webdav::{EntryPath, WebDavPath};

    use super::*;

    #[derive(Default)]
    struct BatchDelete {
        queued: usize,
    }

    impl oio::Delete for BatchDelete {
        fn delete(&mut self, _path: &str, _args: OpDelete) -> Result<()> {
            self.queued += 1;
            Ok(())
        }

        async fn flush(&mut self) -> Result<usize> {
            Ok(std::mem::take(&mut self.queued))
        }
    }

    fn test_finalizer(db: &SqlDb) -> Finalizer {
        Finalizer::new(
            UserService::new(db.clone()),
            EventsService::new(100),
            None,
            CollisionPolicy::Enforce,
        )
    }

    fn test_operator(db: &SqlDb) -> opendal::Operator {
        get_memory_operator().layer(WriteFinalizationLayer::new(
            UserService::new(db.clone()),
            EventsService::new(100),
            None,
            true,
        ))
    }

    async fn create_user(db: &SqlDb) -> pubky_common::crypto::PublicKey {
        let pubkey = Keypair::random().public_key();
        UserRepository::create(&pubkey, &mut db.pool().into())
            .await
            .unwrap();
        pubkey
    }

    async fn user_usage(db: &SqlDb, pubkey: &pubky_common::crypto::PublicKey) -> u64 {
        UserRepository::get(pubkey, &mut db.pool().into())
            .await
            .unwrap()
            .used_bytes
    }

    async fn all_events(db: &SqlDb) -> Vec<crate::persistence::files::events::EventEntity> {
        EventRepository::get_by_cursor(
            None,
            Some(9999),
            EventVisibility::All,
            &mut db.pool().into(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn write_overwrite_and_delete_finalize_all_database_effects() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey.clone(), WebDavPath::new("/test.txt").unwrap());

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

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn deleting_without_an_entry_does_not_emit_an_event() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let missing_path = EntryPath::new(pubkey.clone(), WebDavPath::new("/missing.txt").unwrap());

        operator.delete(missing_path.as_str()).await.unwrap();

        assert_eq!(user_usage(&db, &pubkey).await, 0);
        assert!(all_events(&db).await.is_empty());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn concurrent_delete_finalizations_account_for_an_entry_once() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let deleted_path = EntryPath::new(pubkey.clone(), WebDavPath::new("/deleted.txt").unwrap());
        let retained_path =
            EntryPath::new(pubkey.clone(), WebDavPath::new("/retained.txt").unwrap());

        operator
            .write(deleted_path.as_str(), vec![1; 10])
            .await
            .unwrap();
        operator
            .write(retained_path.as_str(), vec![2; 20])
            .await
            .unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let first_barrier = barrier.clone();
        let second_barrier = barrier.clone();
        let first_finalizer = test_finalizer(&db);
        let second_finalizer = test_finalizer(&db);
        let first_path = deleted_path.clone();
        let second_path = deleted_path.clone();

        let first = async move {
            first_barrier.wait().await;
            first_finalizer.finalize_delete(&first_path).await
        };
        let second = async move {
            second_barrier.wait().await;
            second_finalizer.finalize_delete(&second_path).await
        };
        let (first_result, second_result) = tokio::join!(first, second);

        assert_ne!(first_result.unwrap(), second_result.unwrap());
        assert_eq!(user_usage(&db, &pubkey).await, 20 + FILE_METADATA_SIZE);
        EntryRepository::get_by_path(&deleted_path, &mut db.pool().into())
            .await
            .expect_err("entry should be deleted exactly once");
        EntryRepository::get_by_path(&retained_path, &mut db.pool().into())
            .await
            .expect("unrelated entry should remain");
        let events = all_events(&db).await;
        assert_eq!(events.len(), 3);
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == EventType::Delete)
                .count(),
            1
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn event_insert_failure_rolls_back_entry_event_and_quota() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey.clone(), WebDavPath::new("/test.txt").unwrap());

        sqlx::query(
            r#"
            CREATE FUNCTION fail_event_insert() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'forced event insert failure';
            END;
            $$ LANGUAGE plpgsql
            "#,
        )
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            r#"
            CREATE TRIGGER fail_event_insert_trigger
            BEFORE INSERT ON events
            FOR EACH ROW EXECUTE FUNCTION fail_event_insert()
            "#,
        )
        .execute(db.pool())
        .await
        .unwrap();

        operator
            .write(entry_path.as_str(), vec![1; 10])
            .await
            .expect_err("forced event failure should fail the write");

        EntryRepository::get_by_path(&entry_path, &mut db.pool().into())
            .await
            .expect_err("entry insert should roll back");
        assert_eq!(user_usage(&db, &pubkey).await, 0);
        assert!(all_events(&db).await.is_empty());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn delete_finalization_failure_preserves_blob_and_database_state() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey.clone(), WebDavPath::new("/test.txt").unwrap());
        let content = vec![1; 10];

        operator
            .write(entry_path.as_str(), content.clone())
            .await
            .unwrap();
        let usage_before_delete = user_usage(&db, &pubkey).await;

        sqlx::query(
            r#"
            CREATE FUNCTION fail_delete_event_insert() RETURNS trigger AS $$
            BEGIN
                IF NEW.type = 'DEL' THEN
                    RAISE EXCEPTION 'forced delete event insert failure';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            "#,
        )
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            r#"
            CREATE TRIGGER fail_delete_event_insert_trigger
            BEFORE INSERT ON events
            FOR EACH ROW EXECUTE FUNCTION fail_delete_event_insert()
            "#,
        )
        .execute(db.pool())
        .await
        .unwrap();

        operator
            .delete(entry_path.as_str())
            .await
            .expect_err("forced event failure should fail the delete");

        assert_eq!(
            operator.read(entry_path.as_str()).await.unwrap().to_vec(),
            content,
            "failed delete finalization must preserve the blob"
        );
        EntryRepository::get_by_path(&entry_path, &mut db.pool().into())
            .await
            .expect("failed delete finalization must preserve the entry");
        assert_eq!(user_usage(&db, &pubkey).await, usage_before_delete);
        let events = all_events(&db).await;
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].event_type, EventType::Put { .. }));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn batched_delete_continues_finalization_after_error() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let failing_path = EntryPath::new(pubkey.clone(), WebDavPath::new("/failing.txt").unwrap());
        let succeeding_path =
            EntryPath::new(pubkey.clone(), WebDavPath::new("/succeeding.txt").unwrap());

        operator
            .write(failing_path.as_str(), vec![1; 10])
            .await
            .unwrap();
        operator
            .write(succeeding_path.as_str(), vec![2; 20])
            .await
            .unwrap();

        sqlx::query(
            r#"
            CREATE FUNCTION fail_selected_delete_event() RETURNS trigger AS $$
            BEGIN
                IF NEW.type = 'DEL' AND NEW.path = '/failing.txt' THEN
                    RAISE EXCEPTION 'forced selected delete event failure';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            "#,
        )
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            r#"
            CREATE TRIGGER fail_selected_delete_event_trigger
            BEFORE INSERT ON events
            FOR EACH ROW EXECUTE FUNCTION fail_selected_delete_event()
            "#,
        )
        .execute(db.pool())
        .await
        .unwrap();

        let mut deleter = WriteFinalizationDeleter {
            inner: BatchDelete::default(),
            finalizer: Arc::new(test_finalizer(&db)),
            delete_queue: Vec::new(),
        };
        deleter
            .delete(failing_path.as_str(), OpDelete::default())
            .unwrap();
        deleter
            .delete(succeeding_path.as_str(), OpDelete::default())
            .unwrap();

        deleter
            .flush()
            .await
            .expect_err("the batch should report the first finalization error");

        EntryRepository::get_by_path(&failing_path, &mut db.pool().into())
            .await
            .expect("the failed finalization should roll back");
        EntryRepository::get_by_path(&succeeding_path, &mut db.pool().into())
            .await
            .expect_err("later paths should still be finalized");
        assert_eq!(user_usage(&db, &pubkey).await, 10 + FILE_METADATA_SIZE);
        let events = all_events(&db).await;
        assert_eq!(events.len(), 3);
        assert_eq!(events.last().unwrap().event_type, EventType::Delete);
        assert_eq!(events.last().unwrap().path, succeeding_path);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn concurrent_colliding_closes_allow_exactly_one_entry() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let ancestor = EntryPath::new(pubkey.clone(), WebDavPath::new("/pub/app/foo").unwrap());
        let descendant = EntryPath::new(
            pubkey.clone(),
            WebDavPath::new("/pub/app/foo/bar.json").unwrap(),
        );

        let mut ancestor_writer = operator.writer(ancestor.as_str()).await.unwrap();
        let mut descendant_writer = operator.writer(descendant.as_str()).await.unwrap();
        ancestor_writer.write(vec![1; 10]).await.unwrap();
        descendant_writer.write(vec![2; 20]).await.unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let ancestor_barrier = barrier.clone();
        let descendant_barrier = barrier.clone();
        let ancestor_close = async move {
            ancestor_barrier.wait().await;
            ancestor_writer.close().await
        };
        let descendant_close = async move {
            descendant_barrier.wait().await;
            descendant_writer.close().await
        };
        let (ancestor_result, descendant_result) = tokio::join!(ancestor_close, descendant_close);

        assert_ne!(ancestor_result.is_ok(), descendant_result.is_ok());
        let collision = ancestor_result
            .err()
            .or_else(|| descendant_result.err())
            .expect("one close should fail");
        assert!(matches!(
            FileIoError::from(collision),
            FileIoError::PathCollision
        ));

        let ancestor_entry = EntryRepository::get_by_path(&ancestor, &mut db.pool().into()).await;
        let descendant_entry =
            EntryRepository::get_by_path(&descendant, &mut db.pool().into()).await;
        assert_ne!(ancestor_entry.is_ok(), descendant_entry.is_ok());
        let expected_usage = ancestor_entry.ok().map_or_else(
            || descendant_entry.unwrap().content_length,
            |entry| entry.content_length,
        ) + FILE_METADATA_SIZE;
        assert_eq!(user_usage(&db, &pubkey).await, expected_usage);
        assert_eq!(all_events(&db).await.len(), 1);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn uploads_beyond_pool_size_complete_for_same_and_cross_user_writes() {
        const POOL_SIZE: u32 = 2;
        const UPLOADS: usize = 5;
        let db = SqlDb::test_with_pool_options(POOL_SIZE, Duration::from_secs(2)).await;
        let operator = test_operator(&db);
        let same_user = create_user(&db).await;
        let barrier = Arc::new(Barrier::new(UPLOADS));

        let same_user_uploads = (0..UPLOADS).map(|index| {
            let operator = operator.clone();
            let barrier = barrier.clone();
            let path = format!("{}/same-user-{index}.txt", same_user.z32());
            async move {
                barrier.wait().await;
                operator.write(&path, vec![index as u8; 10]).await
            }
        });
        let same_user_results = tokio::time::timeout(
            Duration::from_secs(10),
            futures_util::future::join_all(same_user_uploads),
        )
        .await
        .expect("same-user uploads should not deadlock");
        assert!(same_user_results.iter().all(Result::is_ok));

        let mut users = Vec::with_capacity(UPLOADS);
        for _ in 0..UPLOADS {
            users.push(create_user(&db).await);
        }
        let barrier = Arc::new(Barrier::new(UPLOADS));
        let cross_user_uploads = users.into_iter().enumerate().map(|(index, pubkey)| {
            let operator = operator.clone();
            let barrier = barrier.clone();
            let path = format!("{}/cross-user.txt", pubkey.z32());
            async move {
                barrier.wait().await;
                operator.write(&path, vec![index as u8; 10]).await
            }
        });
        let cross_user_results = tokio::time::timeout(
            Duration::from_secs(10),
            futures_util::future::join_all(cross_user_uploads),
        )
        .await
        .expect("cross-user uploads should not deadlock");
        assert!(cross_user_results.iter().all(Result::is_ok));
    }

    #[test]
    fn quota_limit_math_handles_boundaries_and_negative_deltas() {
        assert!(!would_exceed_limit(500, 500, Some(1000)));
        assert!(would_exceed_limit(500, 501, Some(1000)));
        assert!(!would_exceed_limit(1000, -500, Some(1000)));
        assert!(!would_exceed_limit(u64::MAX, i64::MAX, None));
        assert!(would_exceed_limit(0, 1, Some(0)));
        assert!(!would_exceed_limit(0, 0, Some(0)));
    }
}
