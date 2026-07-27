use std::sync::Arc;

use crate::persistence::files::{events::EventsService, layer_domain_error::LayerDomainError};
use crate::persistence::sql::{entry::EntryRepository, UnifiedExecutor};
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
/// Blob storage cannot be part of the database transaction. If the database
/// update after a write fails, the blob may remain without a matching entry.
/// If deleting a blob fails after its database update, an unreferenced blob may
/// remain.
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
    pub(super) events_service: EventsService,
    pub(super) default_storage_mb: Option<u64>,
    pub(super) collision_policy: CollisionPolicy,
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
            WriteFinalizationWriter::new(writer, self.finalizer.clone(), entry_path),
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

    pub(super) fn notify_event(&self) {
        let pool = self.user_service.pool().clone();
        drop(tokio::spawn(async move {
            EventsService::notify_event(&pool).await;
        }));
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use pubky_common::crypto::Keypair;

    use crate::persistence::files::{
        events::{EventEntity, EventRepository, EventVisibility},
        opendal::opendal_test_operators::get_memory_operator,
    };
    use crate::persistence::sql::{user::UserRepository, SqlDb};

    use super::*;

    pub(in super::super) fn test_finalizer(db: &SqlDb) -> Finalizer {
        Finalizer::new(
            UserService::new(db.clone()),
            EventsService::new(100),
            None,
            CollisionPolicy::Enforce,
        )
    }

    pub(in super::super) fn test_operator(db: &SqlDb) -> opendal::Operator {
        get_memory_operator().layer(WriteFinalizationLayer::new(
            UserService::new(db.clone()),
            EventsService::new(100),
            None,
            true,
        ))
    }

    pub(in super::super) async fn create_user(db: &SqlDb) -> pubky_common::crypto::PublicKey {
        let pubkey = Keypair::random().public_key();
        UserRepository::create(&pubkey, &mut db.pool().into())
            .await
            .unwrap();
        pubkey
    }

    pub(in super::super) async fn user_usage(
        db: &SqlDb,
        pubkey: &pubky_common::crypto::PublicKey,
    ) -> u64 {
        UserRepository::get(pubkey, &mut db.pool().into())
            .await
            .unwrap()
            .used_bytes
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
    use crate::shared::webdav::{EntryPath, WebDavPath};

    use super::test_support::{all_events, create_user, test_operator, user_usage};

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
}
