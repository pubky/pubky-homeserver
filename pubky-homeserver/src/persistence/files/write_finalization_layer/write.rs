use std::sync::Arc;

use crate::persistence::files::{
    events::EventType, layer_domain_error::LayerDomainError, FileMetadata, FileMetadataBuilder,
};
use crate::persistence::sql::{
    entry::{EntryEntity, EntryRepository},
    user::UserEntity,
    UnifiedExecutor,
};
use crate::services::user_service::FILE_METADATA_SIZE;
use crate::shared::webdav::EntryPath;
use opendal::raw::oio;
use opendal::Result;

use super::{
    layer::{check_no_path_collision, unexpected, Finalizer},
    resolve_storage_max_bytes, would_exceed_limit,
};

struct PreparedWrite {
    user: UserEntity,
    existing_entry: Option<EntryEntity>,
    bytes_delta: i64,
}

impl PreparedWrite {
    fn new(
        user: UserEntity,
        existing_entry: Option<EntryEntity>,
        file_metadata: &FileMetadata,
        default_storage_mb: Option<u64>,
    ) -> Result<Self> {
        let existing_bytes = existing_entry
            .as_ref()
            .map_or(0, |entry| entry.content_length);
        let metadata_bytes = if existing_entry.is_none() {
            FILE_METADATA_SIZE as i64
        } else {
            0
        };
        let bytes_delta = file_metadata.length as i64 - existing_bytes as i64 + metadata_bytes;
        let max_bytes = resolve_storage_max_bytes(&user, default_storage_mb);
        if would_exceed_limit(user.used_bytes, bytes_delta, max_bytes) {
            return Err(opendal::Error::new(
                opendal::ErrorKind::RateLimited,
                "User quota exceeded",
            )
            .set_source(LayerDomainError::DiskSpaceQuotaExceeded));
        }

        Ok(Self {
            user,
            existing_entry,
            bytes_delta,
        })
    }
}

/// Writer that commits entry metadata, its event, and quota accounting together.
pub struct WriteFinalizationWriter<R> {
    inner: R,
    finalizer: Arc<Finalizer>,
    entry_path: EntryPath,
    metadata_builder: FileMetadataBuilder,
}

impl<R> WriteFinalizationWriter<R> {
    pub(super) fn new(inner: R, finalizer: Arc<Finalizer>, entry_path: EntryPath) -> Self {
        Self {
            inner,
            finalizer,
            entry_path,
            metadata_builder: FileMetadataBuilder::default(),
        }
    }
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
        self.finalizer
            .finalize_write(&mut self.inner, &self.entry_path, &file_metadata)
            .await
    }
}

impl Finalizer {
    async fn finalize_write<R: oio::Write>(
        &self,
        backend_writer: &mut R,
        entry_path: &EntryPath,
        file_metadata: &FileMetadata,
    ) -> Result<opendal::Metadata> {
        let mut tx =
            self.user_service.pool().begin().await.map_err(|error| {
                unexpected("Failed to begin write finalization transaction", error)
            })?;

        let result = {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            self.write_in_transaction(backend_writer, entry_path, file_metadata, &mut executor)
                .await
        };

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
                        path = %entry_path,
                        error = %rollback_error,
                        "Failed to roll back write finalization transaction"
                    );
                }
                return Err(error);
            }
        };

        self.notify_event();
        Ok(metadata)
    }

    async fn write_in_transaction<R: oio::Write>(
        &self,
        backend_writer: &mut R,
        entry_path: &EntryPath,
        file_metadata: &FileMetadata,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<opendal::Metadata> {
        let prepared = self
            .prepare_write(entry_path, file_metadata, executor)
            .await?;
        let backend_metadata = backend_writer.close().await?;
        self.apply_write_effects(prepared, entry_path, file_metadata, executor)
            .await?;
        Ok(backend_metadata)
    }

    async fn prepare_write(
        &self,
        entry_path: &EntryPath,
        file_metadata: &FileMetadata,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<PreparedWrite> {
        let user = self
            .user_service
            .get_for_no_key_update(entry_path.pubkey(), executor)
            .await
            .map_err(|error| {
                unexpected(
                    format!("Failed to lock user {}", entry_path.pubkey()),
                    error,
                )
            })?;

        if self.collision_policy.enforces_collisions() {
            check_no_path_collision(entry_path, executor).await?;
        }

        let existing_entry = match EntryRepository::get_by_path(entry_path, executor).await {
            Ok(entry) => Some(entry),
            Err(sqlx::Error::RowNotFound) => None,
            Err(error) => {
                return Err(unexpected(
                    format!("Failed to load existing entry {}", entry_path),
                    error,
                ));
            }
        };

        PreparedWrite::new(user, existing_entry, file_metadata, self.default_storage_mb)
    }

    async fn apply_write_effects(
        &self,
        prepared: PreparedWrite,
        entry_path: &EntryPath,
        file_metadata: &FileMetadata,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<()> {
        let PreparedWrite {
            mut user,
            existing_entry,
            bytes_delta,
        } = prepared;
        match existing_entry {
            Some(mut entry) => {
                entry.content_hash = file_metadata.hash;
                entry.content_length = file_metadata.length as u64;
                entry.content_type = file_metadata.content_type.clone();
                EntryRepository::update(&entry, executor).await
            }
            None => EntryRepository::create(
                user.id,
                entry_path.path(),
                &file_metadata.hash,
                file_metadata.length as u64,
                &file_metadata.content_type,
                executor,
            )
            .await
            .map(|_| ()),
        }
        .map_err(|error| {
            unexpected(
                format!(
                    "Failed to write entry {} after backend close; potential orphaned file",
                    entry_path
                ),
                error,
            )
        })?;
        self.events_service
            .create_event(
                user.id,
                EventType::Put {
                    content_hash: file_metadata.hash,
                },
                entry_path,
                executor,
            )
            .await
            .map_err(|error| {
                unexpected(
                    format!(
                        "Failed to create event {} after backend close; potential orphaned file",
                        entry_path
                    ),
                    error,
                )
            })?;
        user.used_bytes = user.used_bytes.saturating_add_signed(bytes_delta);
        self.user_service
            .update(&user, executor)
            .await
            .map_err(|error| {
                unexpected(
                    format!("Failed to update quota for {}", entry_path.pubkey()),
                    error,
                )
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::sync::Barrier;

    use crate::persistence::files::FileIoError;
    use crate::persistence::sql::{entry::EntryRepository, SqlDb};
    use crate::services::user_service::FILE_METADATA_SIZE;
    use crate::shared::webdav::{EntryPath, WebDavPath};

    use super::super::layer::test_support::{all_events, create_user, test_operator, user_usage};
    use super::*;

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
}
