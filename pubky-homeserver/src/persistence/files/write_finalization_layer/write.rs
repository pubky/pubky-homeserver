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
    layer::{already_closed, check_no_path_collision, spawn_finalization, unexpected, Finalizer},
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
///
/// Closing finalizes on a task of its own, so a caller dropped mid-close (a
/// client disconnect) cannot stop the finalization halfway. A writer dropped
/// before it is closed or aborted discards its staged bytes on a spawned task,
/// so a disconnect mid-upload leaves nothing behind either.
pub struct WriteFinalizationWriter<R: oio::Write + 'static> {
    /// `None` once the backend writer has been handed to the finalization task
    /// or aborted.
    inner: Option<R>,
    finalizer: Arc<Finalizer>,
    entry_path: EntryPath,
    metadata_builder: FileMetadataBuilder,
}

impl<R: oio::Write + 'static> WriteFinalizationWriter<R> {
    pub(super) fn new(inner: R, finalizer: Arc<Finalizer>, entry_path: EntryPath) -> Self {
        Self {
            inner: Some(inner),
            finalizer,
            entry_path,
            metadata_builder: FileMetadataBuilder::default(),
        }
    }
}

impl<R: oio::Write + 'static> oio::Write for WriteFinalizationWriter<R> {
    async fn write(&mut self, bs: opendal::Buffer) -> Result<()> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| already_closed("Writer"))?;
        self.metadata_builder.update(&bs.to_vec());
        inner.write(bs).await
    }

    /// After a failed close there is nothing left to abort: the finalization
    /// already discarded the staged bytes if the failure came before
    /// publication, and must not touch them if it came after.
    async fn abort(&mut self) -> Result<()> {
        match self.inner.take() {
            Some(mut inner) => inner.abort().await,
            None => Ok(()),
        }
    }

    /// Publish the staged bytes and commit their entry together. An upload
    /// that fails before publication is aborted here, see [`WriteFailure`].
    async fn close(&mut self) -> Result<opendal::Metadata> {
        let mut inner = self.inner.take().ok_or_else(|| already_closed("Writer"))?;
        self.metadata_builder
            .guess_mime_type_from_path(self.entry_path.path().as_str());
        let file_metadata = self.metadata_builder.clone().finalize();
        let finalizer = self.finalizer.clone();
        let entry_path = self.entry_path.clone();
        spawn_finalization(async move {
            match finalizer
                .finalize_write(&mut inner, &entry_path, &file_metadata)
                .await
            {
                Ok(metadata) => Ok(metadata),
                Err(WriteFailure::BeforePublication(error)) => {
                    abort_unpublished_upload(&mut inner, &entry_path, "rejected").await;
                    Err(error)
                }
                Err(WriteFailure::AfterPublication(error)) => Err(error),
            }
        })
        .await
    }
}

impl<R: oio::Write + 'static> Drop for WriteFinalizationWriter<R> {
    fn drop(&mut self) {
        let Some(mut inner) = self.inner.take() else {
            return;
        };
        let entry_path = self.entry_path.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(path = %entry_path, "No runtime to abort dropped upload on");
            return;
        };
        runtime.spawn(async move {
            abort_unpublished_upload(&mut inner, &entry_path, "dropped").await;
        });
    }
}

/// Discard the staged bytes of an upload that will not be published. The
/// caller reports why, so a failed cleanup is only logged.
async fn abort_unpublished_upload<R: oio::Write>(
    backend_writer: &mut R,
    entry_path: &EntryPath,
    reason: &str,
) {
    if let Err(error) = backend_writer.abort().await {
        tracing::warn!(path = %entry_path, %error, "Failed to abort {reason} upload");
    }
}

/// Which side of publication a finalization failed on. Before it, the staged
/// bytes are still the writer's to abort. After it, the backend has renamed
/// them into place, or may have, so they are the live blob or a leftover that
/// aborting could not reach anyway.
enum WriteFailure {
    BeforePublication(opendal::Error),
    AfterPublication(opendal::Error),
}

impl Finalizer {
    async fn finalize_write<R: oio::Write>(
        &self,
        backend_writer: &mut R,
        entry_path: &EntryPath,
        file_metadata: &FileMetadata,
    ) -> std::result::Result<opendal::Metadata, WriteFailure> {
        let mut tx = self.sql_db.pool().begin().await.map_err(|error| {
            WriteFailure::BeforePublication(unexpected(
                "Failed to begin write finalization transaction",
                error,
            ))
        })?;

        let result = {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            self.write_in_transaction(backend_writer, entry_path, file_metadata, &mut executor)
                .await
        };

        let metadata = match result {
            Ok(metadata) => {
                tx.commit().await.map_err(|error| {
                    WriteFailure::AfterPublication(unexpected(
                        "Failed to commit write finalization",
                        error,
                    ))
                })?;
                metadata
            }
            Err(failure) => {
                if let Err(rollback_error) = tx.rollback().await {
                    tracing::error!(
                        path = %entry_path,
                        error = %rollback_error,
                        "Failed to roll back write finalization transaction"
                    );
                }
                return Err(failure);
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
    ) -> std::result::Result<opendal::Metadata, WriteFailure> {
        let prepared = self
            .prepare_write(entry_path, file_metadata, executor)
            .await
            .map_err(WriteFailure::BeforePublication)?;
        let backend_metadata = backend_writer
            .close()
            .await
            .map_err(WriteFailure::AfterPublication)?;
        self.apply_write_effects(prepared, entry_path, file_metadata, executor)
            .await
            .map_err(WriteFailure::AfterPublication)?;
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
            .update_in_tx(&user, executor)
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

    use pubky_common::crypto::Keypair;
    use tokio::sync::Barrier;

    use crate::persistence::files::FileIoError;
    use crate::persistence::sql::{entry::EntryRepository, SqlDb};
    use crate::services::user_service::FILE_METADATA_SIZE;
    use crate::shared::webdav::{EntryPath, StoragePath};

    use super::super::layer::test_support::{
        all_events, create_user, install_events_insert_trigger, install_slow_event_insert,
        staged_count, test_fs_operator, test_operator, test_user_service, user_usage,
        wait_for_slow_event_insert, wait_for_staged_count, wait_until,
    };
    use super::*;

    /// A caller that disconnects while the write is being finalized drops the
    /// close future. The finalization must still run to completion, or the
    /// published blob and the entry row would disagree.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn write_finalization_completes_after_the_caller_is_dropped() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey, StoragePath::new("/test.txt").unwrap());
        install_slow_event_insert(&db).await;

        let write = {
            let (operator, path) = (operator.clone(), entry_path.as_str().to_string());
            tokio::spawn(async move { operator.write(&path, b"committed".to_vec()).await })
        };
        wait_for_slow_event_insert(&db).await;
        write.abort();
        assert!(write.await.unwrap_err().is_cancelled());

        let entry = wait_for_entry(&db, &entry_path).await;
        assert_eq!(entry.content_length, 9);
        assert_eq!(
            operator.read(entry_path.as_str()).await.unwrap().to_vec(),
            b"committed"
        );
        assert_eq!(all_events(&db).await.len(), 1);
    }

    async fn wait_for_entry(db: &SqlDb, path: &EntryPath) -> EntryEntity {
        wait_until(
            || async {
                EntryRepository::get_by_path(path, &mut db.pool().into())
                    .await
                    .is_ok()
            },
            &format!("entry {path} was never committed"),
        )
        .await;
        EntryRepository::get_by_path(path, &mut db.pool().into())
            .await
            .unwrap()
    }

    /// A writer dropped without being closed or aborted, as a client
    /// disconnect mid-upload does, must discard its staged bytes and leave
    /// the existing file alone.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn dropped_writer_discards_its_staged_upload() {
        let db = SqlDb::test().await;
        let (operator, tmp_dir) = test_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey, StoragePath::new("/test.txt").unwrap());
        operator
            .write(entry_path.as_str(), b"old".to_vec())
            .await
            .unwrap();

        let mut writer = operator.writer(entry_path.as_str()).await.unwrap();
        writer.write(b"partial".to_vec()).await.unwrap();
        assert_eq!(staged_count(&tmp_dir), 1);
        drop(writer);

        // The abort runs on a spawned task.
        wait_for_staged_count(&tmp_dir, 0, "dropped writer left its staged file").await;
        assert_eq!(
            operator.read(entry_path.as_str()).await.unwrap().to_vec(),
            b"old"
        );
    }

    /// Quota is only known once the whole body has streamed. Rejecting it then
    /// must not have touched the existing file.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn quota_rejected_overwrite_leaves_the_old_bytes_and_no_staged_file() {
        let db = SqlDb::test().await;
        let (operator, tmp_dir) = test_fs_operator(&db);
        let pubkey = Keypair::random().public_key();
        test_user_service(&db)
            .create_with_quota_mb(&pubkey, 1)
            .await;
        let entry_path = EntryPath::new(pubkey, StoragePath::new("/test.txt").unwrap());
        operator
            .write(entry_path.as_str(), b"old".to_vec())
            .await
            .unwrap();

        let rejection = operator
            .write(entry_path.as_str(), vec![42u8; 1024 * 1024])
            .await
            .expect_err("the overwrite should exceed the quota");

        assert!(matches!(
            FileIoError::from(rejection),
            FileIoError::DiskSpaceQuotaExceeded
        ));
        assert_eq!(staged_count(&tmp_dir), 0);
        assert_eq!(
            operator.read(entry_path.as_str()).await.unwrap().to_vec(),
            b"old"
        );
    }

    /// The transaction failing to begin happens before the backend publishes,
    /// so the staged bytes must be aborted like a rejected write.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn upload_is_aborted_when_the_transaction_cannot_begin() {
        let db = SqlDb::test().await;
        let (operator, tmp_dir) = test_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey, StoragePath::new("/test.txt").unwrap());

        let mut writer = operator.writer(entry_path.as_str()).await.unwrap();
        writer.write(vec![1; 10]).await.unwrap();
        assert_eq!(staged_count(&tmp_dir), 1);

        db.pool().close().await;

        writer
            .close()
            .await
            .expect_err("closing without a database should fail");
        assert_eq!(staged_count(&tmp_dir), 0);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn event_insert_failure_rolls_back_entry_event_and_quota() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey.clone(), StoragePath::new("/test.txt").unwrap());

        install_events_insert_trigger(
            &db,
            "fail_event_insert",
            "RAISE EXCEPTION 'forced event insert failure';",
        )
        .await;

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
        let ancestor = EntryPath::new(pubkey.clone(), StoragePath::new("/pub/app/foo").unwrap());
        let descendant = EntryPath::new(
            pubkey.clone(),
            StoragePath::new("/pub/app/foo/bar.json").unwrap(),
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
