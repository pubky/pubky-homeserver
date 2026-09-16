use std::sync::Arc;

use crate::persistence::files::{
    events::EventType, layer_domain_error::LayerDomainError, FileMetadata, FileMetadataBuilder,
    WritePreconditions,
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
    layer::{
        check_no_path_collision, is_precondition_failure, precondition_failed_error, unexpected,
        Finalizer,
    },
    resolve_storage_max_bytes,
    verify::blob_fingerprint,
    would_exceed_limit,
};

struct PreparedWrite {
    user: UserEntity,
    existing_entry: Option<EntryEntity>,
    bytes_delta: i64,
    /// Owed by a repair of the existing entry, inserted with the write's own event.
    repair_event: Option<EventType>,
}

/// Database effects of a write that precede the backend publish.
struct StagedWrite {
    entry_id: i64,
    user_id: i32,
    repair_event: Option<EventType>,
}

impl PreparedWrite {
    fn new(
        user: UserEntity,
        existing_entry: Option<EntryEntity>,
        repair_event: Option<EventType>,
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
            repair_event,
        })
    }
}

/// Writer that commits entry metadata, its event, and quota accounting together.
pub struct WriteFinalizationWriter<R> {
    inner: R,
    finalizer: Arc<Finalizer>,
    entry_path: EntryPath,
    preconditions: WritePreconditions,
    metadata_builder: FileMetadataBuilder,
}

impl<R> WriteFinalizationWriter<R> {
    pub(super) fn new(
        inner: R,
        finalizer: Arc<Finalizer>,
        entry_path: EntryPath,
        preconditions: WritePreconditions,
    ) -> Self {
        Self {
            inner,
            finalizer,
            entry_path,
            preconditions,
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
            .finalize_write(
                &mut self.inner,
                &self.entry_path,
                &file_metadata,
                &self.preconditions,
            )
            .await
    }
}

/// Discard staged bytes after a rejected write. Backends without abort support
/// (filesystem without an atomic write dir) have already written in place.
async fn abort_backend_write<R: oio::Write>(backend_writer: &mut R, entry_path: &EntryPath) {
    if let Err(error) = backend_writer.abort().await {
        tracing::debug!(
            path = %entry_path,
            error = %error,
            "Could not abort rejected backend write"
        );
    }
}

impl Finalizer {
    async fn finalize_write<R: oio::Write>(
        &self,
        backend_writer: &mut R,
        entry_path: &EntryPath,
        file_metadata: &FileMetadata,
        preconditions: &WritePreconditions,
    ) -> Result<opendal::Metadata> {
        let mut tx =
            self.sql_db.pool().begin().await.map_err(|error| {
                unexpected("Failed to begin write finalization transaction", error)
            })?;

        let result = {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            self.write_in_transaction(
                backend_writer,
                entry_path,
                file_metadata,
                preconditions,
                &mut executor,
            )
            .await
        };

        let metadata = match result {
            Ok(metadata) => {
                tx.commit()
                    .await
                    .map_err(|error| unexpected("Failed to commit write finalization", error))?;
                metadata
            }
            Err(error) if is_precondition_failure(&error) => {
                // The condition is checked before any write effect, so the
                // transaction holds at most a repair of the entry row. Keep
                // it: the client's next GET must see the repaired ETag.
                tx.commit().await.map_err(|commit_error| {
                    unexpected("Failed to commit entry repair", commit_error)
                })?;
                self.notify_event();
                return Err(error);
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
        preconditions: &WritePreconditions,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<opendal::Metadata> {
        // Order matters here:
        // 1. Entry row and quota, under the per-user lock only. A failure
        //    rolls back with the blob untouched.
        // 2. Backend publish. From here on a failure leaves the blob
        //    published and the row stale; the next conditional write
        //    repairs that.
        // 3. Fingerprint of the published blob.
        // 4. Events, last: their insert takes a homeserver-wide advisory
        //    lock held until commit, which must not span the publish.
        let staged = match self
            .prepare_write(entry_path, file_metadata, preconditions, executor)
            .await
        {
            Ok(prepared) => {
                self.stage_write_effects(prepared, entry_path, file_metadata, executor)
                    .await
            }
            Err(error) => Err(error),
        };
        let staged = match staged {
            Ok(staged) => staged,
            Err(error) => {
                // Nothing has been published yet: discard the staged bytes.
                abort_backend_write(backend_writer, entry_path).await;
                return Err(error);
            }
        };
        let backend_metadata = backend_writer.close().await?;

        // Record the published blob's identity so a later conditional write
        // can trust this row with a `stat` instead of reading the blob.
        // Some backends report it on close, others only on `stat`.
        let fingerprint = match blob_fingerprint(&backend_metadata) {
            Some(fingerprint) => Some(fingerprint),
            None => self.stat_blob_fingerprint(entry_path).await?,
        };
        EntryRepository::set_blob_fingerprint(staged.entry_id, fingerprint.as_deref(), executor)
            .await
            .map_err(|error| {
                unexpected(
                    format!("Failed to record blob fingerprint for {entry_path}"),
                    error,
                )
            })?;

        if let Some(repair_event) = staged.repair_event {
            self.record_event(staged.user_id, repair_event, entry_path, executor)
                .await?;
        }
        self.record_event(
            staged.user_id,
            EventType::Put {
                content_hash: file_metadata.hash,
            },
            entry_path,
            executor,
        )
        .await?;
        Ok(backend_metadata)
    }

    async fn prepare_write(
        &self,
        entry_path: &EntryPath,
        file_metadata: &FileMetadata,
        preconditions: &WritePreconditions,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<PreparedWrite> {
        let mut user = self
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

        // Only a conditional write depends on the row describing the blob,
        // so only then is it verified (and repaired) before the check.
        let (existing_entry, current_hash, repair_event) = match existing_entry {
            Some(entry) if !preconditions.is_empty() => {
                let reconciled = self.reconcile_entry(&mut user, entry, executor).await?;
                (
                    Some(reconciled.entry),
                    reconciled.content_hash,
                    reconciled.event,
                )
            }
            entry => {
                let current_hash = entry.as_ref().map(|entry| entry.content_hash);
                (entry, current_hash, None)
            }
        };

        // Authoritative precondition check: the user row lock above serializes
        // all writes by this user, so the entry cannot change before commit.
        // Nothing but the repair above may precede it: on failure the
        // transaction is committed to keep that repair.
        if !preconditions.is_satisfied_by(current_hash.as_ref()) {
            if let Some(repair_event) = repair_event {
                self.record_event(user.id, repair_event, entry_path, executor)
                    .await?;
            }
            return Err(precondition_failed_error(entry_path));
        }

        PreparedWrite::new(
            user,
            existing_entry,
            repair_event,
            file_metadata,
            self.default_storage_mb,
        )
    }

    /// Entry row and quota for the write. Events are deliberately not
    /// inserted here: see `write_in_transaction`.
    async fn stage_write_effects(
        &self,
        prepared: PreparedWrite,
        entry_path: &EntryPath,
        file_metadata: &FileMetadata,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<StagedWrite> {
        let PreparedWrite {
            mut user,
            existing_entry,
            bytes_delta,
            repair_event,
        } = prepared;
        let entry_id = match existing_entry {
            Some(mut entry) => {
                entry.content_hash = file_metadata.hash;
                entry.content_length = file_metadata.length as u64;
                entry.content_type = file_metadata.content_type.clone();
                EntryRepository::update(&entry, executor)
                    .await
                    .map(|()| entry.id)
            }
            None => {
                EntryRepository::create(
                    user.id,
                    entry_path.path(),
                    &file_metadata.hash,
                    file_metadata.length as u64,
                    &file_metadata.content_type,
                    executor,
                )
                .await
            }
        }
        .map_err(|error| unexpected(format!("Failed to write entry {}", entry_path), error))?;
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

        Ok(StagedWrite {
            entry_id,
            user_id: user.id,
            repair_event,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::sync::Barrier;

    use crate::persistence::files::{content_hash_etag, FileIoError};
    use crate::persistence::sql::{entry::EntryRepository, SqlDb};
    use crate::services::user_service::FILE_METADATA_SIZE;
    use crate::shared::webdav::{EntryPath, StoragePath};

    use super::super::layer::test_support::{
        all_events, create_user, test_fs_operator, test_operator, user_usage,
    };
    use super::*;

    /// Open a writer carrying `preconditions`, mirroring `OpendalService::write_stream`.
    async fn conditional_writer(
        operator: &opendal::Operator,
        path: &EntryPath,
        preconditions: &WritePreconditions,
    ) -> Result<opendal::Writer> {
        let mut writer = operator.writer_with(path.as_str());
        if let Some(if_match) = preconditions.if_match_header() {
            writer = writer.if_match(&if_match);
        }
        if let Some(if_none_match) = preconditions.if_none_match_header() {
            writer = writer.if_none_match(&if_none_match);
        }
        writer.await
    }

    async fn conditional_write(
        operator: &opendal::Operator,
        path: &EntryPath,
        content: Vec<u8>,
        preconditions: &WritePreconditions,
    ) -> Result<()> {
        let mut writer = conditional_writer(operator, path, preconditions).await?;
        writer.write(content).await?;
        writer.close().await.map(|_| ())
    }

    async fn current_etag(db: &SqlDb, path: &EntryPath) -> String {
        let entry = EntryRepository::get_by_path(path, &mut db.pool().into())
            .await
            .unwrap();
        content_hash_etag(&entry.content_hash)
    }

    fn if_match(etag: &str) -> WritePreconditions {
        WritePreconditions::parse(Some(etag), None).unwrap()
    }

    fn if_none_match(etag: &str) -> WritePreconditions {
        WritePreconditions::parse(None, Some(etag)).unwrap()
    }

    fn assert_precondition_failed(error: opendal::Error) {
        assert!(matches!(
            FileIoError::from(error),
            FileIoError::PreconditionFailed
        ));
    }

    /// `opendal::Writer` is not `Debug`, so `expect_err` cannot be used on it.
    fn writer_error(result: Result<opendal::Writer>, context: &str) -> opendal::Error {
        match result {
            Ok(_) => panic!("{context}"),
            Err(error) => error,
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn if_match_with_current_etag_replaces_content() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test.txt").unwrap());

        operator.write(path.as_str(), vec![1; 10]).await.unwrap();
        let etag = current_etag(&db, &path).await;

        conditional_write(&operator, &path, vec![2; 20], &if_match(&etag))
            .await
            .unwrap();

        assert_eq!(
            operator.read(path.as_str()).await.unwrap().to_vec(),
            vec![2; 20]
        );
        assert_ne!(current_etag(&db, &path).await, etag);
        assert_eq!(user_usage(&db, &pubkey).await, 20 + FILE_METADATA_SIZE);
        assert_eq!(all_events(&db).await.len(), 2);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn stale_if_match_is_rejected_before_any_bytes_are_accepted() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test.txt").unwrap());

        operator.write(path.as_str(), vec![1; 10]).await.unwrap();

        let error = writer_error(
            conditional_writer(&operator, &path, &if_match("\"stale\"")).await,
            "stale If-Match must fail at writer creation",
        );
        assert_precondition_failed(error);

        let missing = EntryPath::new(pubkey.clone(), StoragePath::new("/missing.txt").unwrap());
        let error = writer_error(
            conditional_writer(&operator, &missing, &if_match("*")).await,
            "If-Match: * must fail for a missing path",
        );
        assert_precondition_failed(error);

        assert_eq!(
            operator.read(path.as_str()).await.unwrap().to_vec(),
            vec![1; 10]
        );
        assert_eq!(user_usage(&db, &pubkey).await, 10 + FILE_METADATA_SIZE);
        assert_eq!(all_events(&db).await.len(), 1);
    }

    /// The memory backend advertises no conditional write support, so this
    /// also proves conditions are stripped before reaching the backend.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn if_none_match_star_creates_only_when_absent() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test.txt").unwrap());

        conditional_write(&operator, &path, vec![1; 10], &if_none_match("*"))
            .await
            .unwrap();

        let error = writer_error(
            conditional_writer(&operator, &path, &if_none_match("*")).await,
            "second create-only write must fail",
        );
        assert_precondition_failed(error);

        assert_eq!(
            operator.read(path.as_str()).await.unwrap().to_vec(),
            vec![1; 10]
        );
        assert_eq!(all_events(&db).await.len(), 1);
    }

    /// A writer whose condition held when it was opened must still be rejected
    /// if the entry changes before it closes, and the winning content must be
    /// left untouched. Runs on the memory backend and on the staged filesystem
    /// backend, where the rejected upload's temp file must also be cleaned up.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn precondition_is_rechecked_under_the_user_lock_before_publish() {
        let db = SqlDb::test().await;
        let (fs_operator, fs_dir) = test_fs_operator(&db);
        let staging_dir = fs_dir.path().join("files-tmp");

        for operator in [test_operator(&db), fs_operator] {
            let pubkey = create_user(&db).await;
            let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test.txt").unwrap());

            operator.write(path.as_str(), vec![1; 10]).await.unwrap();
            let etag_v1 = current_etag(&db, &path).await;

            // Condition holds at open time...
            let mut stale_writer = conditional_writer(&operator, &path, &if_match(&etag_v1))
                .await
                .unwrap();
            stale_writer.write(vec![3; 30]).await.unwrap();

            // ...but another write lands before it closes.
            operator.write(path.as_str(), vec![2; 20]).await.unwrap();

            let error = stale_writer
                .close()
                .await
                .expect_err("close must re-check the condition");
            assert_precondition_failed(error);

            assert_eq!(
                operator.read(path.as_str()).await.unwrap().to_vec(),
                vec![2; 20]
            );
            assert_eq!(user_usage(&db, &pubkey).await, 20 + FILE_METADATA_SIZE);
            let put_events = all_events(&db)
                .await
                .into_iter()
                .filter(|event| event.path == path)
                .count();
            assert_eq!(put_events, 2);
        }

        let staged: Vec<_> = std::fs::read_dir(&staging_dir).unwrap().collect();
        assert!(
            staged.is_empty(),
            "rejected upload must not leak a staged file: {staged:?}"
        );
    }

    async fn install_failing_trigger(db: &SqlDb, table: &str, operation: &str) {
        sqlx::query(&format!(
            r#"
            CREATE FUNCTION fail_{table}_{operation}() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'forced {table} {operation} failure';
            END;
            $$ LANGUAGE plpgsql
            "#
        ))
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(&format!(
            "CREATE TRIGGER fail_{table}_{operation}_trigger BEFORE {operation} ON {table} \
             FOR EACH ROW EXECUTE FUNCTION fail_{table}_{operation}()"
        ))
        .execute(db.pool())
        .await
        .unwrap();
    }

    fn assert_staging_empty(dir: &tempfile::TempDir) {
        let staged: Vec<_> = std::fs::read_dir(dir.path().join("files-tmp"))
            .unwrap()
            .collect();
        assert!(staged.is_empty(), "upload leaked a staged file: {staged:?}");
    }

    /// A failure before the publish rolls back everything and leaves the
    /// previous content in place, with the rejected upload's staged file
    /// removed.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn entry_update_failure_rolls_back_without_publishing_the_blob() {
        let db = SqlDb::test().await;
        let (operator, dir) = test_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey.clone(), StoragePath::new("/test.txt").unwrap());

        operator
            .write(entry_path.as_str(), vec![1; 10])
            .await
            .unwrap();
        let etag_v1 = current_etag(&db, &entry_path).await;
        install_failing_trigger(&db, "entries", "UPDATE").await;

        operator
            .write(entry_path.as_str(), vec![2; 20])
            .await
            .expect_err("forced entry update failure should fail the write");

        assert_eq!(current_etag(&db, &entry_path).await, etag_v1);
        assert_eq!(
            operator.read(entry_path.as_str()).await.unwrap().to_vec(),
            vec![1; 10]
        );
        assert_eq!(user_usage(&db, &pubkey).await, 10 + FILE_METADATA_SIZE);
        assert_eq!(all_events(&db).await.len(), 1);
        assert_staging_empty(&dir);
    }

    /// Events are inserted after the publish, so a failed event insert
    /// leaves the blob published and the row stale. That is the state the
    /// next conditional write must detect and repair.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn event_insert_failure_leaves_a_stale_row_that_a_conditional_write_repairs() {
        let db = SqlDb::test().await;
        let (operator, dir) = test_fs_operator(&db);
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey.clone(), StoragePath::new("/test.txt").unwrap());

        operator
            .write(entry_path.as_str(), vec![1; 10])
            .await
            .unwrap();
        let etag_v1 = current_etag(&db, &entry_path).await;
        install_failing_trigger(&db, "events", "INSERT").await;

        operator
            .write(entry_path.as_str(), vec![2; 20])
            .await
            .expect_err("forced event failure should fail the write");

        // Published, but the row still describes v1.
        assert_eq!(
            operator.read(entry_path.as_str()).await.unwrap().to_vec(),
            vec![2; 20]
        );
        assert_eq!(current_etag(&db, &entry_path).await, etag_v1);
        assert_eq!(user_usage(&db, &pubkey).await, 10 + FILE_METADATA_SIZE);
        assert_eq!(all_events(&db).await.len(), 1);
        assert_staging_empty(&dir);

        // The stale tag must not win against the real content, and the
        // repair must be kept even though the write is rejected.
        sqlx::query("DROP TRIGGER fail_events_INSERT_trigger ON events")
            .execute(db.pool())
            .await
            .unwrap();
        let error = conditional_write(&operator, &entry_path, vec![3; 30], &if_match(&etag_v1))
            .await
            .expect_err("stale tag must be rejected");
        assert_precondition_failed(error);

        assert_eq!(
            current_etag(&db, &entry_path).await,
            content_hash_etag(&pubky_common::crypto::hash(&[2; 20]))
        );
        assert_eq!(user_usage(&db, &pubkey).await, 20 + FILE_METADATA_SIZE);
        assert_eq!(all_events(&db).await.len(), 2);
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

/// Proves the ordering in `write_in_transaction`: one user's slow backend
/// publish must not hold the homeserver-wide event lock and stall everyone
/// else's writes.
#[cfg(test)]
mod publish_overlap_tests {
    use std::{sync::Arc, time::Duration};

    use opendal::raw::{
        oio, Access, Layer, LayeredAccess, OpList, OpRead, OpWrite, RpDelete, RpList, RpRead,
        RpWrite,
    };
    use opendal::Result;
    use tokio::sync::Notify;

    use crate::persistence::files::{events::EventsService, opendal::opendal_test_operators};
    use crate::persistence::sql::SqlDb;
    use crate::services::user_service::UserService;
    use crate::shared::webdav::{EntryPath, StoragePath};

    use super::super::layer::test_support::{all_events, create_user};
    use super::super::WriteFinalizationLayer;

    /// Blocks the close of one path until released, and reports when it is
    /// blocked. Sits beneath the finalization layer, where the backend would.
    #[derive(Debug, Clone)]
    struct BlockingCloseLayer {
        path: String,
        blocked: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl<A: Access> Layer<A> for BlockingCloseLayer {
        type LayeredAccess = BlockingCloseAccessor<A>;

        fn layer(&self, inner: A) -> Self::LayeredAccess {
            BlockingCloseAccessor {
                inner,
                layer: self.clone(),
            }
        }
    }

    #[derive(Debug)]
    struct BlockingCloseAccessor<A> {
        inner: A,
        layer: BlockingCloseLayer,
    }

    impl<A: Access> LayeredAccess for BlockingCloseAccessor<A> {
        type Inner = A;
        type Reader = A::Reader;
        type Writer = BlockingCloseWriter<A::Writer>;
        type Lister = A::Lister;
        type Deleter = A::Deleter;
        type Copier = A::Copier;

        fn inner(&self) -> &Self::Inner {
            &self.inner
        }

        async fn read(&self, path: &str, args: OpRead) -> Result<(RpRead, Self::Reader)> {
            self.inner.read(path, args).await
        }

        async fn write(&self, path: &str, args: OpWrite) -> Result<(RpWrite, Self::Writer)> {
            let (rp, inner) = self.inner.write(path, args).await?;
            let gate = (path == self.layer.path)
                .then(|| (self.layer.blocked.clone(), self.layer.release.clone()));
            Ok((rp, BlockingCloseWriter { inner, gate }))
        }

        async fn list(&self, path: &str, args: OpList) -> Result<(RpList, Self::Lister)> {
            self.inner.list(path, args).await
        }

        async fn delete(&self) -> Result<(RpDelete, Self::Deleter)> {
            self.inner.delete().await
        }
    }

    struct BlockingCloseWriter<W> {
        inner: W,
        gate: Option<(Arc<Notify>, Arc<Notify>)>,
    }

    impl<W: oio::Write> oio::Write for BlockingCloseWriter<W> {
        async fn write(&mut self, bs: opendal::Buffer) -> Result<()> {
            self.inner.write(bs).await
        }

        async fn abort(&mut self) -> Result<()> {
            self.inner.abort().await
        }

        async fn close(&mut self) -> Result<opendal::Metadata> {
            if let Some((blocked, release)) = self.gate.take() {
                blocked.notify_one();
                release.notified().await;
            }
            self.inner.close().await
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_slow_publish_for_one_user_does_not_block_other_users() {
        let db = SqlDb::test().await;
        let slow_user = create_user(&db).await;
        let other_user = create_user(&db).await;
        let slow_path = EntryPath::new(slow_user, StoragePath::new("/slow.txt").unwrap());
        let other_path = EntryPath::new(other_user, StoragePath::new("/quick.txt").unwrap());

        let blocked = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let operator = opendal_test_operators::get_memory_operator()
            .layer(BlockingCloseLayer {
                path: slow_path.as_str().to_string(),
                blocked: blocked.clone(),
                release: release.clone(),
            })
            .layer(WriteFinalizationLayer::new(
                UserService::new(db.clone()),
                db.clone(),
                EventsService::new(db.clone(), 100),
                None,
                true,
            ));

        let slow_operator = operator.clone();
        let slow_write =
            tokio::spawn(async move { slow_operator.write(slow_path.as_str(), vec![1; 10]).await });
        blocked.notified().await;

        // The slow write is inside its finalization transaction with its
        // publish stalled. Another user's write must still get through.
        tokio::time::timeout(
            Duration::from_secs(5),
            operator.write(other_path.as_str(), vec![2; 20]),
        )
        .await
        .expect("another user's write must not wait on a stalled publish")
        .unwrap();

        release.notify_one();
        slow_write.await.unwrap().unwrap();
        assert_eq!(all_events(&db).await.len(), 2);
    }
}
