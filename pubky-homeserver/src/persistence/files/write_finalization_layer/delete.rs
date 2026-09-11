use std::{mem::take, sync::Arc};

use crate::persistence::files::{events::EventType, WritePreconditions};
use crate::persistence::sql::{
    entry::{EntryEntity, EntryRepository},
    user::UserEntity,
    UnifiedExecutor,
};
use crate::services::user_service::FILE_METADATA_SIZE;
use crate::shared::webdav::EntryPath;
use opendal::raw::{oio, OpDelete};
use opendal::{Error, Result};

use super::layer::{precondition_failed_error, unexpected, Finalizer};

struct StagedDelete {
    user: UserEntity,
    deleted_entry: EntryEntity,
}

struct PendingDelete {
    entry_path: EntryPath,
    preconditions: WritePreconditions,
}

#[derive(Default)]
struct DeleteQueueOutcome {
    should_notify: bool,
    first_error: Option<Error>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeleteOutcome {
    Deleted,
    NotFound,
}

/// Deleter that commits entry deletion, its event, and quota accounting together.
pub struct WriteFinalizationDeleter<R> {
    inner: R,
    finalizer: Arc<Finalizer>,
    delete_queue: Vec<PendingDelete>,
}

impl<R> WriteFinalizationDeleter<R> {
    pub(super) fn new(inner: R, finalizer: Arc<Finalizer>) -> Self {
        Self {
            inner,
            finalizer,
            delete_queue: Vec::new(),
        }
    }
}

impl<R: oio::Delete> WriteFinalizationDeleter<R> {
    async fn process_delete_queue(&mut self) -> DeleteQueueOutcome {
        let mut outcome = DeleteQueueOutcome::default();
        let mut failed_deletes = Vec::new();

        for pending in take(&mut self.delete_queue) {
            match self.finalize_and_queue_blob_delete(&pending).await {
                Ok(DeleteOutcome::Deleted) => outcome.should_notify = true,
                Ok(DeleteOutcome::NotFound) => {}
                Err(error) => {
                    failed_deletes.push(pending);
                    outcome.first_error.get_or_insert(error);
                }
            }
        }
        self.delete_queue = failed_deletes;

        outcome
    }

    async fn finalize_and_queue_blob_delete(
        &mut self,
        pending: &PendingDelete,
    ) -> Result<DeleteOutcome> {
        // Only forward the blob delete after its database finalization succeeds.
        let outcome = match self
            .finalizer
            .finalize_delete(&pending.entry_path, &pending.preconditions)
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::error!(
                    path = %pending.entry_path,
                    error = %error,
                    "Failed to finalize deleted path"
                );
                return Err(error);
            }
        };

        // The condition was consumed above; the backend gets a plain delete.
        self.inner
            .delete(pending.entry_path.as_str(), OpDelete::default())
            .map_err(|error| {
                tracing::error!(
                    path = %pending.entry_path,
                    error = %error,
                    "Failed to queue finalized path for blob deletion"
                );
                error
            })?;

        Ok(outcome)
    }

    async fn flush_blob_deletes(&mut self, earlier_error: Option<Error>) -> Result<usize> {
        let flush_result = self.inner.flush().await;
        match (earlier_error, flush_result) {
            (Some(error), Err(flush_error)) => {
                tracing::error!(
                    error = %flush_error,
                    "Failed to flush blob deletions after an earlier delete error"
                );
                Err(error)
            }
            (Some(error), Ok(_)) => Err(error),
            (None, result) => result,
        }
    }
}

impl<R: oio::Delete> oio::Delete for WriteFinalizationDeleter<R> {
    /// A delete `version`, the only argument a delete op carries, is read as
    /// the `If-Match` condition for this path (see `OpendalService::delete`).
    fn delete(&mut self, path: &str, args: OpDelete) -> Result<()> {
        let entry_path = EntryPath::parse_opendal(path)?;
        let preconditions = WritePreconditions::parse(args.version(), None).map_err(|error| {
            unexpected(
                format!("Invalid delete precondition for {entry_path}"),
                error,
            )
        })?;
        self.delete_queue.push(PendingDelete {
            entry_path,
            preconditions,
        });
        Ok(())
    }

    async fn flush(&mut self) -> Result<usize> {
        let outcome = self.process_delete_queue().await;

        if outcome.should_notify {
            self.finalizer.notify_event();
        }

        self.flush_blob_deletes(outcome.first_error).await
    }
}

impl Finalizer {
    async fn finalize_delete(
        &self,
        entry_path: &EntryPath,
        preconditions: &WritePreconditions,
    ) -> Result<DeleteOutcome> {
        let mut tx = self.sql_db.pool().begin().await.map_err(|error| {
            unexpected("Failed to begin delete finalization transaction", error)
        })?;

        let result = {
            let mut executor = UnifiedExecutor::from_tx(&mut tx);
            self.delete_in_transaction(entry_path, preconditions, &mut executor)
                .await
        };

        match result {
            Ok(DeleteOutcome::Deleted) => {
                tx.commit()
                    .await
                    .map_err(|error| unexpected("Failed to commit delete finalization", error))?;
                Ok(DeleteOutcome::Deleted)
            }
            Ok(DeleteOutcome::NotFound) => {
                tx.rollback()
                    .await
                    .map_err(|error| unexpected("Failed to roll back empty delete", error))?;
                Ok(DeleteOutcome::NotFound)
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

    async fn delete_in_transaction(
        &self,
        entry_path: &EntryPath,
        preconditions: &WritePreconditions,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<DeleteOutcome> {
        let Some(staged) = self
            .stage_delete(entry_path, preconditions, executor)
            .await?
        else {
            return Ok(DeleteOutcome::NotFound);
        };
        self.apply_delete_effects(staged, entry_path, executor)
            .await?;
        Ok(DeleteOutcome::Deleted)
    }

    async fn stage_delete(
        &self,
        entry_path: &EntryPath,
        preconditions: &WritePreconditions,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<Option<StagedDelete>> {
        let user = match self
            .user_service
            .get_for_no_key_update(entry_path.pubkey(), executor)
            .await
        {
            Ok(user) => Some(user),
            Err(sqlx::Error::RowNotFound) => None,
            Err(error) => {
                return Err(unexpected(
                    format!("Failed to lock user {}", entry_path.pubkey()),
                    error,
                ));
            }
        };

        let existing_entry = match user {
            Some(_) => match EntryRepository::get_by_path(entry_path, executor).await {
                Ok(entry) => Some(entry),
                Err(sqlx::Error::RowNotFound) => None,
                Err(error) => {
                    return Err(unexpected(
                        format!("Failed to delete entry {entry_path}"),
                        error,
                    ));
                }
            },
            None => None,
        };

        // Checked under the user lock, like writes. A missing entry fails
        // `If-Match` (RFC 9110 §13.1.1) rather than being a silent no-op.
        if !preconditions.is_satisfied_by(existing_entry.as_ref().map(|entry| &entry.content_hash))
        {
            return Err(precondition_failed_error(entry_path));
        }

        let (Some(user), Some(deleted_entry)) = (user, existing_entry) else {
            return Ok(None);
        };
        EntryRepository::delete(deleted_entry.id, executor)
            .await
            .map_err(|error| unexpected(format!("Failed to delete entry {entry_path}"), error))?;

        Ok(Some(StagedDelete {
            user,
            deleted_entry,
        }))
    }

    async fn apply_delete_effects(
        &self,
        staged: StagedDelete,
        entry_path: &EntryPath,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<()> {
        let StagedDelete {
            mut user,
            deleted_entry,
        } = staged;
        self.events_service
            .create_event(user.id, EventType::Delete, entry_path, executor)
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
    use std::sync::Arc;

    use opendal::raw::oio::Delete;
    use tokio::sync::Barrier;

    use crate::persistence::files::{
        content_hash_etag, events::EventType, FileIoError, WritePreconditions,
    };
    use crate::persistence::sql::{entry::EntryRepository, SqlDb};
    use crate::services::user_service::FILE_METADATA_SIZE;
    use crate::shared::webdav::{EntryPath, StoragePath};

    use super::super::layer::test_support::{
        all_events, create_user, test_finalizer, test_operator, user_usage,
    };
    use super::*;

    /// Delete carrying an `If-Match` condition, mirroring `OpendalService::delete`.
    async fn delete_if_match(
        operator: &opendal::Operator,
        path: &EntryPath,
        if_match: &str,
    ) -> Result<()> {
        operator.delete_with(path.as_str()).version(if_match).await
    }

    async fn current_etag(db: &SqlDb, path: &EntryPath) -> String {
        let entry = EntryRepository::get_by_path(path, &mut db.pool().into())
            .await
            .unwrap();
        content_hash_etag(&entry.content_hash)
    }

    fn assert_precondition_failed(error: opendal::Error) {
        assert!(matches!(
            FileIoError::from(error),
            FileIoError::PreconditionFailed
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn if_match_delete_removes_only_the_matching_version() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/test.txt").unwrap());

        operator.write(path.as_str(), vec![1; 10]).await.unwrap();
        let etag = current_etag(&db, &path).await;

        let error = delete_if_match(&operator, &path, "\"stale\"")
            .await
            .expect_err("stale If-Match must not delete");
        assert_precondition_failed(error);
        assert_eq!(
            operator.read(path.as_str()).await.unwrap().to_vec(),
            vec![1; 10],
            "rejected delete must leave the blob"
        );
        EntryRepository::get_by_path(&path, &mut db.pool().into())
            .await
            .expect("rejected delete must leave the entry");
        assert_eq!(user_usage(&db, &pubkey).await, 10 + FILE_METADATA_SIZE);
        assert_eq!(all_events(&db).await.len(), 1);

        delete_if_match(&operator, &path, &etag).await.unwrap();
        EntryRepository::get_by_path(&path, &mut db.pool().into())
            .await
            .expect_err("matching If-Match must delete the entry");
        assert!(!operator.exists(path.as_str()).await.unwrap());
        assert_eq!(user_usage(&db, &pubkey).await, 0);
        assert_eq!(
            all_events(&db).await.last().unwrap().event_type,
            EventType::Delete
        );
    }

    /// Unconditional deletes of a missing path are a no-op, but `If-Match`
    /// requires a current representation (RFC 9110 §13.1.1).
    ///
    /// Over HTTP a plainly missing file is 404 before this check runs (RFC
    /// 9110 §13.2.1: preconditions are ignored when the unconditional response
    /// would not be 2xx). This branch is reached when the file vanished
    /// between the route's existence check and taking the user lock.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn if_match_delete_of_a_missing_path_fails() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let path = EntryPath::new(pubkey.clone(), StoragePath::new("/missing.txt").unwrap());

        operator.delete(path.as_str()).await.unwrap();

        let error = delete_if_match(&operator, &path, "\"any\"")
            .await
            .expect_err("If-Match on a missing path must fail");
        assert_precondition_failed(error);
        let error = delete_if_match(&operator, &path, "*")
            .await
            .expect_err("If-Match: * on a missing path must fail");
        assert_precondition_failed(error);
        assert!(all_events(&db).await.is_empty());
    }

    #[derive(Default)]
    struct BatchDelete {
        queued_paths: Vec<String>,
        flushed_paths: Vec<String>,
    }

    impl oio::Delete for BatchDelete {
        fn delete(&mut self, path: &str, _args: OpDelete) -> Result<()> {
            self.queued_paths.push(path.to_string());
            Ok(())
        }

        async fn flush(&mut self) -> Result<usize> {
            let queued_paths = std::mem::take(&mut self.queued_paths);
            let deleted = queued_paths.len();
            self.flushed_paths.extend(queued_paths);
            Ok(deleted)
        }
    }

    async fn fail_all_delete_event_inserts(db: &SqlDb) {
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
    }

    async fn fail_delete_event_inserts_for_failing_path(db: &SqlDb) {
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
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn deleting_without_an_entry_does_not_emit_an_event() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let missing_path =
            EntryPath::new(pubkey.clone(), StoragePath::new("/missing.txt").unwrap());

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
        let deleted_path =
            EntryPath::new(pubkey.clone(), StoragePath::new("/deleted.txt").unwrap());
        let retained_path =
            EntryPath::new(pubkey.clone(), StoragePath::new("/retained.txt").unwrap());

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
            first_finalizer
                .finalize_delete(&first_path, &WritePreconditions::default())
                .await
        };
        let second = async move {
            second_barrier.wait().await;
            second_finalizer
                .finalize_delete(&second_path, &WritePreconditions::default())
                .await
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
    async fn delete_finalization_failure_preserves_blob_and_database_state() {
        let db = SqlDb::test().await;
        let operator = test_operator(&db);
        let pubkey = create_user(&db).await;
        let entry_path = EntryPath::new(pubkey.clone(), StoragePath::new("/test.txt").unwrap());
        let content = vec![1; 10];

        operator
            .write(entry_path.as_str(), content.clone())
            .await
            .unwrap();
        let usage_before_delete = user_usage(&db, &pubkey).await;

        fail_all_delete_event_inserts(&db).await;

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
        let failing_path =
            EntryPath::new(pubkey.clone(), StoragePath::new("/failing.txt").unwrap());
        let succeeding_path =
            EntryPath::new(pubkey.clone(), StoragePath::new("/succeeding.txt").unwrap());

        operator
            .write(failing_path.as_str(), vec![1; 10])
            .await
            .unwrap();
        operator
            .write(succeeding_path.as_str(), vec![2; 20])
            .await
            .unwrap();

        fail_delete_event_inserts_for_failing_path(&db).await;

        let mut deleter =
            WriteFinalizationDeleter::new(BatchDelete::default(), Arc::new(test_finalizer(&db)));
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
        assert_eq!(
            deleter.inner.flushed_paths,
            vec![succeeding_path.as_str().to_string()],
            "successfully finalized paths should still be deleted from the backend"
        );
    }
}
