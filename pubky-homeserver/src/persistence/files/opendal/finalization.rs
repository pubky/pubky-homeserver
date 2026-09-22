use std::future::Future;

use tracing::Instrument;

use super::super::FileIoError;

/// Run a finalization step to completion on its own task, so a request
/// dropped mid-step (a client disconnect) cannot leave the entry row and the
/// blob disagreeing. Why that matters is described in the
/// [`files`](crate::persistence::files) module docs.
///
/// The task runs in the caller's tracing span, so whatever the finalization
/// logs still carries the request's context.
pub(super) async fn spawn_finalization<T: Send + 'static>(
    finalization: impl Future<Output = Result<T, opendal::Error>> + Send + 'static,
) -> Result<T, FileIoError> {
    match tokio::spawn(finalization.in_current_span()).await {
        Ok(result) => Ok(result?),
        Err(error) => Err(FileIoError::OpenDAL(
            opendal::Error::new(
                opendal::ErrorKind::Unexpected,
                "Finalization task did not complete",
            )
            .set_source(error),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;

    use super::super::opendal_service::OpendalService;
    use crate::persistence::files::write_finalization_layer::test_support::{
        all_events, create_user, install_events_insert_trigger, wait_until,
    };
    use crate::persistence::sql::entry::{EntryEntity, EntryRepository};
    use crate::persistence::sql::SqlDb;
    use crate::shared::webdav::{EntryPath, StoragePath};
    use crate::AppContext;

    /// A client that disconnects while the write is being finalized drops the
    /// request future. The finalization must still run to completion, or the
    /// published blob and the entry row would disagree.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn write_finalization_completes_after_the_request_is_dropped() {
        let (_context, db, service, path) = service_with_user().await;
        install_slow_event_insert(&db).await;

        let request = {
            let (service, path) = (service.clone(), path.clone());
            tokio::spawn(async move { service.write(&path, b"committed".to_vec()).await })
        };
        wait_for_active_query(&db, "%INSERT INTO \"events\"%").await;
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());

        let entry = wait_for_entry(&db, &path).await;
        assert_eq!(entry.content_length, 9);
        assert_eq!(
            service.get(&path).await.unwrap(),
            Bytes::from_static(b"committed")
        );
        assert_eq!(all_events(&db).await.len(), 1);
    }

    /// The delete counterpart: the row removal must commit and the blob must
    /// go even though the request was dropped mid-finalization.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn delete_finalization_completes_after_the_request_is_dropped() {
        let (_context, db, service, path) = service_with_user().await;
        service.write(&path, b"doomed".to_vec()).await.unwrap();
        install_slow_event_insert(&db).await;

        let request = {
            let (service, path) = (service.clone(), path.clone());
            tokio::spawn(async move { service.delete(&path).await })
        };
        wait_for_active_query(&db, "%INSERT INTO \"events\"%").await;
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());

        wait_until(
            || async {
                let row_gone = EntryRepository::get_by_path(&path, &mut db.pool().into())
                    .await
                    .is_err();
                row_gone && !service.exists(&path).await.unwrap()
            },
            "the dropped delete never completed",
        )
        .await;
        assert_eq!(all_events(&db).await.len(), 2);
    }

    /// A service on the default test backend, a user, and a file path of theirs.
    async fn service_with_user() -> (Arc<AppContext>, SqlDb, OpendalService, EntryPath) {
        let context = AppContext::test().await;
        let db = context.sql_db.clone();
        let service = OpendalService::new(&context).unwrap();
        let pubkey = create_user(&db).await;
        let path = EntryPath::new(pubkey, StoragePath::new("/pub/test.txt").unwrap());
        (context, db, service, path)
    }

    /// Hold every event insert for a while so a request can be dropped while
    /// its finalization transaction is open.
    async fn install_slow_event_insert(db: &SqlDb) {
        install_events_insert_trigger(db, "slow_event_insert", "PERFORM pg_sleep(1);").await;
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
}
