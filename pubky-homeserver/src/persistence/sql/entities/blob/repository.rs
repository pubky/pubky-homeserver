use crate::persistence::sql::UnifiedExecutor;
use sqlx::{Postgres, Transaction};

pub(crate) const UPLOAD_TIMEOUT_SECONDS: u64 = 60 * 60;
const UPLOAD_SETTLE_SECONDS: i64 = 5 * 60;

/// Tracks uploads and unreferenced immutable blobs until publication or cleanup.
pub struct BlobRepository;

impl BlobRepository {
    pub async fn stage_upload(
        blob_key: &str,
        user_id: i32,
        content_length: u64,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO unreferenced_blobs (blob_key, user_id, content_length, state, eligible_at) \
             VALUES ($1, $2, $3, 'uploading', statement_timestamp() + ($4 * INTERVAL '1 second'))",
        )
        .bind(blob_key)
        .bind(user_id)
        .bind(content_length as i64)
        .bind(UPLOAD_TIMEOUT_SECONDS as i64 + UPLOAD_SETTLE_SECONDS)
        .execute(executor.get_con().await?)
        .await?;
        Ok(())
    }

    /// Consume upload ownership inside the transaction publishing its logical entry.
    pub async fn activate_upload(
        blob_key: &str,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<(), sqlx::Error> {
        let con = executor.get_con().await?;
        // Check time after taking the row lock: cleanup may have held it past expiry.
        sqlx::query("SELECT blob_key FROM unreferenced_blobs WHERE blob_key = $1 FOR UPDATE")
            .bind(blob_key)
            .fetch_optional(&mut *con)
            .await?;
        let activated = sqlx::query_scalar::<_, String>(
            "DELETE FROM unreferenced_blobs \
             WHERE blob_key = $1 AND state = 'uploading' \
               AND eligible_at > clock_timestamp() + ($2 * INTERVAL '1 second') \
             RETURNING blob_key",
        )
        .bind(blob_key)
        .bind(UPLOAD_SETTLE_SECONDS)
        .fetch_optional(con)
        .await?;
        activated.map(|_| ()).ok_or(sqlx::Error::RowNotFound)
    }

    /// Retain cleanup tracking even if an interrupted backend write finishes late.
    pub async fn abandon_upload(
        blob_key: &str,
        user_id: i32,
        content_length: u64,
        delay_seconds: i64,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO unreferenced_blobs (blob_key, user_id, content_length, state, eligible_at) \
             VALUES ($1, $2, $3, 'garbage', statement_timestamp() + ($4 * INTERVAL '1 second')) \
             ON CONFLICT (blob_key) DO UPDATE SET \
               user_id = EXCLUDED.user_id, \
               content_length = GREATEST(unreferenced_blobs.content_length, EXCLUDED.content_length), \
               state = 'garbage', \
               eligible_at = GREATEST(unreferenced_blobs.eligible_at, EXCLUDED.eligible_at)",
        )
        .bind(blob_key)
        .bind(user_id)
        .bind(content_length as i64)
        .bind(delay_seconds)
        .execute(executor.get_con().await?)
        .await?;
        Ok(())
    }

    /// Retain replaced or deleted content for reads, unless quota pressure reclaims it.
    pub async fn enqueue_garbage(
        blob_key: &str,
        user_id: i32,
        content_length: u64,
        delay_seconds: i64,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO unreferenced_blobs (blob_key, user_id, content_length, state, eligible_at) \
             VALUES ($1, $2, $3, 'retained', statement_timestamp() + ($4 * INTERVAL '1 second')) \
             ON CONFLICT (blob_key) DO UPDATE SET \
               eligible_at = GREATEST(unreferenced_blobs.eligible_at, EXCLUDED.eligible_at)",
        )
        .bind(blob_key)
        .bind(user_id)
        .bind(content_length as i64)
        .bind(delay_seconds)
        .execute(executor.get_con().await?)
        .await?;
        Ok(())
    }

    /// Queue backend objects with no logical entry or pending upload.
    pub async fn enqueue_untracked_blobs(
        blob_keys: &[String],
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<u64, sqlx::Error> {
        if blob_keys.is_empty() {
            return Ok(0);
        }
        let result = sqlx::query(
            "INSERT INTO unreferenced_blobs (blob_key, user_id, content_length, state, eligible_at) \
             SELECT candidate.blob_key, NULL, 0, 'garbage', statement_timestamp() \
             FROM UNNEST($1::TEXT[]) AS candidate(blob_key) \
             WHERE NOT EXISTS (SELECT 1 FROM entries WHERE entries.blob_key = candidate.blob_key) \
               AND NOT EXISTS (SELECT 1 FROM unreferenced_blobs WHERE blob_key = candidate.blob_key) \
             ON CONFLICT (blob_key) DO NOTHING",
        )
        .bind(blob_keys)
        .execute(executor.get_con().await?)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn tracked_bytes_for_user(
        user_id: i32,
        minimum_blob_bytes: u64,
        executor: &mut UnifiedExecutor<'_>,
    ) -> Result<u64, sqlx::Error> {
        let total: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(GREATEST(content_length, $2)), 0)::BIGINT \
             FROM unreferenced_blobs WHERE user_id = $1",
        )
        .bind(user_id)
        .bind(minimum_blob_bytes as i64)
        .fetch_one(executor.get_con().await?)
        .await?;
        Ok(total.max(0) as u64)
    }

    /// Lock one cleanup batch until its backend deletions have been acknowledged.
    pub async fn lock_garbage(
        limit: i64,
        quota_user_id: Option<i32>,
        tx: &mut Transaction<'static, Postgres>,
    ) -> Result<Vec<String>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT blob_key FROM unreferenced_blobs \
             WHERE (eligible_at <= statement_timestamp() OR ($2::INTEGER IS NOT NULL AND state = 'retained')) \
               AND ($2::INTEGER IS NULL OR user_id = $2) \
             ORDER BY eligible_at, blob_key LIMIT $1 FOR UPDATE SKIP LOCKED",
        )
        .bind(limit)
        .bind(quota_user_id)
        .fetch_all(&mut **tx)
        .await
    }

    pub async fn finish_garbage(
        blob_key: &str,
        tx: &mut Transaction<'static, Postgres>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM unreferenced_blobs WHERE blob_key = $1")
            .bind(blob_key)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    /// Failed deletes respect backoff, including during quota-pressure cleanup.
    pub async fn defer_garbage(
        blob_key: &str,
        retry_delay_seconds: i64,
        tx: &mut Transaction<'static, Postgres>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE unreferenced_blobs SET state = 'garbage', \
             eligible_at = statement_timestamp() + ($2 * INTERVAL '1 second') WHERE blob_key = $1",
        )
        .bind(blob_key)
        .bind(retry_delay_seconds)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::SqlDb;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_cleanup_locks_are_released_on_rollback() {
        let db = SqlDb::test().await;
        BlobRepository::enqueue_garbage("old", 1, 10, 0, &mut db.pool().into())
            .await
            .unwrap();
        let mut first = db.pool().begin().await.unwrap();
        assert_eq!(
            BlobRepository::lock_garbage(64, None, &mut first)
                .await
                .unwrap(),
            ["old"]
        );
        let mut second = db.pool().begin().await.unwrap();
        assert!(BlobRepository::lock_garbage(64, None, &mut second)
            .await
            .unwrap()
            .is_empty());
        first.rollback().await.unwrap();
        assert_eq!(
            BlobRepository::lock_garbage(64, None, &mut second)
                .await
                .unwrap(),
            ["old"]
        );
        BlobRepository::finish_garbage("old", &mut second)
            .await
            .unwrap();
        second.commit().await.unwrap();
        assert_eq!(
            BlobRepository::tracked_bytes_for_user(1, 1, &mut db.pool().into())
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_quota_cleanup_preserves_upload_settling_and_delete_backoff() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();
        BlobRepository::enqueue_garbage("retained", 1, 10, 3600, &mut executor)
            .await
            .unwrap();
        BlobRepository::enqueue_garbage("other-user", 2, 10, 0, &mut executor)
            .await
            .unwrap();
        BlobRepository::stage_upload("active", 1, 10, &mut executor)
            .await
            .unwrap();
        BlobRepository::abandon_upload("abandoned", 1, 10, 3600, &mut executor)
            .await
            .unwrap();
        BlobRepository::abandon_upload("expired", 1, 10, 0, &mut executor)
            .await
            .unwrap();
        let mut tx = db.pool().begin().await.unwrap();
        let mut selected = BlobRepository::lock_garbage(64, Some(1), &mut tx)
            .await
            .unwrap();
        selected.sort();
        assert_eq!(selected, ["expired", "retained"]);
        for key in selected {
            BlobRepository::defer_garbage(&key, 60, &mut tx)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        let mut tx = db.pool().begin().await.unwrap();
        assert!(BlobRepository::lock_garbage(64, Some(1), &mut tx)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            BlobRepository::lock_garbage(64, None, &mut tx)
                .await
                .unwrap(),
            ["other-user"]
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_expired_upload_cannot_publish_after_cleanup_rollback() {
        let db = SqlDb::test().await;
        BlobRepository::stage_upload("expired", 1, 10, &mut db.pool().into())
            .await
            .unwrap();
        sqlx::query("UPDATE unreferenced_blobs SET eligible_at = statement_timestamp()")
            .execute(db.pool())
            .await
            .unwrap();
        let mut cleanup = db.pool().begin().await.unwrap();
        assert_eq!(
            BlobRepository::lock_garbage(1, None, &mut cleanup)
                .await
                .unwrap(),
            ["expired"]
        );
        cleanup.rollback().await.unwrap();
        let mut publication = db.pool().begin().await.unwrap();
        assert!(matches!(
            BlobRepository::activate_upload("expired", &mut (&mut publication).into()).await,
            Err(sqlx::Error::RowNotFound)
        ));
        publication.rollback().await.unwrap();
        // Settling time protects late backend completion, not continued publication.
        sqlx::query("UPDATE unreferenced_blobs SET eligible_at = statement_timestamp() + INTERVAL '1 minute'")
            .execute(db.pool()).await.unwrap();
        let mut publication = db.pool().begin().await.unwrap();
        assert!(matches!(
            BlobRepository::activate_upload("expired", &mut (&mut publication).into()).await,
            Err(sqlx::Error::RowNotFound)
        ));
        BlobRepository::stage_upload("active", 1, 10, &mut (&mut publication).into())
            .await
            .unwrap();
        BlobRepository::activate_upload("active", &mut (&mut publication).into())
            .await
            .unwrap();
        publication.commit().await.unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_abandonment_recreates_tracking_and_preserves_deadline() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();
        BlobRepository::abandon_upload("late", 1, 10, 3600, &mut executor)
            .await
            .unwrap();
        let deadline: chrono::NaiveDateTime = sqlx::query_scalar(
            "SELECT eligible_at FROM unreferenced_blobs WHERE blob_key = 'late'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        BlobRepository::abandon_upload("late", 1, 5, 0, &mut executor)
            .await
            .unwrap();
        let row: (String, i64, chrono::NaiveDateTime) = sqlx::query_as("SELECT state, content_length, eligible_at FROM unreferenced_blobs WHERE blob_key = 'late'")
            .fetch_one(db.pool()).await.unwrap();
        assert_eq!(row, ("garbage".to_string(), 10, deadline));
        assert!(matches!(
            BlobRepository::activate_upload("late", &mut executor).await,
            Err(sqlx::Error::RowNotFound)
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_tracked_bytes_charge_for_zero_length_objects() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();
        BlobRepository::stage_upload("upload", 1, 0, &mut executor)
            .await
            .unwrap();
        BlobRepository::enqueue_garbage("retained", 1, 0, 3600, &mut executor)
            .await
            .unwrap();
        assert_eq!(
            BlobRepository::tracked_bytes_for_user(1, 512, &mut executor)
                .await
                .unwrap(),
            1024
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_reconciliation_preserves_owned_objects() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();
        BlobRepository::stage_upload("pending", 1, 10, &mut executor)
            .await
            .unwrap();
        BlobRepository::enqueue_garbage("retained", 1, 10, 3600, &mut executor)
            .await
            .unwrap();
        let keys = ["pending", "retained", "orphan"].map(str::to_owned);
        assert_eq!(
            BlobRepository::enqueue_untracked_blobs(&keys, &mut executor)
                .await
                .unwrap(),
            1
        );
        let mut tx = db.pool().begin().await.unwrap();
        assert_eq!(
            BlobRepository::lock_garbage(64, None, &mut tx)
                .await
                .unwrap(),
            ["orphan"]
        );
    }
}
