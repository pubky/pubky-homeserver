use crate::persistence::sql::UnifiedExecutor;

/// Persists immutable blob upload and cleanup bookkeeping.
pub struct BlobRepository;

/// One worker's ownership of a queued backend deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobGarbageClaim {
    pub blob_key: String,
    claim_token: String,
}

/// A bounded cross-process read lease on one immutable blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobReadLeaseRecord {
    pub blob_key: String,
    lease_id: String,
}

impl BlobRepository {
    /// Record an immutable blob before uploading its bytes.
    pub async fn stage_upload<'a>(
        blob_key: &str,
        user_id: i32,
        content_length: u64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let con = executor.get_con().await?;
        sqlx::query(
            "INSERT INTO blob_uploads (blob_key, user_id, content_length) VALUES ($1, $2, $3)",
        )
        .bind(blob_key)
        .bind(user_id)
        .bind(content_length as i64)
        .execute(con)
        .await?;
        Ok(())
    }

    /// Replace an upload reservation with its actual immutable blob size.
    pub async fn set_upload_size<'a>(
        blob_key: &str,
        content_length: u64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<bool, sqlx::Error> {
        let con = executor.get_con().await?;
        let result = sqlx::query(
            "UPDATE blob_uploads SET content_length = $2, updated_at = CURRENT_TIMESTAMP \
             WHERE blob_key = $1 AND NOT EXISTS (\
                 SELECT 1 FROM blob_garbage WHERE blob_key = $1\
             )",
        )
        .bind(blob_key)
        .bind(content_length as i64)
        .execute(con)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Remove an upload from staging without activating it.
    #[cfg(test)]
    pub async fn remove_staged_upload<'a>(
        blob_key: &str,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let con = executor.get_con().await?;
        sqlx::query("DELETE FROM blob_uploads WHERE blob_key = $1")
            .bind(blob_key)
            .execute(con)
            .await?;
        Ok(())
    }

    /// Ensure an abandoned blob remains durably queued even after upload ownership was lost.
    pub async fn abandon_upload<'a>(
        blob_key: &str,
        user_id: i32,
        content_length: u64,
        delay_seconds: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let con = executor.get_con().await?;
        sqlx::query(
            r#"
            WITH removed AS (
                DELETE FROM blob_uploads WHERE blob_key = $1
            )
            INSERT INTO blob_garbage (
                blob_key, user_id, content_length, available_at, claimed_at, claim_token
            )
            VALUES (
                $1, $2, $3, statement_timestamp() + ($4 * INTERVAL '1 second'), NULL, NULL
            )
            ON CONFLICT (blob_key) DO UPDATE
            SET user_id = EXCLUDED.user_id,
                content_length = GREATEST(blob_garbage.content_length, EXCLUDED.content_length),
                available_at = GREATEST(blob_garbage.available_at, EXCLUDED.available_at),
                claimed_at = NULL,
                claim_token = NULL
            "#,
        )
        .bind(blob_key)
        .bind(user_id)
        .bind(content_length as i64)
        .bind(delay_seconds)
        .execute(con)
        .await?;
        Ok(())
    }

    /// Commit an exclusively staged upload as active.
    pub async fn activate_upload<'a>(
        blob_key: &str,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let con = executor.get_con().await?;
        let activated = sqlx::query_scalar::<_, String>(
            r#"
            DELETE FROM blob_uploads AS upload
            WHERE upload.blob_key = $1
              AND NOT EXISTS (
                SELECT 1 FROM blob_garbage WHERE blob_key = $1
              )
            RETURNING upload.blob_key
            "#,
        )
        .bind(blob_key)
        .fetch_optional(con)
        .await?;
        activated.map(|_| ()).ok_or(sqlx::Error::RowNotFound)
    }

    /// Keep an active upload from being mistaken for abandoned work.
    pub async fn touch_upload<'a>(
        blob_key: &str,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<bool, sqlx::Error> {
        let con = executor.get_con().await?;
        let refreshed = sqlx::query_scalar::<_, String>(
            r#"
            UPDATE blob_uploads AS upload
            SET updated_at = CURRENT_TIMESTAMP
            WHERE upload.blob_key = $1
              AND NOT EXISTS (
                SELECT 1 FROM blob_garbage WHERE blob_key = $1
            )
            RETURNING upload.blob_key
            "#,
        )
        .bind(blob_key)
        .fetch_optional(con)
        .await?;
        Ok(refreshed.is_some())
    }

    /// Queue an unreferenced backend object for eventual deletion.
    pub async fn enqueue_garbage<'a>(
        blob_key: &str,
        user_id: i32,
        content_length: u64,
        delay_seconds: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let con = executor.get_con().await?;
        sqlx::query(
            r#"
            INSERT INTO blob_garbage (blob_key, user_id, content_length, available_at)
            VALUES ($1, $2, $3, statement_timestamp() + ($4 * INTERVAL '1 second'))
            ON CONFLICT (blob_key) DO UPDATE
            SET available_at = GREATEST(
                    blob_garbage.available_at,
                    EXCLUDED.available_at
                )
            "#,
        )
        .bind(blob_key)
        .bind(user_id)
        .bind(content_length as i64)
        .bind(delay_seconds)
        .execute(con)
        .await?;
        Ok(())
    }

    /// Move uploads abandoned before a database commit into the cleanup queue.
    pub async fn enqueue_stale_uploads<'a>(
        minimum_age_seconds: i64,
        cleanup_delay_seconds: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<u64, sqlx::Error> {
        let con = executor.get_con().await?;
        let result = sqlx::query(
            r#"
            WITH stale AS (
                DELETE FROM blob_uploads
                WHERE updated_at <= CURRENT_TIMESTAMP - ($1 * INTERVAL '1 second')
                RETURNING blob_key, user_id, content_length
            )
            INSERT INTO blob_garbage (blob_key, user_id, content_length, available_at)
            SELECT
                blob_key,
                user_id,
                content_length,
                statement_timestamp() + ($2 * INTERVAL '1 second')
            FROM stale
            ON CONFLICT (blob_key) DO UPDATE
            SET user_id = EXCLUDED.user_id,
                content_length = GREATEST(blob_garbage.content_length, EXCLUDED.content_length),
                available_at = GREATEST(blob_garbage.available_at, EXCLUDED.available_at),
                claimed_at = NULL,
                claim_token = NULL
            "#,
        )
        .bind(minimum_age_seconds)
        .bind(cleanup_delay_seconds)
        .execute(con)
        .await?;
        Ok(result.rows_affected())
    }

    /// Queue backend objects that have no active or pending database owner.
    pub async fn enqueue_untracked_blobs<'a>(
        blob_keys: &[String],
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<u64, sqlx::Error> {
        if blob_keys.is_empty() {
            return Ok(0);
        }
        let con = executor.get_con().await?;
        let result = sqlx::query(
            r#"
            INSERT INTO blob_garbage (blob_key, user_id, content_length, available_at)
            SELECT candidate.blob_key, NULL, 0, statement_timestamp()
            FROM UNNEST($1::TEXT[]) AS candidate(blob_key)
            WHERE NOT EXISTS (
                    SELECT 1 FROM entries WHERE entries.blob_key = candidate.blob_key
                )
              AND NOT EXISTS (
                    SELECT 1 FROM blob_uploads WHERE blob_uploads.blob_key = candidate.blob_key
                )
              AND NOT EXISTS (
                    SELECT 1 FROM blob_garbage WHERE blob_garbage.blob_key = candidate.blob_key
                )
            ON CONFLICT (blob_key) DO NOTHING
            "#,
        )
        .bind(blob_keys)
        .execute(con)
        .await?;
        Ok(result.rows_affected())
    }

    /// Total bytes occupied by staged and retained blobs for one user.
    pub async fn tracked_bytes_for_user<'a>(
        user_id: i32,
        minimum_blob_bytes: u64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<u64, sqlx::Error> {
        let con = executor.get_con().await?;
        let total = sqlx::query_scalar::<_, i64>(
            "SELECT (\
                 COALESCE((SELECT SUM(GREATEST(content_length, $2)) FROM blob_uploads WHERE user_id = $1), 0) \
                 + COALESCE((SELECT SUM(GREATEST(content_length, $2)) FROM blob_garbage WHERE user_id = $1), 0)\
             )::BIGINT",
        )
        .bind(user_id)
        .bind(minimum_blob_bytes as i64)
        .fetch_one(con)
        .await?;
        Ok(total.max(0) as u64)
    }

    /// Create a renewable lease unless cleanup already owns the blob.
    pub async fn create_read_lease<'a>(
        blob_key: &str,
        lease_id: &str,
        lease_seconds: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Option<BlobReadLeaseRecord>, sqlx::Error> {
        let con = executor.get_con().await?;
        let leased = sqlx::query_as::<_, (String, String)>(
            r#"
            WITH garbage AS (
                SELECT claim_token
                FROM blob_garbage
                WHERE blob_key = $1
                FOR UPDATE
            ), leased AS (
                INSERT INTO blob_read_leases (blob_key, lease_id, expires_at)
                SELECT $1, $2, clock_timestamp() + ($3 * INTERVAL '1 second')
                WHERE NOT EXISTS (
                    SELECT 1 FROM garbage WHERE claim_token IS NOT NULL
                )
                ON CONFLICT (blob_key, lease_id) DO UPDATE
                SET expires_at = GREATEST(
                    blob_read_leases.expires_at,
                    EXCLUDED.expires_at
                )
                RETURNING blob_key, lease_id
            )
            SELECT blob_key, lease_id FROM leased
            "#,
        )
        .bind(blob_key)
        .bind(lease_id)
        .bind(lease_seconds)
        .fetch_optional(con)
        .await?;
        Ok(leased.map(|(blob_key, lease_id)| BlobReadLeaseRecord { blob_key, lease_id }))
    }

    /// Extend one active reader lease without affecting other readers.
    pub async fn refresh_read_lease<'a>(
        lease: &BlobReadLeaseRecord,
        lease_seconds: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<bool, sqlx::Error> {
        let con = executor.get_con().await?;
        let result = sqlx::query(
            r#"
            WITH garbage AS (
                SELECT claim_token
                FROM blob_garbage
                WHERE blob_key = $1
                FOR UPDATE
            )
            UPDATE blob_read_leases
            SET expires_at = GREATEST(
                expires_at, clock_timestamp() + ($3 * INTERVAL '1 second')
            )
            WHERE blob_key = $1
              AND lease_id = $2
              AND expires_at > clock_timestamp()
              AND NOT EXISTS (
                  SELECT 1 FROM garbage WHERE claim_token IS NOT NULL
              )
            "#,
        )
        .bind(&lease.blob_key)
        .bind(&lease.lease_id)
        .bind(lease_seconds)
        .execute(con)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Release one reader lease after its final local reader is dropped.
    pub async fn release_read_lease<'a>(
        lease: &BlobReadLeaseRecord,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let con = executor.get_con().await?;
        sqlx::query("DELETE FROM blob_read_leases WHERE blob_key = $1 AND lease_id = $2")
            .bind(&lease.blob_key)
            .bind(&lease.lease_id)
            .execute(con)
            .await?;
        Ok(())
    }

    /// Remove reader leases that were not renewed before their deadline.
    pub async fn prune_expired_read_leases<'a>(
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<u64, sqlx::Error> {
        let con = executor.get_con().await?;
        let result =
            sqlx::query("DELETE FROM blob_read_leases WHERE expires_at <= statement_timestamp()")
                .execute(con)
                .await?;
        Ok(result.rows_affected())
    }

    /// Claim cleanup work without holding a database transaction during backend I/O.
    pub async fn claim_garbage<'a>(
        limit: i64,
        stale_claim_seconds: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<BlobGarbageClaim>, sqlx::Error> {
        let con = executor.get_con().await?;
        let claim_token = uuid::Uuid::new_v4().simple().to_string();
        let rows = sqlx::query_as::<_, (String, String)>(
            r#"
            WITH candidates AS (
                SELECT blob_key
                FROM blob_garbage
                WHERE available_at <= statement_timestamp()
                  AND (
                    claimed_at IS NULL
                    OR claimed_at <= statement_timestamp() - ($2 * INTERVAL '1 second')
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM blob_read_leases
                    WHERE blob_read_leases.blob_key = blob_garbage.blob_key
                      AND blob_read_leases.expires_at > statement_timestamp()
                  )
                ORDER BY available_at, blob_key
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE blob_garbage AS garbage
            SET claimed_at = statement_timestamp(),
                claim_token = $3
            FROM candidates
            WHERE garbage.blob_key = candidates.blob_key
            RETURNING garbage.blob_key, garbage.claim_token
            "#,
        )
        .bind(limit)
        .bind(stale_claim_seconds)
        .bind(&claim_token)
        .fetch_all(con)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(blob_key, claim_token)| BlobGarbageClaim {
                blob_key,
                claim_token,
            })
            .collect())
    }

    /// Remove a blob from the cleanup queue after backend deletion succeeds.
    pub async fn finish_garbage<'a>(
        claim: &BlobGarbageClaim,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let con = executor.get_con().await?;
        sqlx::query("DELETE FROM blob_garbage WHERE blob_key = $1 AND claim_token = $2")
            .bind(&claim.blob_key)
            .bind(&claim.claim_token)
            .execute(con)
            .await?;
        Ok(())
    }

    /// Keep a failed deletion tombstoned while deferring it for a later retry.
    pub async fn defer_garbage<'a>(
        claim: &BlobGarbageClaim,
        retry_delay_seconds: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let con = executor.get_con().await?;
        sqlx::query(
            "UPDATE blob_garbage \
             SET claimed_at = NULL, \
                 available_at = statement_timestamp() + ($3 * INTERVAL '1 second') \
             WHERE blob_key = $1 AND claim_token = $2",
        )
        .bind(&claim.blob_key)
        .bind(&claim.claim_token)
        .bind(retry_delay_seconds)
        .execute(con)
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
    async fn test_remove_staged_upload_and_claim_garbage() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();

        BlobRepository::stage_upload("blob-a", 1, 10, &mut executor)
            .await
            .unwrap();
        BlobRepository::remove_staged_upload("blob-a", &mut executor)
            .await
            .unwrap();
        let staged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_uploads")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(staged, 0);
        BlobRepository::enqueue_garbage("blob-a", 1, 10, 0, &mut executor)
            .await
            .unwrap();
        assert_eq!(
            BlobRepository::tracked_bytes_for_user(1, 1, &mut executor)
                .await
                .unwrap(),
            10
        );

        let claimed = BlobRepository::claim_garbage(10, 300, &mut executor)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].blob_key, "blob-a");
        assert!(BlobRepository::claim_garbage(10, 300, &mut executor)
            .await
            .unwrap()
            .is_empty());

        BlobRepository::defer_garbage(&claimed[0], 0, &mut executor)
            .await
            .unwrap();
        assert!(
            BlobRepository::create_read_lease("blob-a", "reader-a", 300, &mut executor)
                .await
                .unwrap()
                .is_none(),
            "an ambiguous deletion must remain tombstoned"
        );
        let reclaimed = BlobRepository::claim_garbage(10, 300, &mut executor)
            .await
            .unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].blob_key, "blob-a");
        BlobRepository::finish_garbage(&reclaimed[0], &mut executor)
            .await
            .unwrap();
        let garbage: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(garbage, 0);
        assert_eq!(
            BlobRepository::tracked_bytes_for_user(1, 1, &mut executor)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_active_upload_heartbeat_delays_recovery() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();
        BlobRepository::stage_upload("blob-a", 1, 10, &mut executor)
            .await
            .unwrap();
        sqlx::query("UPDATE blob_uploads SET updated_at = CURRENT_TIMESTAMP - INTERVAL '2 hours'")
            .execute(db.pool())
            .await
            .unwrap();

        assert!(BlobRepository::touch_upload("blob-a", &mut executor)
            .await
            .unwrap());
        assert_eq!(
            BlobRepository::enqueue_stale_uploads(60 * 60, 300, &mut executor)
                .await
                .unwrap(),
            0
        );

        sqlx::query("UPDATE blob_uploads SET updated_at = CURRENT_TIMESTAMP - INTERVAL '2 hours'")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(
            BlobRepository::enqueue_stale_uploads(60 * 60, 300, &mut executor)
                .await
                .unwrap(),
            1
        );

        assert!(!BlobRepository::touch_upload("blob-a", &mut executor)
            .await
            .unwrap());
        let garbage: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(garbage, 1);
        assert!(matches!(
            BlobRepository::activate_upload("blob-a", &mut executor).await,
            Err(sqlx::Error::RowNotFound)
        ));
        sqlx::query("UPDATE blob_garbage SET available_at = CURRENT_TIMESTAMP")
            .execute(db.pool())
            .await
            .unwrap();
        let claimed = BlobRepository::claim_garbage(10, 300, &mut executor)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].blob_key, "blob-a");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_abandon_upload_restores_missing_cleanup_tracking() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();
        BlobRepository::stage_upload("blob-a", 1, 10, &mut executor)
            .await
            .unwrap();
        BlobRepository::remove_staged_upload("blob-a", &mut executor)
            .await
            .unwrap();

        BlobRepository::abandon_upload("blob-a", 1, 12, 0, &mut executor)
            .await
            .unwrap();
        let claim = BlobRepository::claim_garbage(1, 300, &mut executor)
            .await
            .unwrap()
            .pop()
            .expect("lost upload ownership must recreate cleanup tracking");

        BlobRepository::abandon_upload("blob-a", 1, 14, 0, &mut executor)
            .await
            .unwrap();
        BlobRepository::finish_garbage(&claim, &mut executor)
            .await
            .unwrap();
        assert_eq!(
            BlobRepository::tracked_bytes_for_user(1, 1, &mut executor)
                .await
                .unwrap(),
            14
        );
        assert_eq!(
            BlobRepository::claim_garbage(1, 300, &mut executor)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_lost_upload_preserves_settling_deadline() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();

        BlobRepository::enqueue_garbage("blob-a", 1, 10, 0, &mut executor)
            .await
            .unwrap();
        BlobRepository::abandon_upload("blob-a", 1, 10, 300, &mut executor)
            .await
            .unwrap();
        assert!(BlobRepository::claim_garbage(1, 300, &mut executor)
            .await
            .unwrap()
            .is_empty());

        BlobRepository::stage_upload("blob-b", 1, 10, &mut executor)
            .await
            .unwrap();
        BlobRepository::enqueue_garbage("blob-b", 1, 10, 0, &mut executor)
            .await
            .unwrap();
        sqlx::query("UPDATE blob_uploads SET updated_at = CURRENT_TIMESTAMP - INTERVAL '2 hours'")
            .execute(db.pool())
            .await
            .unwrap();
        BlobRepository::enqueue_stale_uploads(60 * 60, 300, &mut executor)
            .await
            .unwrap();
        assert!(BlobRepository::claim_garbage(2, 300, &mut executor)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_tracked_bytes_charge_for_zero_length_objects() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();
        BlobRepository::stage_upload("blob-a", 1, 0, &mut executor)
            .await
            .unwrap();
        BlobRepository::enqueue_garbage("blob-b", 1, 0, 0, &mut executor)
            .await
            .unwrap();

        assert_eq!(
            BlobRepository::tracked_bytes_for_user(1, 256, &mut executor)
                .await
                .unwrap(),
            512
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_enqueue_untracked_blobs_preserves_owned_objects() {
        let db = SqlDb::test().await;
        let user_id: i32 =
            sqlx::query_scalar("INSERT INTO users (public_key) VALUES ('user-a') RETURNING id")
                .fetch_one(db.pool())
                .await
                .unwrap();
        sqlx::query(
            r#"
            INSERT INTO entries
                ("user", path, content_hash, content_length, content_type, blob_key)
            VALUES ($1, '/pub/active', $2, 1, 'application/octet-stream', 'active')
            "#,
        )
        .bind(user_id)
        .bind(vec![0u8; 32])
        .execute(db.pool())
        .await
        .unwrap();

        let mut executor = db.pool().into();
        BlobRepository::stage_upload("uploading", user_id, 1, &mut executor)
            .await
            .unwrap();
        BlobRepository::enqueue_garbage("garbage", user_id, 1, 0, &mut executor)
            .await
            .unwrap();

        let keys = ["active", "uploading", "garbage", "orphan"].map(str::to_string);
        assert_eq!(
            BlobRepository::enqueue_untracked_blobs(&keys, &mut executor)
                .await
                .unwrap(),
            1
        );
        let orphan_owner: Option<i32> =
            sqlx::query_scalar("SELECT user_id FROM blob_garbage WHERE blob_key = 'orphan'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(orphan_owner, None);
        let garbage_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(garbage_count, 2);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_read_lease_blocks_garbage_claim() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();
        BlobRepository::enqueue_garbage("blob-a", 1, 10, 0, &mut executor)
            .await
            .unwrap();
        let lease = BlobRepository::create_read_lease("blob-a", "reader-a", 300, &mut executor)
            .await
            .unwrap()
            .expect("unclaimed garbage should remain readable");
        let expires_before: chrono::NaiveDateTime =
            sqlx::query_scalar("SELECT expires_at FROM blob_read_leases WHERE blob_key = 'blob-a'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(lease.blob_key, "blob-a");

        assert!(
            BlobRepository::refresh_read_lease(&lease, 60, &mut executor)
                .await
                .unwrap(),
            "renewing an active lease should succeed"
        );
        let expires_after: chrono::NaiveDateTime =
            sqlx::query_scalar("SELECT expires_at FROM blob_read_leases WHERE blob_key = 'blob-a'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert!(expires_after >= expires_before);

        let second_lease =
            BlobRepository::create_read_lease("blob-a", "reader-b", 300, &mut executor)
                .await
                .unwrap()
                .expect("a second reader should get an independent lease");
        let lease_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM blob_read_leases WHERE blob_key = 'blob-a'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(lease_count, 2);

        assert!(BlobRepository::claim_garbage(1, 300, &mut executor)
            .await
            .unwrap()
            .is_empty());

        BlobRepository::release_read_lease(&lease, &mut executor)
            .await
            .unwrap();
        assert!(BlobRepository::claim_garbage(1, 300, &mut executor)
            .await
            .unwrap()
            .is_empty());
        BlobRepository::release_read_lease(&second_lease, &mut executor)
            .await
            .unwrap();
        assert_eq!(
            BlobRepository::claim_garbage(1, 300, &mut executor)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_claimed_garbage_rejects_new_read_lease() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();
        BlobRepository::enqueue_garbage("blob-a", 1, 10, 0, &mut executor)
            .await
            .unwrap();
        assert_eq!(
            BlobRepository::claim_garbage(1, 300, &mut executor)
                .await
                .unwrap()
                .len(),
            1
        );

        assert!(
            BlobRepository::create_read_lease("blob-a", "reader-a", 300, &mut executor)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_expired_read_lease_cannot_be_revived_after_cleanup_claim() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();
        BlobRepository::enqueue_garbage("blob-a", 1, 10, 0, &mut executor)
            .await
            .unwrap();
        let lease = BlobRepository::create_read_lease("blob-a", "reader-a", 60, &mut executor)
            .await
            .unwrap()
            .unwrap();
        sqlx::query("UPDATE blob_read_leases SET expires_at = statement_timestamp()")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(
            BlobRepository::claim_garbage(1, 300, &mut executor)
                .await
                .unwrap()
                .len(),
            1
        );

        assert!(
            !BlobRepository::refresh_read_lease(&lease, 60, &mut executor)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_read_lease_waiting_on_claim_is_rejected() {
        let db = SqlDb::test().await;
        BlobRepository::enqueue_garbage("blob-a", 1, 10, 0, &mut db.pool().into())
            .await
            .unwrap();
        let mut claim_tx = db.pool().begin().await.unwrap();
        sqlx::query("SELECT blob_key FROM blob_garbage WHERE blob_key = 'blob-a' FOR UPDATE")
            .execute(&mut *claim_tx)
            .await
            .unwrap();

        let task_db = db.clone();
        let lease_task = tokio::spawn(async move {
            BlobRepository::create_read_lease("blob-a", "reader-a", 300, &mut task_db.pool().into())
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        sqlx::query(
            "UPDATE blob_garbage SET claimed_at = statement_timestamp(), claim_token = 'claim' \
             WHERE blob_key = 'blob-a'",
        )
        .execute(&mut *claim_tx)
        .await
        .unwrap();
        claim_tx.commit().await.unwrap();

        assert!(lease_task.await.unwrap().unwrap().is_none());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_garbage_claim_skips_concurrent_read_lease() {
        let db = SqlDb::test().await;
        BlobRepository::enqueue_garbage("blob-a", 1, 10, 0, &mut db.pool().into())
            .await
            .unwrap();
        let mut lease_tx = db.pool().begin().await.unwrap();
        BlobRepository::create_read_lease("blob-a", "reader-a", 300, &mut (&mut lease_tx).into())
            .await
            .unwrap()
            .expect("lease should be staged inside the transaction");

        let task_db = db.clone();
        let claim_task = tokio::spawn(async move {
            BlobRepository::claim_garbage(1, 300, &mut task_db.pool().into()).await
        });
        assert!(claim_task.await.unwrap().unwrap().is_empty());
        lease_tx.commit().await.unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_garbage_deadline_uses_enqueue_statement_time() {
        let db = SqlDb::test().await;
        let mut tx = db.pool().begin().await.unwrap();
        sqlx::query("SELECT pg_sleep(0.05)")
            .execute(&mut *tx)
            .await
            .unwrap();
        BlobRepository::enqueue_garbage("blob-a", 1, 10, 0, &mut (&mut tx).into())
            .await
            .unwrap();
        let deadline_is_fresh: bool = sqlx::query_scalar(
            "SELECT available_at >= transaction_timestamp() + INTERVAL '40 milliseconds' \
             FROM blob_garbage WHERE blob_key = 'blob-a'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        tx.rollback().await.unwrap();

        assert!(deadline_is_fresh);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_activation_finishes_staged_upload() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();
        BlobRepository::stage_upload("blob-a", 1, 10, &mut executor)
            .await
            .unwrap();

        BlobRepository::activate_upload("blob-a", &mut executor)
            .await
            .unwrap();

        assert!(BlobRepository::claim_garbage(10, 300, &mut executor)
            .await
            .unwrap()
            .is_empty());
        let staged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_uploads")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(staged, 0);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_stale_worker_cannot_mutate_newer_claim() {
        let db = SqlDb::test().await;
        let mut executor = db.pool().into();
        BlobRepository::enqueue_garbage("blob-a", 1, 10, 0, &mut executor)
            .await
            .unwrap();
        let old_claim = BlobRepository::claim_garbage(1, 300, &mut executor)
            .await
            .unwrap()
            .remove(0);
        sqlx::query(
            "UPDATE blob_garbage SET claimed_at = CURRENT_TIMESTAMP - INTERVAL '10 minutes'",
        )
        .execute(db.pool())
        .await
        .unwrap();
        let new_claim = BlobRepository::claim_garbage(1, 300, &mut executor)
            .await
            .unwrap()
            .remove(0);

        BlobRepository::defer_garbage(&old_claim, 0, &mut executor)
            .await
            .unwrap();
        assert!(BlobRepository::claim_garbage(1, 300, &mut executor)
            .await
            .unwrap()
            .is_empty());
        BlobRepository::finish_garbage(&old_claim, &mut executor)
            .await
            .unwrap();
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(remaining, 1);

        BlobRepository::finish_garbage(&new_claim, &mut executor)
            .await
            .unwrap();
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_garbage")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(remaining, 0);
    }
}
