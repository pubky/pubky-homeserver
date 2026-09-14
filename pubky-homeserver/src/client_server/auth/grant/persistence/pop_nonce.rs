//! Repository for PoP nonce replay prevention.

use pubky_common::auth::jws::PopNonce;
use sea_query::{Expr, ExprTrait, PostgresQueryBuilder, Query, SimpleExpr};
use sea_query_sqlx::SqlxBinder;

use crate::persistence::sql::{
    migrations::m20260325_create_grant_sessions::{PopNonceIden, POP_NONCES_TABLE},
    UnifiedExecutor,
};

/// Repository for PoP nonce tracking and garbage collection.
pub struct PopNonceRepository;

#[derive(Debug, thiserror::Error)]
pub enum PopNonceError {
    /// PoP nonce was already used (replay attack).
    #[error("PoP nonce already used")]
    AlreadyUsed,

    /// Database or infrastructure error.
    #[error("Failed to track PoP nonce: {0}")]
    Internal(#[from] sqlx::Error),
}

impl PopNonceRepository {
    /// Attempt to track a nonce. Returns `Ok(())` if the nonce is new.
    ///
    /// Returns [`PopNonceError::AlreadyUsed`] if the nonce was already seen.
    pub async fn check_and_track<'a>(
        nonce: &PopNonce,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), PopNonceError> {
        let statement = Query::insert()
            .into_table(POP_NONCES_TABLE)
            .columns([PopNonceIden::Nonce])
            .values(vec![SimpleExpr::Value(nonce.to_string().into())])
            .expect("invariant: values count matches columns count")
            .on_conflict(
                sea_query::OnConflict::column(PopNonceIden::Nonce)
                    .do_nothing()
                    .to_owned(),
            )
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let result = sqlx::query_with(&query, values).execute(con).await?;

        if result.rows_affected() == 0 {
            return Err(PopNonceError::AlreadyUsed);
        }

        Ok(())
    }

    /// Delete nonces older than `max_age_secs` seconds.
    ///
    /// Called lazily during nonce checks to prevent unbounded table growth.
    pub async fn garbage_collect<'a>(
        max_age_secs: u64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<u64, sqlx::Error> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(max_age_secs as i64);

        let statement = Query::delete()
            .from_table(POP_NONCES_TABLE)
            .and_where(Expr::col(PopNonceIden::CreatedAt).lt(cutoff.naive_utc()))
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let result = sqlx::query_with(&query, values).execute(con).await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_common::auth::jws::PopNonce;

    use crate::persistence::sql::SqlDb;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_check_and_track_new_nonce() {
        let db = SqlDb::test().await;
        let nonce = PopNonce::generate();
        PopNonceRepository::check_and_track(&nonce, &mut db.pool().into())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_check_and_track_duplicate_rejected() {
        let db = SqlDb::test().await;
        let nonce = PopNonce::generate();

        PopNonceRepository::check_and_track(&nonce, &mut db.pool().into())
            .await
            .unwrap();

        let result = PopNonceRepository::check_and_track(&nonce, &mut db.pool().into()).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, PopNonceError::AlreadyUsed));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_garbage_collect_removes_old_nonces() {
        let db = SqlDb::test().await;
        let nonce = PopNonce::generate();

        PopNonceRepository::check_and_track(&nonce, &mut db.pool().into())
            .await
            .unwrap();

        // GC with max_age=0 should remove everything
        let deleted = PopNonceRepository::garbage_collect(0, &mut db.pool().into())
            .await
            .unwrap();
        assert!(deleted >= 1);

        // Nonce should be gone, so reinserting should succeed
        PopNonceRepository::check_and_track(&nonce, &mut db.pool().into())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_garbage_collect_preserves_recent() {
        let db = SqlDb::test().await;
        let nonce = PopNonce::generate();

        PopNonceRepository::check_and_track(&nonce, &mut db.pool().into())
            .await
            .unwrap();

        // GC with 1-hour threshold should keep the just-inserted nonce
        let deleted = PopNonceRepository::garbage_collect(3600, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(deleted, 0);

        // Nonce should still be there, so reinserting should fail
        let result = PopNonceRepository::check_and_track(&nonce, &mut db.pool().into()).await;
        assert!(result.is_err());
    }
}
