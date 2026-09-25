//! Repository for grant-based session entities.

use pubky_common::auth::jws::{GrantId, RandomId};
use sea_query::{Expr, ExprTrait, Iden, PostgresQueryBuilder, Query};
use sea_query_sqlx::SqlxBinder;
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use crate::client_server::auth::grant::crypto::session_token::SessionTokenHash;
use crate::data_directory::GrantAuthToml;
use crate::persistence::sql::{
    migrations::m20260325_create_grant_sessions::{GrantSessionIden, GRANT_SESSIONS_TABLE},
    SqlDb, UnifiedExecutor,
};

/// Repository for grant-based session CRUD operations.
pub struct GrantSessionRepository;

impl GrantSessionRepository {
    /// Lock the grant row to serialize issuance with other exchanges and revocation.
    pub async fn issue(
        session: &NewGrantSession,
        db: &SqlDb,
        limits: &GrantAuthToml,
    ) -> Result<(), SessionIssueError> {
        let mut tx = db.pool().begin().await?;
        let grant_id = session.grant_id.to_string();
        let grant = sqlx::query(
            "SELECT revoked_at, expires_at, session_window_start, session_window_count
             FROM grants WHERE id = $1 FOR UPDATE",
        )
        .bind(&grant_id)
        .fetch_one(&mut *tx)
        .await?;
        // The grant may have expired while waiting for the lock.
        let now = chrono::Utc::now().timestamp();
        if grant.try_get::<Option<i64>, _>("revoked_at")?.is_some() {
            return Err(SessionIssueError::Revoked);
        }
        if grant.try_get::<i64, _>("expires_at")? <= now {
            return Err(SessionIssueError::Expired);
        }
        let slot = session.session_id.as_ref().map(RandomId::as_str);
        Self::reserve_slot(&mut tx, &grant_id, slot, now, limits).await?;
        Self::consume_issuance_budget(&mut tx, &grant_id, &grant, now, limits).await?;

        sqlx::query(
            "INSERT INTO grant_sessions (token_hash, grant_id, expires_at, session_id)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(session.token_hash.as_ref())
        .bind(&grant_id)
        .bind(session.expires_at as i64)
        .bind(slot)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Self::collect_expired_sessions(db, now).await;
        Ok(())
    }

    async fn reserve_slot(
        tx: &mut Transaction<'_, Postgres>,
        grant_id: &str,
        slot: Option<&str>,
        now: i64,
        limits: &GrantAuthToml,
    ) -> Result<(), SessionIssueError> {
        sqlx::query("DELETE FROM grant_sessions WHERE grant_id = $1 AND expires_at <= $2")
            .bind(grant_id)
            .bind(now)
            .execute(&mut **tx)
            .await?;
        // Rejected exchanges roll back this deletion, preserving the old bearer.
        let replaced = sqlx::query(
            "DELETE FROM grant_sessions WHERE grant_id = $1 AND session_id IS NOT DISTINCT FROM $2",
        )
        .bind(grant_id)
        .bind(slot)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM grant_sessions WHERE grant_id = $1")
                .bind(grant_id)
                .fetch_one(&mut **tx)
                .await?;
        if replaced == 0 && count as u64 >= limits.max_sessions_per_grant.get() {
            return Err(SessionIssueError::Capacity);
        }
        Ok(())
    }

    async fn consume_issuance_budget(
        tx: &mut Transaction<'_, Postgres>,
        grant_id: &str,
        grant: &PgRow,
        now: i64,
        limits: &GrantAuthToml,
    ) -> Result<(), SessionIssueError> {
        let window_start: i64 = grant.try_get("session_window_start")?;
        let window_count: i64 = grant.try_get("session_window_count")?;
        let new_window = now >= window_start + 60;
        if !new_window && window_count as u64 >= limits.session_issuance_per_minute.get() {
            return Err(SessionIssueError::RateLimited);
        }
        sqlx::query(
            "UPDATE grants SET session_window_start = $2, session_window_count = $3 WHERE id = $1",
        )
        .bind(grant_id)
        .bind(if new_window { now } else { window_start })
        .bind(if new_window { 1 } else { window_count + 1 })
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn collect_expired_sessions(db: &SqlDb, now: i64) {
        // Cleanup failure must not turn a committed exchange into an error.
        if let Err(error) = sqlx::query(
            "DELETE FROM grant_sessions WHERE id IN (
                 SELECT id FROM grant_sessions WHERE expires_at <= $1
                 ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED
             )",
        )
        .bind(now)
        .execute(db.pool())
        .await
        {
            tracing::warn!(%error, "Expired grant session cleanup failed");
        }
    }

    /// Get a session by its token hash.
    pub async fn get_by_token_hash<'a>(
        token_hash: &SessionTokenHash,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<GrantSessionEntity, sqlx::Error> {
        let statement = Query::select()
            .from(GRANT_SESSIONS_TABLE)
            .columns([
                GrantSessionIden::Id,
                GrantSessionIden::TokenHash,
                GrantSessionIden::GrantId,
                GrantSessionIden::ExpiresAt,
                GrantSessionIden::CreatedAt,
                GrantSessionIden::SessionId,
            ])
            .and_where(Expr::col(GrantSessionIden::TokenHash).eq(token_hash.as_ref().to_vec()))
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values).fetch_one(con).await
    }

    /// Delete all sessions for a given grant (used on revocation).
    pub async fn delete_all_for_grant<'a>(
        grant_id: &GrantId,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let statement = Query::delete()
            .from_table(GRANT_SESSIONS_TABLE)
            .and_where(Expr::col(GrantSessionIden::GrantId).eq(grant_id.to_string()))
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_with(&query, values).execute(con).await?;
        Ok(())
    }
}

/// Data needed to create a new grant session.
pub struct NewGrantSession {
    pub session_id: Option<RandomId>,
    pub token_hash: SessionTokenHash,
    pub grant_id: GrantId,
    pub expires_at: u64,
}

/// A grant session entity as stored in the database.
#[derive(Debug, Clone)]
#[allow(dead_code)] // `id`, `token_hash`, `created_at` are decoded from DB rows for completeness but only consumed in tests.
pub struct GrantSessionEntity {
    pub session_id: Option<RandomId>,
    pub id: i32,
    pub token_hash: SessionTokenHash,
    pub grant_id: GrantId,
    pub expires_at: i64,
    pub created_at: sqlx::types::chrono::NaiveDateTime,
}

impl FromRow<'_, PgRow> for GrantSessionEntity {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        let id: i32 = row.try_get(GrantSessionIden::Id.to_string().as_str())?;
        let token_hash_bytes: Vec<u8> =
            row.try_get(GrantSessionIden::TokenHash.to_string().as_str())?;
        let token_hash = SessionTokenHash::try_from(token_hash_bytes)
            .map_err(|e| sqlx::Error::Decode(e.into()))?;
        let grant_id: String = row.try_get(GrantSessionIden::GrantId.to_string().as_str())?;
        let grant_id = GrantId::parse(&grant_id).map_err(|e| sqlx::Error::Decode(e.into()))?;
        let expires_at: i64 = row.try_get(GrantSessionIden::ExpiresAt.to_string().as_str())?;
        let created_at = row.try_get(GrantSessionIden::CreatedAt.to_string().as_str())?;

        let session_id: Option<String> = row.try_get("session_id")?;
        let session_id = session_id
            .map(|id| RandomId::parse(&id))
            .transpose()
            .map_err(|e| sqlx::Error::Decode(e.into()))?;
        Ok(GrantSessionEntity {
            session_id,
            id,
            token_hash,
            grant_id,
            expires_at,
            created_at,
        })
    }
}

/// Expected issuance failures; callers map these to protocol errors.
#[derive(Debug, thiserror::Error)]
pub enum SessionIssueError {
    #[error("Grant has been revoked")]
    Revoked,
    #[error("Grant has expired")]
    Expired,
    #[error("Active session limit reached")]
    Capacity,
    #[error("Session issuance rate limit reached")]
    RateLimited,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_common::{
        auth::jws::{ClientId, GrantId},
        capabilities::{Capabilities, Capability},
        crypto::Keypair,
    };

    use crate::client_server::auth::grant::crypto::session_token::SessionBearer;
    use crate::client_server::auth::grant::persistence::grant::{GrantRepository, NewGrant};
    use crate::services::user_service::UserService;

    async fn setup_user_and_grant(db: &SqlDb) -> GrantId {
        let pubkey = Keypair::random().public_key();
        let user = UserService::new(db.clone()).create(&pubkey).await.unwrap();
        let now = chrono::Utc::now().timestamp() as u64;
        let grant_id = GrantId::generate();
        let new_grant = NewGrant {
            id: grant_id.clone(),
            user_id: user.id,
            client_id: ClientId::new("test.app").unwrap(),
            client_cnf_key: Keypair::random().public_key().z32(),
            capabilities: Capabilities::builder().cap(Capability::root()).finish(),
            issued_at: now,
            expires_at: now + 3600,
        };
        GrantRepository::create(&new_grant, &mut db.pool().into())
            .await
            .unwrap();
        grant_id
    }

    fn make_new_session(grant_id: &GrantId) -> (NewGrantSession, SessionTokenHash) {
        let now = chrono::Utc::now().timestamp() as u64;
        let hash = SessionBearer::generate().hash();
        (
            NewGrantSession {
                session_id: None,
                token_hash: hash,
                grant_id: grant_id.clone(),
                expires_at: now + 3600,
            },
            hash,
        )
    }

    fn slot(grant: &GrantId) -> NewGrantSession {
        let (mut session, _) = make_new_session(grant);
        session.session_id = Some(RandomId::generate());
        session
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_and_get_session() {
        let db = SqlDb::test().await;
        let grant_id = setup_user_and_grant(&db).await;

        let (new_session, hash) = make_new_session(&grant_id);
        let expires_at = new_session.expires_at;

        GrantSessionRepository::issue(&new_session, &db, &Default::default())
            .await
            .unwrap();

        let entity = GrantSessionRepository::get_by_token_hash(&hash, &mut db.pool().into())
            .await
            .unwrap();

        assert_eq!(entity.token_hash, hash);
        assert_eq!(entity.grant_id, grant_id);
        assert_eq!(entity.expires_at, expires_at as i64);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn legacy_slots_rotate_independently() {
        let db = SqlDb::test().await;
        let grant_a = setup_user_and_grant(&db).await;
        let grant_b = setup_user_and_grant(&db).await;
        let (a, _) = make_new_session(&grant_a);
        let (b, _) = make_new_session(&grant_b);
        let (replacement, _) = make_new_session(&grant_a);
        for session in [&a, &b, &replacement] {
            GrantSessionRepository::issue(session, &db, &Default::default())
                .await
                .unwrap();
        }
        assert!(matches!(
            GrantSessionRepository::get_by_token_hash(&a.token_hash, &mut db.pool().into()).await,
            Err(sqlx::Error::RowNotFound)
        ));
        for session in [&b, &replacement] {
            GrantSessionRepository::get_by_token_hash(&session.token_hash, &mut db.pool().into())
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_delete_all_for_grant() {
        let db = SqlDb::test().await;
        let grant_id = setup_user_and_grant(&db).await;

        let s1 = slot(&grant_id);
        GrantSessionRepository::issue(&s1, &db, &Default::default())
            .await
            .unwrap();

        let s2 = slot(&grant_id);
        GrantSessionRepository::issue(&s2, &db, &Default::default())
            .await
            .unwrap();

        GrantSessionRepository::delete_all_for_grant(&grant_id, &mut db.pool().into())
            .await
            .unwrap();

        assert!(
            GrantSessionRepository::get_by_token_hash(&s1.token_hash, &mut db.pool().into())
                .await
                .is_err()
        );
        assert!(
            GrantSessionRepository::get_by_token_hash(&s2.token_hash, &mut db.pool().into())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_nonexistent_session() {
        let db = SqlDb::test().await;
        let unknown = SessionTokenHash::try_from(vec![0u8; 32]).unwrap();
        let result =
            GrantSessionRepository::get_by_token_hash(&unknown, &mut db.pool().into()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn slots_rotate_at_capacity_and_expiry_frees_capacity() {
        let db = SqlDb::test().await;
        let grant = setup_user_and_grant(&db).await;
        let limits = GrantAuthToml {
            max_sessions_per_grant: 2.try_into().unwrap(),
            ..Default::default()
        };
        let a = slot(&grant);
        let b = slot(&grant);
        GrantSessionRepository::issue(&a, &db, &limits)
            .await
            .unwrap();
        GrantSessionRepository::issue(&b, &db, &limits)
            .await
            .unwrap();
        assert!(matches!(
            GrantSessionRepository::issue(&slot(&grant), &db, &limits).await,
            Err(SessionIssueError::Capacity)
        ));
        let mut refreshed = slot(&grant);
        refreshed.session_id = a.session_id.clone();
        GrantSessionRepository::issue(&refreshed, &db, &limits)
            .await
            .unwrap();
        assert!(
            GrantSessionRepository::get_by_token_hash(&a.token_hash, &mut db.pool().into())
                .await
                .is_err()
        );
        GrantSessionRepository::get_by_token_hash(&b.token_hash, &mut db.pool().into())
            .await
            .unwrap();
        // Simulate an abandoned tab's expiry; no unload request is needed.
        sqlx::query("UPDATE grant_sessions SET expires_at = 0 WHERE token_hash = $1")
            .bind(b.token_hash.as_ref())
            .execute(db.pool())
            .await
            .unwrap();
        GrantSessionRepository::issue(&slot(&grant), &db, &limits)
            .await
            .unwrap();
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM grant_sessions WHERE grant_id = $1")
                .bind(grant.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn concurrent_issuers_share_capacity_and_legacy_slot_is_isolated() {
        let db = SqlDb::test().await;
        let grant = setup_user_and_grant(&db).await;
        let limits = GrantAuthToml::default();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..30 {
            let db = db.clone();
            let limits = limits.clone();
            let session = slot(&grant);
            tasks.spawn(async move { GrantSessionRepository::issue(&session, &db, &limits).await });
        }
        let mut successes = 0;
        while let Some(result) = tasks.join_next().await {
            match result.unwrap() {
                Ok(()) => successes += 1,
                Err(SessionIssueError::Capacity) => (),
                other => panic!("unexpected issuance result: {other:?}"),
            }
        }
        assert_eq!(successes, 20);
        let mut limits = limits;
        limits.max_sessions_per_grant = 21.try_into().unwrap();
        for _ in 0..2 {
            let (legacy, _) = make_new_session(&grant);
            GrantSessionRepository::issue(&legacy, &db, &limits)
                .await
                .unwrap();
        }
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM grant_sessions WHERE grant_id = $1")
                .bind(grant.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(
            count, 21,
            "legacy refresh preserves every identified session"
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn rate_limit_and_revocation_do_not_replace_live_bearers() {
        let db = SqlDb::test().await;
        let grant = setup_user_and_grant(&db).await;
        let limits = GrantAuthToml {
            session_issuance_per_minute: 1.try_into().unwrap(),
            ..Default::default()
        };
        let a = slot(&grant);
        GrantSessionRepository::issue(&a, &db, &limits)
            .await
            .unwrap();
        let mut retry = slot(&grant);
        retry.session_id = a.session_id.clone();
        assert!(matches!(
            GrantSessionRepository::issue(&retry, &db, &limits).await,
            Err(SessionIssueError::RateLimited)
        ));
        GrantSessionRepository::get_by_token_hash(&a.token_hash, &mut db.pool().into())
            .await
            .unwrap();
        sqlx::query("UPDATE grants SET session_window_start = 0 WHERE id = $1")
            .bind(grant.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        GrantSessionRepository::issue(&retry, &db, &limits)
            .await
            .unwrap();
        GrantRepository::revoke(&grant, &mut db.pool().into())
            .await
            .unwrap();
        assert!(matches!(
            GrantSessionRepository::issue(&slot(&grant), &db, &limits).await,
            Err(SessionIssueError::Revoked)
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn issuance_waiting_for_logout_cannot_resurrect_sessions() {
        let db = SqlDb::test().await;
        let grant = setup_user_and_grant(&db).await;
        let mut tx = db.pool().begin().await.unwrap();
        sqlx::query("UPDATE grants SET revoked_at = 1 WHERE id = $1")
            .bind(grant.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        let session = slot(&grant);
        let task_db = db.clone();
        let task = tokio::spawn(async move {
            GrantSessionRepository::issue(&session, &task_db, &Default::default()).await
        });
        tx.commit().await.unwrap();
        assert!(matches!(
            task.await.unwrap(),
            Err(SessionIssueError::Revoked)
        ));
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM grant_sessions WHERE grant_id = $1")
                .bind(grant.to_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(count, 0);
    }
}
