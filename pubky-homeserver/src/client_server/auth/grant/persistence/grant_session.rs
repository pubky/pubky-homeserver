//! Repository for grant-based session entities.

use pubky_common::auth::jws::GrantId;
use sea_query::{
    Alias, CommonTableExpression, Expr, Iden, PostgresQueryBuilder, Query, WithClause, WithQuery,
};
use sea_query_binder::SqlxBinder;
use sqlx::{postgres::PgRow, FromRow, Row};

use crate::client_server::auth::grant::crypto::session_token::SessionTokenHash;
use crate::persistence::sql::{
    migrations::m20260325_create_grant_sessions::{GrantSessionIden, GRANT_SESSIONS_TABLE},
    UnifiedExecutor,
};

/// Repository for grant-based session CRUD operations.
pub struct GrantSessionRepository;

impl GrantSessionRepository {
    /// Atomically replace any existing session for this grant with the new one.
    ///
    /// Enforces the "1 session per grant" invariant. Implemented as a CTE
    /// (DELETE then INSERT) in a single statement so that two concurrent
    /// `mint_session` calls for the same grant cannot both observe 0 prior
    /// sessions and produce 2 rows. Do **not** split into
    /// `delete_all_for_grant` followed by an insert — `mint_session` is
    /// called outside a transaction in `AuthService::create_grant_session`,
    /// so the atomicity must come from the SQL statement itself.
    pub async fn replace_for_grant<'a>(
        session: &NewGrantSession,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let delete_cte = CommonTableExpression::new()
            .query(
                Query::delete()
                    .from_table(GRANT_SESSIONS_TABLE)
                    .and_where(
                        Expr::col(GrantSessionIden::GrantId).eq(session.grant_id.to_string()),
                    )
                    .to_owned(),
            )
            .table_name(Alias::new("delete_old"))
            .to_owned();

        let insert = Query::insert()
            .into_table(GRANT_SESSIONS_TABLE)
            .columns([
                GrantSessionIden::TokenHash,
                GrantSessionIden::GrantId,
                GrantSessionIden::ExpiresAt,
            ])
            .values_panic([
                session.token_hash.as_ref().to_vec().into(),
                session.grant_id.to_string().into(),
                (session.expires_at as i64).into(),
            ])
            .to_owned();

        let statement = WithQuery::new()
            .with_clause(WithClause::new().cte(delete_cte).to_owned())
            .query(insert)
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_with(&query, values).execute(con).await?;
        Ok(())
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
    pub token_hash: SessionTokenHash,
    pub grant_id: GrantId,
    pub expires_at: u64,
}

/// A grant session entity as stored in the database.
#[derive(Debug, Clone)]
#[allow(dead_code)] // `id`, `token_hash`, `created_at` are decoded from DB rows for completeness but only consumed in tests.
pub struct GrantSessionEntity {
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

        Ok(GrantSessionEntity {
            id,
            token_hash,
            grant_id,
            expires_at,
            created_at,
        })
    }
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
    use crate::persistence::sql::SqlDb;
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
                token_hash: hash,
                grant_id: grant_id.clone(),
                expires_at: now + 3600,
            },
            hash,
        )
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_and_get_session() {
        let db = SqlDb::test().await;
        let grant_id = setup_user_and_grant(&db).await;

        let (new_session, hash) = make_new_session(&grant_id);
        let expires_at = new_session.expires_at;

        GrantSessionRepository::replace_for_grant(&new_session, &mut db.pool().into())
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
    async fn test_session_limit_evicts_oldest() {
        let db = SqlDb::test().await;
        let grant_id = setup_user_and_grant(&db).await;

        // With MAX_SESSIONS_PER_GRANT = 1, each new session evicts the previous one.
        let (s1, s1_hash) = make_new_session(&grant_id);
        GrantSessionRepository::replace_for_grant(&s1, &mut db.pool().into())
            .await
            .unwrap();

        // s2 evicts s1
        let (s2, s2_hash) = make_new_session(&grant_id);
        GrantSessionRepository::replace_for_grant(&s2, &mut db.pool().into())
            .await
            .unwrap();

        let result =
            GrantSessionRepository::get_by_token_hash(&s1_hash, &mut db.pool().into()).await;
        assert!(result.is_err(), "s1 should have been evicted by s2");

        // s3 evicts s2
        let (s3, s3_hash) = make_new_session(&grant_id);
        GrantSessionRepository::replace_for_grant(&s3, &mut db.pool().into())
            .await
            .unwrap();

        let result =
            GrantSessionRepository::get_by_token_hash(&s2_hash, &mut db.pool().into()).await;
        assert!(result.is_err(), "s2 should have been evicted by s3");

        // Only s3 survives
        GrantSessionRepository::get_by_token_hash(&s3_hash, &mut db.pool().into())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_session_limit_different_grants_independent() {
        let db = SqlDb::test().await;
        let grant_a = setup_user_and_grant(&db).await;

        // Create a second grant for the same user
        let grant_b_id = GrantId::generate();
        let now = chrono::Utc::now().timestamp() as u64;
        let pubkey = Keypair::random().public_key();
        let user = UserService::new(db.clone()).create(&pubkey).await.unwrap();
        let new_grant_b = NewGrant {
            id: grant_b_id.clone(),
            user_id: user.id,
            client_id: ClientId::new("other.app").unwrap(),
            client_cnf_key: Keypair::random().public_key().z32(),
            capabilities: Capabilities::builder().cap(Capability::root()).finish(),
            issued_at: now,
            expires_at: now + 3600,
        };
        GrantRepository::create(&new_grant_b, &mut db.pool().into())
            .await
            .unwrap();

        // With MAX_SESSIONS_PER_GRANT = 1, each grant independently holds 1 session.
        // sa2 evicts sa1, sb2 evicts sb1.
        let (sa1, _) = make_new_session(&grant_a);
        GrantSessionRepository::replace_for_grant(&sa1, &mut db.pool().into())
            .await
            .unwrap();
        let (sa2, sa2_hash) = make_new_session(&grant_a);
        GrantSessionRepository::replace_for_grant(&sa2, &mut db.pool().into())
            .await
            .unwrap();

        let (sb1, _) = make_new_session(&grant_b_id);
        GrantSessionRepository::replace_for_grant(&sb1, &mut db.pool().into())
            .await
            .unwrap();
        let (sb2, sb2_hash) = make_new_session(&grant_b_id);
        GrantSessionRepository::replace_for_grant(&sb2, &mut db.pool().into())
            .await
            .unwrap();

        // Only the latest session per grant survives
        GrantSessionRepository::get_by_token_hash(&sa2_hash, &mut db.pool().into())
            .await
            .unwrap();
        GrantSessionRepository::get_by_token_hash(&sb2_hash, &mut db.pool().into())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_delete_all_for_grant() {
        let db = SqlDb::test().await;
        let grant_id = setup_user_and_grant(&db).await;

        let (s1, s1_hash) = make_new_session(&grant_id);
        GrantSessionRepository::replace_for_grant(&s1, &mut db.pool().into())
            .await
            .unwrap();

        let (s2, s2_hash) = make_new_session(&grant_id);
        GrantSessionRepository::replace_for_grant(&s2, &mut db.pool().into())
            .await
            .unwrap();

        GrantSessionRepository::delete_all_for_grant(&grant_id, &mut db.pool().into())
            .await
            .unwrap();

        assert!(
            GrantSessionRepository::get_by_token_hash(&s1_hash, &mut db.pool().into())
                .await
                .is_err()
        );
        assert!(
            GrantSessionRepository::get_by_token_hash(&s2_hash, &mut db.pool().into())
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
}
