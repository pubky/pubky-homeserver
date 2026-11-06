//! Repository for Grant entities (grant auth).

use pubky_common::{
    auth::{
        grant::GrantClaims,
        grant_session_responses::GrantKind,
        jws::{ClientId, GrantId},
    },
    capabilities::Capabilities,
    crypto::PublicKey,
};
use sea_query::{
    Expr, ExprTrait, Iden, LockType, PostgresQueryBuilder, Query, SelectStatement, SimpleExpr,
};
use sea_query_sqlx::SqlxBinder;
use sqlx::{postgres::PgRow, FromRow, Row};

use crate::persistence::sql::{
    entities::user::{UserIden, USER_TABLE},
    migrations::m20260325_create_grant_sessions::{GrantIden, GRANTS_TABLE},
    UnifiedExecutor,
};

/// Repository for grant CRUD operations.
pub struct GrantRepository;

impl GrantRepository {
    /// Insert a grant. Ignores if a grant with the same id already exists (idempotent).
    pub async fn create<'a>(
        grant: &NewGrant,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let statement = Query::insert()
            .into_table(GRANTS_TABLE)
            .columns([
                GrantIden::Id,
                GrantIden::User,
                GrantIden::ClientId,
                GrantIden::ClientCnfKey,
                GrantIden::Capabilities,
                GrantIden::IssuedAt,
                GrantIden::ExpiresAt,
                GrantIden::Kind,
                GrantIden::ParentId,
                GrantIden::RevokedAt,
            ])
            .values(vec![
                SimpleExpr::Value(grant.id.to_string().into()),
                SimpleExpr::Value(grant.user_id.into()),
                SimpleExpr::Value(grant.client_id.to_string().into()),
                SimpleExpr::Value(grant.client_cnf_key.clone().into()),
                SimpleExpr::Value(grant.capabilities.to_string().into()),
                SimpleExpr::Value((grant.issued_at as i64).into()),
                SimpleExpr::Value((grant.expires_at as i64).into()),
                SimpleExpr::Value(grant.kind.as_str().into()),
                SimpleExpr::Value(grant.parent_id.as_ref().map(ToString::to_string).into()),
                SimpleExpr::Value(grant.revoked_at.into()),
            ])
            .expect("invariant: values count matches columns count")
            .on_conflict(
                sea_query::OnConflict::column(GrantIden::Id)
                    .do_nothing()
                    .to_owned(),
            )
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_with(&query, values).execute(con).await?;
        Ok(())
    }

    /// Select a grant with its user's public key.
    fn select_grant() -> SelectStatement {
        Query::select()
            .from(GRANTS_TABLE)
            .columns([
                (GRANTS_TABLE, GrantIden::Id),
                (GRANTS_TABLE, GrantIden::User),
                (GRANTS_TABLE, GrantIden::ClientId),
                (GRANTS_TABLE, GrantIden::ClientCnfKey),
                (GRANTS_TABLE, GrantIden::Capabilities),
                (GRANTS_TABLE, GrantIden::IssuedAt),
                (GRANTS_TABLE, GrantIden::ExpiresAt),
                (GRANTS_TABLE, GrantIden::RevokedAt),
                (GRANTS_TABLE, GrantIden::CreatedAt),
                (GRANTS_TABLE, GrantIden::Kind),
                (GRANTS_TABLE, GrantIden::ParentId),
            ])
            .column((USER_TABLE, UserIden::PublicKey))
            .left_join(
                USER_TABLE,
                Expr::col((GRANTS_TABLE, GrantIden::User))
                    .eq(Expr::col((USER_TABLE, UserIden::Id))),
            )
            .to_owned()
    }

    /// Get a grant by its id.
    pub async fn get_by_id<'a>(
        grant_id: &GrantId,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<GrantEntity, sqlx::Error> {
        let statement = Self::select_grant()
            .and_where(Expr::col((GRANTS_TABLE, GrantIden::Id)).eq(grant_id.to_string()))
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values).fetch_one(con).await
    }

    /// Lock a grant row until the transaction ends and return its current state.
    ///
    /// Lifecycle changes under a parent lock the parent first, which serializes
    /// them without a separate lock service.
    pub async fn get_for_update<'a>(
        grant_id: &GrantId,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<GrantEntity, sqlx::Error> {
        let statement = Self::select_grant()
            .and_where(Expr::col((GRANTS_TABLE, GrantIden::Id)).eq(grant_id.to_string()))
            .lock_with_tables(LockType::Update, [GRANTS_TABLE])
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values).fetch_one(con).await
    }

    /// Revoke a grant by setting revoked_at to the current unix timestamp.
    ///
    /// A grant that is already revoked keeps its original time.
    pub async fn revoke<'a>(
        grant_id: &GrantId,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let statement = Query::update()
            .table(GRANTS_TABLE)
            .value(GrantIden::RevokedAt, SimpleExpr::Value(now.into()))
            .and_where(Expr::col(GrantIden::Id).eq(grant_id.to_string()))
            .and_where(Expr::col(GrantIden::RevokedAt).is_null())
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_with(&query, values).execute(con).await?;
        Ok(())
    }

    /// Check if a grant has been revoked.
    pub async fn is_revoked<'a>(
        grant_id: &GrantId,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<bool, sqlx::Error> {
        let statement = Query::select()
            .from(GRANTS_TABLE)
            .column(GrantIden::RevokedAt)
            .and_where(Expr::col(GrantIden::Id).eq(grant_id.to_string()))
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let row: PgRow = sqlx::query_with(&query, values).fetch_one(con).await?;
        let revoked_at: Option<i64> = row.try_get(GrantIden::RevokedAt.to_string().as_str())?;
        Ok(revoked_at.is_some())
    }

    /// List all active (non-revoked, non-expired) grants for a user.
    pub async fn list_active_for_user<'a>(
        user_id: i32,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<GrantEntity>, sqlx::Error> {
        let now = chrono::Utc::now().timestamp();
        let statement = Self::select_grant()
            .and_where(Expr::col((GRANTS_TABLE, GrantIden::User)).eq(user_id))
            .and_where(Expr::col((GRANTS_TABLE, GrantIden::RevokedAt)).is_null())
            .and_where(Expr::col((GRANTS_TABLE, GrantIden::ExpiresAt)).gt(now))
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values).fetch_all(con).await
    }

    /// Revoke a parent's unrevoked children, optionally only one app's, and
    /// return their ids.
    pub async fn revoke_children<'a>(
        parent_id: &GrantId,
        client_id: Option<&ClientId>,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<GrantId>, sqlx::Error> {
        let con = executor.get_con().await?;
        let ids: Vec<String> = sqlx::query_scalar(
            "UPDATE grants SET revoked_at = $1
             WHERE parent_id = $2 AND revoked_at IS NULL AND ($3::TEXT IS NULL OR client_id = $3)
             RETURNING id",
        )
        .bind(chrono::Utc::now().timestamp())
        .bind(parent_id.as_str())
        .bind(client_id.map(ClientId::as_str))
        .fetch_all(con)
        .await?;
        ids.iter()
            .map(|id| GrantId::parse(id).map_err(|e| sqlx::Error::Decode(e.into())))
            .collect()
    }

    /// Block an app from silently reconnecting under a parent.
    pub async fn block_app<'a>(
        user_id: i32,
        parent_id: &GrantId,
        client_id: &ClientId,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let con = executor.get_con().await?;
        sqlx::query(
            r#"INSERT INTO grant_app_blocks ("user", parent_id, client_id) VALUES ($1, $2, $3)
               ON CONFLICT DO NOTHING"#,
        )
        .bind(user_id)
        .bind(parent_id.as_str())
        .bind(client_id.as_str())
        .execute(con)
        .await?;
        Ok(())
    }

    /// Remove an app's block under a parent. Does nothing if there is none.
    pub async fn unblock_app<'a>(
        user_id: i32,
        parent_id: &GrantId,
        client_id: &ClientId,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let con = executor.get_con().await?;
        sqlx::query(
            r#"DELETE FROM grant_app_blocks WHERE "user" = $1 AND parent_id = $2 AND client_id = $3"#,
        )
        .bind(user_id)
        .bind(parent_id.as_str())
        .bind(client_id.as_str())
        .execute(con)
        .await?;
        Ok(())
    }

    /// Whether an app is blocked under a parent.
    pub async fn is_app_blocked<'a>(
        user_id: i32,
        parent_id: &GrantId,
        client_id: &ClientId,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<bool, sqlx::Error> {
        let con = executor.get_con().await?;
        sqlx::query_scalar(
            r#"SELECT EXISTS (
                SELECT 1 FROM grant_app_blocks
                WHERE "user" = $1 AND parent_id = $2 AND client_id = $3
            )"#,
        )
        .bind(user_id)
        .bind(parent_id.as_str())
        .bind(client_id.as_str())
        .fetch_one(con)
        .await
    }

    /// Load what a child's session depends on beyond the child itself: its
    /// parent's lifetime, and whether its app is blocked under that parent.
    ///
    /// One query, because every request from a child session checks both.
    pub async fn get_parent_state<'a>(
        user_id: i32,
        parent_id: &GrantId,
        client_id: &ClientId,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<ParentState, sqlx::Error> {
        let con = executor.get_con().await?;
        let (revoked_at, expires_at, app_blocked) = sqlx::query_as(
            r#"SELECT revoked_at, expires_at, EXISTS (
                SELECT 1 FROM grant_app_blocks
                WHERE "user" = $1 AND parent_id = $2 AND client_id = $3
            )
            FROM grants WHERE id = $2"#,
        )
        .bind(user_id)
        .bind(parent_id.as_str())
        .bind(client_id.as_str())
        .fetch_one(con)
        .await?;
        Ok(ParentState {
            revoked_at,
            expires_at,
            app_blocked,
        })
    }
}

/// A parent's lifetime and whether one app is blocked under it.
#[derive(Debug, Clone, Copy)]
pub struct ParentState {
    revoked_at: Option<i64>,
    expires_at: i64,
    /// Whether the app is blocked under this parent.
    pub app_blocked: bool,
}

impl ParentState {
    /// Check that the parent is active (not revoked, not expired).
    pub fn require_active(&self, now_unix: i64) -> Result<(), GrantStatus> {
        require_active(self.revoked_at, self.expires_at, now_unix)
    }
}

/// Data needed to create a new grant.
pub struct NewGrant {
    pub id: GrantId,
    pub user_id: i32,
    pub client_id: ClientId,
    pub client_cnf_key: String,
    pub capabilities: Capabilities,
    pub issued_at: u64,
    pub expires_at: u64,
    pub kind: GrantKind,
    pub parent_id: Option<GrantId>,
    /// Set to record an unseen grant as already revoked.
    pub revoked_at: Option<i64>,
}

impl NewGrant {
    /// Build the record for verified grant claims.
    pub fn from_claims(
        claims: &GrantClaims,
        user_id: i32,
        kind: GrantKind,
        parent_id: Option<GrantId>,
    ) -> Self {
        Self {
            id: claims.jti.clone(),
            user_id,
            client_id: claims.client_id.clone(),
            client_cnf_key: claims.cnf.z32(),
            capabilities: claims.caps.clone().into(),
            issued_at: claims.iat,
            expires_at: claims.exp,
            kind,
            parent_id,
            revoked_at: None,
        }
    }
}

/// A grant entity as stored in the database.
#[derive(Debug, Clone)]
pub struct GrantEntity {
    pub id: GrantId,
    pub user_id: i32,
    pub user_pubkey: PublicKey,
    pub client_id: ClientId,
    #[allow(dead_code)]
    pub client_cnf_key: String,
    pub capabilities: Capabilities,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub created_at: sqlx::types::chrono::NaiveDateTime,
    pub kind: GrantKind,
    pub parent_id: Option<GrantId>,
}

/// Why a grant is no longer active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStatus {
    Revoked,
    Expired,
}

/// Check that a grant with these timestamps is active (not revoked, not expired).
fn require_active(
    revoked_at: Option<i64>,
    expires_at: i64,
    now_unix: i64,
) -> Result<(), GrantStatus> {
    if revoked_at.is_some() {
        return Err(GrantStatus::Revoked);
    }
    if expires_at <= now_unix {
        return Err(GrantStatus::Expired);
    }
    Ok(())
}

impl GrantEntity {
    /// Check that this grant is active (not revoked, not expired).
    pub fn require_active(&self, now_unix: i64) -> Result<(), GrantStatus> {
        require_active(self.revoked_at, self.expires_at, now_unix)
    }

    /// Whether this record holds the same authorization claims as `grant`.
    ///
    /// A grant ID identifies one set of claims, so a repeated use must match
    /// everything that decides who the grant authorizes and for what.
    pub fn has_same_claims(&self, grant: &NewGrant) -> bool {
        self.user_id == grant.user_id
            && self.kind == grant.kind
            && self.parent_id == grant.parent_id
            && self.client_id == grant.client_id
            && self.client_cnf_key == grant.client_cnf_key
            && self.capabilities == grant.capabilities
            && self.issued_at == grant.issued_at as i64
            && self.expires_at == grant.expires_at as i64
    }
}

impl FromRow<'_, PgRow> for GrantEntity {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        let (id, user_id, user_pubkey, client_id, client_cnf_key) = parse_identity_fields(row)?;
        let (capabilities, issued_at, expires_at, revoked_at, created_at) =
            parse_grant_metadata(row)?;
        let (kind, parent_id) = parse_kind_and_parent(row)?;
        Ok(GrantEntity {
            id,
            user_id,
            user_pubkey,
            client_id,
            client_cnf_key,
            capabilities,
            issued_at,
            expires_at,
            revoked_at,
            created_at,
            kind,
            parent_id,
        })
    }
}

fn parse_identity_fields(
    row: &PgRow,
) -> Result<(GrantId, i32, PublicKey, ClientId, String), sqlx::Error> {
    let id: String = row.try_get(GrantIden::Id.to_string().as_str())?;
    let id = GrantId::parse(&id).map_err(|e| sqlx::Error::Decode(e.into()))?;
    let user_id: i32 = row.try_get(GrantIden::User.to_string().as_str())?;
    let user_pubkey: String = row.try_get(UserIden::PublicKey.to_string().as_str())?;
    let user_pubkey: PublicKey = user_pubkey
        .try_into()
        .map_err(|e: pkarr::errors::PublicKeyError| sqlx::Error::Decode(e.into()))?;
    let client_id: String = row.try_get(GrantIden::ClientId.to_string().as_str())?;
    let client_id = ClientId::new(&client_id).map_err(|e| sqlx::Error::Decode(e.into()))?;
    let client_cnf_key: String = row.try_get(GrantIden::ClientCnfKey.to_string().as_str())?;
    Ok((id, user_id, user_pubkey, client_id, client_cnf_key))
}

fn parse_grant_metadata(
    row: &PgRow,
) -> Result<
    (
        Capabilities,
        i64,
        i64,
        Option<i64>,
        sqlx::types::chrono::NaiveDateTime,
    ),
    sqlx::Error,
> {
    let capabilities: String = row.try_get(GrantIden::Capabilities.to_string().as_str())?;
    let capabilities: Capabilities =
        capabilities
            .parse()
            .map_err(|e: pubky_common::capabilities::CapabilitiesParseError| {
                sqlx::Error::Decode(e.into())
            })?;
    let issued_at: i64 = row.try_get(GrantIden::IssuedAt.to_string().as_str())?;
    let expires_at: i64 = row.try_get(GrantIden::ExpiresAt.to_string().as_str())?;
    let revoked_at: Option<i64> = row.try_get(GrantIden::RevokedAt.to_string().as_str())?;
    let created_at = row.try_get(GrantIden::CreatedAt.to_string().as_str())?;
    Ok((capabilities, issued_at, expires_at, revoked_at, created_at))
}

fn parse_kind_and_parent(row: &PgRow) -> Result<(GrantKind, Option<GrantId>), sqlx::Error> {
    let kind: String = row.try_get(GrantIden::Kind.to_string().as_str())?;
    let kind = match kind.as_str() {
        "direct" => GrantKind::Direct,
        "parent" => GrantKind::Parent,
        "child" => GrantKind::Child,
        other => {
            return Err(sqlx::Error::Decode(
                format!("unknown grant kind {other}").into(),
            ))
        }
    };
    let parent_id: Option<String> = row.try_get(GrantIden::ParentId.to_string().as_str())?;
    let parent_id = parent_id
        .map(|id| GrantId::parse(&id))
        .transpose()
        .map_err(|e| sqlx::Error::Decode(e.into()))?;
    Ok((kind, parent_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_common::{
        auth::jws::{ClientId, GrantId},
        capabilities::{Capabilities, Capability},
        crypto::Keypair,
    };

    use crate::persistence::sql::SqlDb;
    use crate::services::user_service::UserService;

    fn make_new_grant(user_id: i32) -> NewGrant {
        let now = chrono::Utc::now().timestamp() as u64;
        NewGrant {
            id: GrantId::generate(),
            user_id,
            client_id: ClientId::new("test.app").unwrap(),
            client_cnf_key: Keypair::random().public_key().z32(),
            capabilities: Capabilities::builder().cap(Capability::root()).finish(),
            issued_at: now,
            expires_at: now + 3600,
            kind: GrantKind::Direct,
            parent_id: None,
            revoked_at: None,
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_and_get_grant() {
        let db = SqlDb::test().await;
        let keypair = Keypair::random();
        let user = UserService::new(db.clone())
            .create(&keypair.public_key())
            .await
            .unwrap();

        let new_grant = make_new_grant(user.id);
        let grant_id = new_grant.id.clone();
        let client_id = new_grant.client_id.clone();
        let caps = new_grant.capabilities.clone();
        let issued_at = new_grant.issued_at;
        let expires_at = new_grant.expires_at;

        GrantRepository::create(&new_grant, &mut db.pool().into())
            .await
            .unwrap();

        let entity = GrantRepository::get_by_id(&grant_id, &mut db.pool().into())
            .await
            .unwrap();

        assert_eq!(entity.id, grant_id);
        assert_eq!(entity.user_id, user.id);
        assert_eq!(entity.user_pubkey, keypair.public_key());
        assert_eq!(entity.client_id, client_id);
        assert_eq!(entity.capabilities, caps);
        assert_eq!(entity.issued_at, issued_at as i64);
        assert_eq!(entity.expires_at, expires_at as i64);
        assert!(entity.revoked_at.is_none());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_grant_is_idempotent() {
        let db = SqlDb::test().await;
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();

        let new_grant = make_new_grant(user.id);
        GrantRepository::create(&new_grant, &mut db.pool().into())
            .await
            .unwrap();
        // Second insert with same grant_id should succeed (ON CONFLICT DO NOTHING)
        GrantRepository::create(&new_grant, &mut db.pool().into())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_revoke_and_is_revoked() {
        let db = SqlDb::test().await;
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();

        let new_grant = make_new_grant(user.id);
        let grant_id = new_grant.id.clone();
        GrantRepository::create(&new_grant, &mut db.pool().into())
            .await
            .unwrap();

        assert!(
            !GrantRepository::is_revoked(&grant_id, &mut db.pool().into())
                .await
                .unwrap()
        );

        GrantRepository::revoke(&grant_id, &mut db.pool().into())
            .await
            .unwrap();

        assert!(
            GrantRepository::is_revoked(&grant_id, &mut db.pool().into())
                .await
                .unwrap()
        );

        let entity = GrantRepository::get_by_id(&grant_id, &mut db.pool().into())
            .await
            .unwrap();
        assert!(entity.revoked_at.is_some());

        // Revoking again keeps the original time.
        sqlx::query("UPDATE grants SET revoked_at = 1 WHERE id = $1")
            .bind(grant_id.as_str())
            .execute(db.pool())
            .await
            .unwrap();
        GrantRepository::revoke(&grant_id, &mut db.pool().into())
            .await
            .unwrap();
        let entity = GrantRepository::get_by_id(&grant_id, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(entity.revoked_at, Some(1));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_active_for_user() {
        let db = SqlDb::test().await;
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();

        // Active grant
        let active = make_new_grant(user.id);
        let active_id = active.id.clone();
        GrantRepository::create(&active, &mut db.pool().into())
            .await
            .unwrap();

        // Revoked grant
        let revoked = make_new_grant(user.id);
        let revoked_id = revoked.id.clone();
        GrantRepository::create(&revoked, &mut db.pool().into())
            .await
            .unwrap();
        GrantRepository::revoke(&revoked_id, &mut db.pool().into())
            .await
            .unwrap();

        // Expired grant
        let now = chrono::Utc::now().timestamp() as u64;
        let mut expired = make_new_grant(user.id);
        expired.issued_at = now.saturating_sub(7200);
        expired.expires_at = now.saturating_sub(3600);
        GrantRepository::create(&expired, &mut db.pool().into())
            .await
            .unwrap();

        let list = GrantRepository::list_active_for_user(user.id, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, active_id);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_active_for_user_empty() {
        let db = SqlDb::test().await;
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();

        let list = GrantRepository::list_active_for_user(user.id, &mut db.pool().into())
            .await
            .unwrap();
        assert!(list.is_empty());
    }

    fn make_grant_entity(expires_at: i64, revoked_at: Option<i64>) -> GrantEntity {
        GrantEntity {
            id: GrantId::generate(),
            user_id: 1,
            user_pubkey: Keypair::random().public_key(),
            client_id: ClientId::new("test.app").unwrap(),
            client_cnf_key: Keypair::random().public_key().z32(),
            capabilities: Capabilities::builder().cap(Capability::root()).finish(),
            issued_at: 1000,
            expires_at,
            revoked_at,
            created_at: chrono::Utc::now().naive_utc(),
            kind: GrantKind::Direct,
            parent_id: None,
        }
    }

    #[test]
    fn require_active_passes_for_active_grant() {
        let grant = make_grant_entity(2000, None);
        assert!(grant.require_active(1500).is_ok());
    }

    #[test]
    fn require_active_returns_revoked() {
        let grant = make_grant_entity(2000, Some(1500));
        assert_eq!(
            grant.require_active(1500).unwrap_err(),
            GrantStatus::Revoked
        );
    }

    #[test]
    fn require_active_returns_expired() {
        let grant = make_grant_entity(1000, None);
        assert_eq!(
            grant.require_active(1500).unwrap_err(),
            GrantStatus::Expired
        );
    }

    #[test]
    fn require_active_boundary_expires_at_equals_now() {
        let grant = make_grant_entity(1000, None);
        assert_eq!(
            grant.require_active(1000).unwrap_err(),
            GrantStatus::Expired
        );
    }

    #[test]
    fn require_active_revoked_takes_precedence_over_expired() {
        let grant = make_grant_entity(1000, Some(900));
        assert_eq!(
            grant.require_active(1500).unwrap_err(),
            GrantStatus::Revoked
        );
    }

    #[test]
    fn has_same_claims_compares_every_authorization_claim() {
        let stored = make_grant_entity(2000, None);
        let matching = || NewGrant {
            id: stored.id.clone(),
            user_id: stored.user_id,
            client_id: stored.client_id.clone(),
            client_cnf_key: stored.client_cnf_key.clone(),
            capabilities: stored.capabilities.clone(),
            issued_at: stored.issued_at as u64,
            expires_at: stored.expires_at as u64,
            kind: stored.kind,
            parent_id: stored.parent_id.clone(),
            revoked_at: None,
        };
        assert!(stored.has_same_claims(&matching()));

        type Edit = fn(&mut NewGrant);
        let edits: [Edit; 8] = [
            |g| g.user_id += 1,
            |g| g.kind = GrantKind::Parent,
            |g| g.parent_id = Some(GrantId::generate()),
            |g| g.client_id = ClientId::new("other.app").unwrap(),
            |g| g.client_cnf_key = Keypair::random().public_key().z32(),
            |g| g.capabilities = "/pub/:r".parse().unwrap(),
            |g| g.issued_at += 1,
            |g| g.expires_at += 1,
        ];
        for edit in edits {
            let mut changed = matching();
            edit(&mut changed);
            assert!(!stored.has_same_claims(&changed));
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn one_app_keeps_one_unrevoked_child_per_parent() {
        let db = SqlDb::test().await;
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let mut parent = make_new_grant(user.id);
        parent.kind = GrantKind::Parent;
        GrantRepository::create(&parent, &mut db.pool().into())
            .await
            .unwrap();
        let child = |client_id: &str| {
            let mut child = make_new_grant(user.id);
            child.kind = GrantKind::Child;
            child.parent_id = Some(parent.id.clone());
            child.client_id = ClientId::new(client_id).unwrap();
            child
        };

        let first = child("https://a.example/cb");
        GrantRepository::create(&first, &mut db.pool().into())
            .await
            .unwrap();
        let duplicate = child("https://a.example/cb");
        assert!(matches!(
            GrantRepository::create(&duplicate, &mut db.pool().into()).await,
            Err(sqlx::Error::Database(e)) if e.is_unique_violation()
        ));

        // Another app and a revoked record are outside the constraint.
        GrantRepository::create(&child("https://b.example/cb"), &mut db.pool().into())
            .await
            .unwrap();
        let revoked = GrantRepository::revoke_children(
            &parent.id,
            Some(&first.client_id),
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        assert_eq!(revoked, vec![first.id]);
        GrantRepository::create(&child("https://a.example/cb"), &mut db.pool().into())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn app_blocks_are_scoped_to_user_parent_and_callback() {
        let db = SqlDb::test().await;
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let parent = make_new_grant(user.id);
        let other_parent = make_new_grant(user.id);
        for grant in [&parent, &other_parent] {
            GrantRepository::create(grant, &mut db.pool().into())
                .await
                .unwrap();
        }
        let app = ClientId::new("https://a.example/cb").unwrap();
        let other_app = ClientId::new("https://a.example/cb/").unwrap();
        let blocked = |parent_id: GrantId, client_id: ClientId| {
            let db = db.clone();
            async move {
                GrantRepository::is_app_blocked(
                    user.id,
                    &parent_id,
                    &client_id,
                    &mut db.pool().into(),
                )
                .await
                .unwrap()
            }
        };

        for _ in 0..2 {
            GrantRepository::block_app(user.id, &parent.id, &app, &mut db.pool().into())
                .await
                .unwrap();
        }
        assert!(blocked(parent.id.clone(), app.clone()).await);
        assert!(!blocked(parent.id.clone(), other_app).await);
        assert!(!blocked(other_parent.id.clone(), app.clone()).await);

        GrantRepository::unblock_app(user.id, &parent.id, &app, &mut db.pool().into())
            .await
            .unwrap();
        assert!(!blocked(parent.id.clone(), app.clone()).await);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn parent_state_reports_the_parent_lifetime_and_the_app_block() {
        let db = SqlDb::test().await;
        let user = UserService::new(db.clone())
            .create(&Keypair::random().public_key())
            .await
            .unwrap();
        let parent = make_new_grant(user.id);
        GrantRepository::create(&parent, &mut db.pool().into())
            .await
            .unwrap();
        let app = ClientId::new("https://a.example/cb").unwrap();
        let state = |parent_id: GrantId| {
            let (db, app) = (db.clone(), app.clone());
            async move {
                GrantRepository::get_parent_state(user.id, &parent_id, &app, &mut db.pool().into())
                    .await
            }
        };
        let now = parent.issued_at as i64;

        let active = state(parent.id.clone()).await.unwrap();
        assert!(!active.app_blocked);
        assert_eq!(active.require_active(now), Ok(()));
        assert_eq!(
            active.require_active(parent.expires_at as i64),
            Err(GrantStatus::Expired)
        );

        GrantRepository::block_app(user.id, &parent.id, &app, &mut db.pool().into())
            .await
            .unwrap();
        GrantRepository::revoke(&parent.id, &mut db.pool().into())
            .await
            .unwrap();
        let ended = state(parent.id.clone()).await.unwrap();
        assert!(ended.app_blocked);
        assert_eq!(ended.require_active(now), Err(GrantStatus::Revoked));

        // A missing parent is an error, never an active parent.
        assert!(matches!(
            state(GrantId::generate()).await,
            Err(sqlx::Error::RowNotFound)
        ));
    }
}
