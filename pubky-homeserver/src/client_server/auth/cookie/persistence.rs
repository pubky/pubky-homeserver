//! Cookie session persistence — entity and repository.
//!
//! Manages the deprecated `sessions` table used by cookie-based authentication.

use std::{fmt::Display, str::FromStr};

use pubky_common::crypto::PublicKey;
use pubky_common::{
    capabilities::Capabilities, crypto::random_bytes, session::CookieSessionRecord,
};
use sea_query::{Expr, Iden, PostgresQueryBuilder, Query, SimpleExpr};
use sea_query_binder::SqlxBinder;
use sqlx::{postgres::PgRow, FromRow, Row};

use crate::persistence::sql::{
    entities::user::{UserIden, USER_TABLE},
    UnifiedExecutor,
};

pub const SESSION_TABLE: &str = "sessions";

/// Repository for deprecated cookie-based sessions.
pub struct SessionRepository;

impl SessionRepository {
    /// Create a new session.
    /// The executor can either be db.pool() or a transaction.
    pub async fn create<'a>(
        user_id: i32,
        capabilities: &Capabilities,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SessionSecret, sqlx::Error> {
        let session_secret = base32::encode(base32::Alphabet::Crockford, &random_bytes::<16>());
        let statement = Query::insert()
            .into_table(SESSION_TABLE)
            .columns([
                SessionIden::Secret,
                SessionIden::User,
                SessionIden::Capabilities,
            ])
            .values(vec![
                SimpleExpr::Value(session_secret.into()),
                SimpleExpr::Value(user_id.into()),
                SimpleExpr::Value(capabilities.to_string().into()),
            ])
            .expect("Failed to build insert statement")
            .returning_col(SessionIden::Secret)
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);

        let con = executor.get_con().await?;
        let row: PgRow = sqlx::query_with(&query, values).fetch_one(con).await?;
        let session_secret: String = row.try_get(SessionIden::Secret.to_string().as_str())?;
        SessionSecret::new(session_secret).map_err(|e| sqlx::Error::Decode(e.into()))
    }

    /// Get a session by its secret.
    /// The executor can either be db.pool() or a transaction.
    pub async fn get_by_secret<'a>(
        secret: &SessionSecret,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SessionEntity, sqlx::Error> {
        let statement = Query::select()
            .from(SESSION_TABLE)
            .columns([
                (SESSION_TABLE, SessionIden::Id),
                (SESSION_TABLE, SessionIden::Secret),
                (SESSION_TABLE, SessionIden::User),
                (SESSION_TABLE, SessionIden::Capabilities),
                (SESSION_TABLE, SessionIden::CreatedAt),
            ])
            .column((USER_TABLE, UserIden::PublicKey))
            .left_join(
                USER_TABLE,
                Expr::col((SESSION_TABLE, SessionIden::User))
                    .eq(Expr::col((USER_TABLE, UserIden::Id))),
            )
            .and_where(Expr::col((SESSION_TABLE, SessionIden::Secret)).eq(secret.to_string()))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let user: SessionEntity = sqlx::query_as_with(&query, values).fetch_one(con).await?;
        Ok(user)
    }

    /// Delete a session by its secret.
    /// The executor can either be db.pool() or a transaction.
    pub async fn delete<'a>(
        secret: &SessionSecret,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let statement = Query::delete()
            .from_table(SESSION_TABLE)
            .and_where(Expr::col(SessionIden::Secret).eq(secret.to_string()))
            .to_owned();

        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_with(&query, values).execute(con).await?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SessionSecret(String);

impl SessionSecret {
    pub fn new(secret: String) -> anyhow::Result<Self> {
        if secret.len() != 26 {
            return Err(anyhow::anyhow!("Invalid session secret length"));
        }
        Ok(Self(secret))
    }

    /// Check if a string is a valid session secret.
    pub fn is_valid(value: &str) -> bool {
        if value.len() != 26 {
            return false;
        }
        let decoded = base32::decode(base32::Alphabet::Crockford, value);
        decoded.is_some() && decoded.unwrap().len() == 16
    }

    #[cfg(test)]
    pub fn random() -> Self {
        let secret = base32::encode(base32::Alphabet::Crockford, &random_bytes::<16>());
        Self(secret)
    }
}

impl Display for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for SessionSecret {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !Self::is_valid(s) {
            return Err(anyhow::anyhow!("Invalid session secret"));
        }
        Ok(Self(s.to_string()))
    }
}

#[derive(Iden)]
pub enum SessionIden {
    Id,
    Secret,
    User,
    Capabilities,
    CreatedAt,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SessionEntity {
    pub id: i32,
    pub secret: SessionSecret,
    pub user_id: i32,
    pub user_pubkey: PublicKey,
    pub capabilities: Capabilities,
    pub created_at: sqlx::types::chrono::NaiveDateTime,
}

impl SessionEntity {
    pub fn to_legacy(&self) -> CookieSessionRecord {
        let mut record =
            CookieSessionRecord::new(&self.user_pubkey, self.capabilities.clone(), None);
        record.set_created_at(self.created_at.and_utc().timestamp() as u64);
        record
    }
}

impl FromRow<'_, PgRow> for SessionEntity {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        let id: i32 = row.try_get(SessionIden::Id.to_string().as_str())?;
        let secret: String = row.try_get(SessionIden::Secret.to_string().as_str())?;
        let secret: SessionSecret =
            SessionSecret::new(secret).map_err(|e| sqlx::Error::Decode(e.into()))?;
        let user_id: i32 = row.try_get(SessionIden::User.to_string().as_str())?;
        let user_public_key: String = row.try_get(UserIden::PublicKey.to_string().as_str())?;
        let user_public_key: PublicKey = user_public_key
            .try_into()
            .map_err(|e: pkarr::errors::PublicKeyError| sqlx::Error::Decode(e.into()))?;
        let capabilities: String = row.try_get(SessionIden::Capabilities.to_string().as_str())?;
        let capabilities: Capabilities = capabilities.parse().map_err(
            |e: pubky_common::capabilities::CapabilitiesParseError| sqlx::Error::Decode(e.into()),
        )?;
        let created_at: sqlx::types::chrono::NaiveDateTime =
            row.try_get(SessionIden::CreatedAt.to_string().as_str())?;
        Ok(SessionEntity {
            id,
            secret,
            user_id,
            user_pubkey: user_public_key,
            capabilities,
            created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use pubky_common::capabilities::Capability;
    use pubky_common::crypto::Keypair;

    use crate::persistence::sql::{entities::user::UserRepository, SqlDb};

    use super::*;

    #[test]
    fn test_session_secret() {
        let secret = SessionSecret::random();
        assert!(SessionSecret::is_valid(&secret.to_string()));

        let _ = SessionSecret::from_str("6HHZ06GHB964CZMDAA0WCNV2C8").unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_get_session() {
        let db = SqlDb::test().await;
        let user_pubkey = Keypair::random().public_key();

        // Test create user
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

        // Test create session
        let secret = SessionRepository::create(
            user.id,
            &Capabilities::builder().cap(Capability::root()).finish(),
            &mut db.pool().into(),
        )
        .await
        .unwrap();
        let session = SessionRepository::get_by_secret(&secret, &mut db.pool().into())
            .await
            .unwrap();

        // Test get session
        let session = SessionRepository::get_by_secret(&session.secret, &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(session.user_id, user.id);
        assert_eq!(
            session.capabilities,
            Capabilities::builder().cap(Capability::root()).finish()
        );

        // Test delete session
        SessionRepository::delete(&session.secret, &mut db.pool().into())
            .await
            .unwrap();

        // Test get session again
        let result = SessionRepository::get_by_secret(&session.secret, &mut db.pool().into()).await;
        assert!(result.is_err());
    }
}
