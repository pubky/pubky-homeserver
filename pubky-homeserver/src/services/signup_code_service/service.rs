//! Service layer for signup code operations.

use pubky_common::crypto::PublicKey;

use crate::persistence::sql::signup_code::{
    SignupCode, SignupCodeEntity, SignupCodeListPage, SignupCodeListQuery, SignupCodeOverview,
    SignupCodeRepository,
};
use crate::persistence::sql::{SqlDb, UnifiedExecutor};
use crate::shared::quota::UserQuota;

/// Why a signup code could not be consumed.
#[derive(Debug, thiserror::Error)]
pub enum SignupCodeError {
    /// No signup code with this id exists.
    #[error("Invalid token")]
    Invalid,
    /// The signup code has already been used.
    #[error("Token already used")]
    AlreadyUsed,
    /// Database error.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Coordinates signup code creation, lookup and consumption.
#[derive(Clone, Debug)]
pub struct SignupCodeService {
    /// Database connection pool.
    sql_db: SqlDb,
}

impl SignupCodeService {
    /// Create a new service on the given database.
    pub fn new(sql_db: SqlDb) -> Self {
        Self { sql_db }
    }

    // ── Reads (use internal pool) ──────────────────────────────────

    /// Get a signup code by its id.
    pub async fn get(&self, code: &SignupCode) -> Result<SignupCodeEntity, sqlx::Error> {
        SignupCodeRepository::get(code, &mut self.sql_db.pool().into()).await
    }

    /// List signup codes in token order.
    pub async fn list(
        &self,
        query: SignupCodeListQuery,
    ) -> Result<SignupCodeListPage, sqlx::Error> {
        SignupCodeRepository::list(query, &mut self.sql_db.pool().into()).await
    }

    /// Get an overview of all signup codes (total and unused counts).
    pub async fn get_overview(&self) -> Result<SignupCodeOverview, sqlx::Error> {
        SignupCodeRepository::get_overview(&mut self.sql_db.pool().into()).await
    }

    // ── Writes ─────────────────────────────────────────────────────

    /// Create a random signup code granting `quota` to the user who redeems it.
    pub async fn create(&self, quota: &UserQuota) -> Result<SignupCodeEntity, sqlx::Error> {
        SignupCodeRepository::create(&SignupCode::random(), quota, &mut self.sql_db.pool().into())
            .await
    }

    /// Mark a signup code as used by `used_by` inside an existing transaction.
    ///
    /// Fails if the code does not exist or has already been used.
    pub async fn consume_in_tx<'a>(
        &self,
        code: &SignupCode,
        used_by: &PublicKey,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SignupCodeEntity, SignupCodeError> {
        let entity = match SignupCodeRepository::get(code, executor).await {
            Ok(entity) => entity,
            Err(sqlx::Error::RowNotFound) => return Err(SignupCodeError::Invalid),
            Err(e) => return Err(e.into()),
        };
        if entity.used_by.is_some() {
            return Err(SignupCodeError::AlreadyUsed);
        }
        Ok(SignupCodeRepository::mark_as_used(code, used_by, executor).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::signup_code::SignupCodeListState;
    use pubky_common::crypto::Keypair;

    async fn service() -> SignupCodeService {
        SignupCodeService::new(SqlDb::test().await)
    }

    fn all_codes() -> SignupCodeListQuery {
        SignupCodeListQuery {
            state: SignupCodeListState::All,
            limit: None,
            cursor: None,
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_and_get() {
        let svc = service().await;

        let created = svc.create(&UserQuota::default()).await.unwrap();
        assert!(created.used_by.is_none());

        let fetched = svc.get(&created.id).await.unwrap();
        assert_eq!(fetched.id, created.id);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_nonexistent_returns_row_not_found() {
        let svc = service().await;
        let code = SignupCode::random();

        let err = svc.get(&code).await.unwrap_err();
        assert!(matches!(err, sqlx::Error::RowNotFound));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_and_overview() {
        let svc = service().await;

        assert!(svc.list(all_codes()).await.unwrap().items.is_empty());
        assert_eq!(svc.get_overview().await.unwrap().num_signup_codes, 0);

        let first = svc.create(&UserQuota::default()).await.unwrap();
        svc.create(&UserQuota::default()).await.unwrap();
        svc.consume_in_tx(
            &first.id,
            &Keypair::random().public_key(),
            &mut svc.sql_db.pool().into(),
        )
        .await
        .unwrap();

        assert_eq!(svc.list(all_codes()).await.unwrap().items.len(), 2);

        let overview = svc.get_overview().await.unwrap();
        assert_eq!(overview.num_signup_codes, 2);
        assert_eq!(overview.num_unused_signup_codes, 1);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_consume_marks_code_as_used() {
        let svc = service().await;
        let code = svc.create(&UserQuota::default()).await.unwrap();
        let used_by = Keypair::random().public_key();

        let consumed = svc
            .consume_in_tx(&code.id, &used_by, &mut svc.sql_db.pool().into())
            .await
            .unwrap();
        assert_eq!(consumed.used_by, Some(used_by.clone()));

        let fetched = svc.get(&code.id).await.unwrap();
        assert_eq!(fetched.used_by, Some(used_by));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_consume_rejects_unknown_and_used_codes() {
        let svc = service().await;
        let used_by = Keypair::random().public_key();

        let err = svc
            .consume_in_tx(
                &SignupCode::random(),
                &used_by,
                &mut svc.sql_db.pool().into(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SignupCodeError::Invalid));

        let code = svc.create(&UserQuota::default()).await.unwrap();
        svc.consume_in_tx(&code.id, &used_by, &mut svc.sql_db.pool().into())
            .await
            .unwrap();
        let err = svc
            .consume_in_tx(
                &code.id,
                &Keypair::random().public_key(),
                &mut svc.sql_db.pool().into(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SignupCodeError::AlreadyUsed));
    }
}
