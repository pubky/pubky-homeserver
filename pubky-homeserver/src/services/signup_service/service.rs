//! Service layer for signups.
//!
//! Owns the signup policy (`signup_mode`), the signup tokens that gate it,
//! and the creation of a user on signup. Called by the client signup flows
//! and by the admin token endpoints.

use pubky_common::crypto::PublicKey;

use crate::persistence::sql::signup_code::{
    SignupCode, SignupCodeEntity, SignupCodeListPage, SignupCodeListQuery, SignupCodeOverview,
    SignupCodeRepository,
};
use crate::persistence::sql::{uexecutor, SqlDb, UnifiedExecutor};
use crate::services::user_service::{UserEntity, UserService};
use crate::shared::quota::UserQuota;
use crate::SignupMode;

/// Domain errors from signup operations.
#[derive(Debug, thiserror::Error)]
pub enum SignupServiceError {
    /// User already exists (signup conflict).
    #[error("User already exists")]
    UserAlreadyExists,

    /// Signup token is required but was not provided.
    #[error("Token required")]
    SignupTokenRequired,

    /// Signup token not found or invalid.
    #[error("Invalid token")]
    InvalidSignupToken,

    /// Signup token has already been used.
    #[error("Token already used")]
    SignupTokenAlreadyUsed,

    /// Database or infrastructure error.
    #[error("Internal error: {0}")]
    Internal(#[from] sqlx::Error),
}

/// Owns the signup policy, signup tokens and user creation on signup.
#[derive(Clone, Debug)]
pub struct SignupService {
    sql_db: SqlDb,
    signup_mode: SignupMode,
    user_service: UserService,
}

impl SignupService {
    /// Creates a signup service with the configured signup policy.
    pub fn new(sql_db: SqlDb, signup_mode: SignupMode, user_service: UserService) -> Self {
        Self {
            sql_db,
            signup_mode,
            user_service,
        }
    }

    /// Whether signups must present a signup token.
    pub fn requires_signup_token(&self) -> bool {
        self.signup_mode == SignupMode::TokenRequired
    }

    // ── Signup ─────────────────────────────────────────────────────

    /// Creates a new user in its own transaction.
    ///
    /// Rejects existing users and enforces signup-token validation when the
    /// homeserver is configured with [`SignupMode::TokenRequired`].
    pub async fn create_new_user(
        &self,
        public_key: &PublicKey,
        signup_token: Option<&SignupCode>,
    ) -> Result<UserEntity, SignupServiceError> {
        let mut tx = self.sql_db.pool().begin().await?;
        let user = self
            .create_user_in_tx(public_key, signup_token, &mut tx)
            .await?;
        tx.commit().await?;
        self.user_service.cache_user_quota(&user);
        Ok(user)
    }

    /// Creates a new user inside an existing transaction.
    ///
    /// Used by auth flows that must atomically create the user and persist
    /// method-specific session state, such as grant signup.
    pub(crate) async fn create_user_in_tx(
        &self,
        public_key: &PublicKey,
        signup_token: Option<&SignupCode>,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    ) -> Result<UserEntity, SignupServiceError> {
        self.ensure_user_not_exists(public_key, tx).await?;
        let quota = if self.requires_signup_token() {
            let code = signup_token.ok_or(SignupServiceError::SignupTokenRequired)?;
            Self::consume_token(code, public_key, uexecutor!(*tx))
                .await?
                .quota()
        } else {
            UserQuota::default()
        };
        let user = self
            .user_service
            .create_in_tx(public_key, uexecutor!(*tx))
            .await?;
        let user = self
            .user_service
            .set_quota_in_tx(user.id, &quota, uexecutor!(*tx))
            .await?;
        Ok(user)
    }

    /// Fails if a user row already exists for `public_key`.
    async fn ensure_user_not_exists(
        &self,
        public_key: &PublicKey,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    ) -> Result<(), SignupServiceError> {
        match self
            .user_service
            .get_in_tx(public_key, uexecutor!(*tx))
            .await
        {
            Ok(_) => Err(SignupServiceError::UserAlreadyExists),
            Err(sqlx::Error::RowNotFound) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Marks a signup token as used by `used_by` inside the signup transaction.
    async fn consume_token<'a>(
        code: &SignupCode,
        used_by: &PublicKey,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SignupCodeEntity, SignupServiceError> {
        // Tells an unknown token apart from a used one before the guarded update.
        Self::fetch_token(code, executor).await?;
        match SignupCodeRepository::mark_as_used(code, used_by, executor).await {
            Ok(entity) => Ok(entity),
            // The update only matches `used_by IS NULL`, so no row means the
            // token was already used, possibly by a concurrent signup.
            Err(sqlx::Error::RowNotFound) => Err(SignupServiceError::SignupTokenAlreadyUsed),
            Err(e) => Err(e.into()),
        }
    }

    async fn fetch_token<'a>(
        code: &SignupCode,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<SignupCodeEntity, SignupServiceError> {
        match SignupCodeRepository::get(code, executor).await {
            Ok(entity) => Ok(entity),
            Err(sqlx::Error::RowNotFound) => Err(SignupServiceError::InvalidSignupToken),
            Err(e) => Err(e.into()),
        }
    }

    // ── Signup tokens ──────────────────────────────────────────────

    /// Looks up a signup token.
    ///
    /// Fails with [`SignupServiceError::InvalidSignupToken`] when the token is unknown.
    pub async fn get_token(
        &self,
        code: &SignupCode,
    ) -> Result<SignupCodeEntity, SignupServiceError> {
        Self::fetch_token(code, &mut self.sql_db.pool().into()).await
    }

    /// Creates a random signup token granting `quota` to the user who redeems it.
    pub async fn create_token(&self, quota: &UserQuota) -> Result<SignupCodeEntity, sqlx::Error> {
        SignupCodeRepository::create(&SignupCode::random(), quota, &mut self.sql_db.pool().into())
            .await
    }

    /// Lists signup tokens in token order.
    pub async fn list_tokens(
        &self,
        query: SignupCodeListQuery,
    ) -> Result<SignupCodeListPage, sqlx::Error> {
        SignupCodeRepository::list(query, &mut self.sql_db.pool().into()).await
    }

    /// Counts all and unused signup tokens.
    pub async fn token_overview(&self) -> Result<SignupCodeOverview, sqlx::Error> {
        SignupCodeRepository::get_overview(&mut self.sql_db.pool().into()).await
    }
}

#[cfg(test)]
impl SignupService {
    /// Create a signup token with a chosen id, for tests that depend on token order.
    pub async fn create_token_with_id(
        &self,
        id: &SignupCode,
        quota: &UserQuota,
    ) -> Result<SignupCodeEntity, sqlx::Error> {
        SignupCodeRepository::create(id, quota, &mut self.sql_db.pool().into()).await
    }

    /// Mark a signup token as used without signing anyone up.
    pub async fn mark_token_used(
        &self,
        code: &SignupCode,
        used_by: &PublicKey,
    ) -> Result<SignupCodeEntity, sqlx::Error> {
        SignupCodeRepository::mark_as_used(code, used_by, &mut self.sql_db.pool().into()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::signup_code::SignupCodeListState;
    use pubky_common::crypto::Keypair;

    async fn service(signup_mode: SignupMode) -> SignupService {
        let db = SqlDb::test().await;
        SignupService::new(db.clone(), signup_mode, UserService::new(db))
    }

    fn all_tokens() -> SignupCodeListQuery {
        SignupCodeListQuery {
            state: SignupCodeListState::All,
            limit: None,
            cursor: None,
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_requires_signup_token_follows_signup_mode() {
        let db = SqlDb::test().await;
        let service = |mode| SignupService::new(db.clone(), mode, UserService::new(db.clone()));

        assert!(!service(SignupMode::Open).requires_signup_token());
        assert!(service(SignupMode::TokenRequired).requires_signup_token());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_and_get_token() {
        let svc = service(SignupMode::TokenRequired).await;

        let err = svc.get_token(&SignupCode::random()).await.unwrap_err();
        assert!(matches!(err, SignupServiceError::InvalidSignupToken));

        let created = svc.create_token(&UserQuota::default()).await.unwrap();
        let fetched = svc.get_token(&created.id).await.unwrap();
        assert_eq!(fetched.id, created.id);
        assert!(fetched.used_by.is_none());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_tokens_and_overview() {
        let svc = service(SignupMode::TokenRequired).await;

        assert!(svc
            .list_tokens(all_tokens())
            .await
            .unwrap()
            .items
            .is_empty());
        assert_eq!(svc.token_overview().await.unwrap().num_signup_codes, 0);

        let first = svc.create_token(&UserQuota::default()).await.unwrap();
        svc.create_token(&UserQuota::default()).await.unwrap();
        svc.mark_token_used(&first.id, &Keypair::random().public_key())
            .await
            .unwrap();

        assert_eq!(svc.list_tokens(all_tokens()).await.unwrap().items.len(), 2);

        let overview = svc.token_overview().await.unwrap();
        assert_eq!(overview.num_signup_codes, 2);
        assert_eq!(overview.num_unused_signup_codes, 1);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_signup_consumes_token() {
        let svc = service(SignupMode::TokenRequired).await;
        let code = svc.create_token(&UserQuota::default()).await.unwrap();

        let user = svc
            .create_new_user(&Keypair::random().public_key(), Some(&code.id))
            .await
            .unwrap();

        let used = svc.get_token(&code.id).await.unwrap();
        assert_eq!(used.used_by, Some(user.public_key));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_signup_rejects_missing_unknown_and_used_tokens() {
        let svc = service(SignupMode::TokenRequired).await;

        let err = svc
            .create_new_user(&Keypair::random().public_key(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, SignupServiceError::SignupTokenRequired));

        let err = svc
            .create_new_user(&Keypair::random().public_key(), Some(&SignupCode::random()))
            .await
            .unwrap_err();
        assert!(matches!(err, SignupServiceError::InvalidSignupToken));

        let code = svc.create_token(&UserQuota::default()).await.unwrap();
        svc.create_new_user(&Keypair::random().public_key(), Some(&code.id))
            .await
            .unwrap();
        let err = svc
            .create_new_user(&Keypair::random().public_key(), Some(&code.id))
            .await
            .unwrap_err();
        assert!(matches!(err, SignupServiceError::SignupTokenAlreadyUsed));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_concurrent_signups_redeem_token_once() {
        let svc = service(SignupMode::TokenRequired).await;
        let code = svc.create_token(&UserQuota::default()).await.unwrap();

        let alice = Keypair::random().public_key();
        let bob = Keypair::random().public_key();
        let (first, second) = tokio::join!(
            svc.create_new_user(&alice, Some(&code.id)),
            svc.create_new_user(&bob, Some(&code.id)),
        );
        let mut results = [first, second];
        results.sort_by_key(|result| result.is_err());

        let [winner, loser] = results;
        let winner = winner.unwrap();
        assert!(matches!(
            loser.unwrap_err(),
            SignupServiceError::SignupTokenAlreadyUsed
        ));
        let used = svc.get_token(&code.id).await.unwrap();
        assert_eq!(used.used_by, Some(winner.public_key));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_open_signup_ignores_tokens() {
        let svc = service(SignupMode::Open).await;
        let pubkey = Keypair::random().public_key();

        let user = svc.create_new_user(&pubkey, None).await.unwrap();
        assert_eq!(user.public_key, pubkey);

        let err = svc.create_new_user(&pubkey, None).await.unwrap_err();
        assert!(matches!(err, SignupServiceError::UserAlreadyExists));
    }
}
