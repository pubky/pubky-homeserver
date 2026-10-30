//! Signup service — owns signup policy and user creation.

use crate::persistence::sql::{
    signup_code::{SignupCode, SignupCodeEntity},
    uexecutor, SqlDb,
};
use crate::services::signup_code_service::{SignupCodeError, SignupCodeService};
use crate::services::user_service::{UserEntity, UserService};
use crate::shared::quota::UserQuota;
use crate::SignupMode;
use pubky_common::crypto::PublicKey;

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

impl From<SignupCodeError> for SignupServiceError {
    fn from(error: SignupCodeError) -> Self {
        match error {
            SignupCodeError::Invalid => Self::InvalidSignupToken,
            SignupCodeError::AlreadyUsed => Self::SignupTokenAlreadyUsed,
            SignupCodeError::Db(e) => Self::Internal(e),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignupService {
    sql_db: SqlDb,
    signup_mode: SignupMode,
    user_service: UserService,
    signup_code_service: SignupCodeService,
}

impl SignupService {
    /// Creates a signup service from the application context.
    pub(crate) fn from_context(context: &crate::AppContext) -> Self {
        Self {
            sql_db: context.sql_db.clone(),
            signup_mode: context.config_toml.general.signup_mode.clone(),
            user_service: context.user_service.clone(),
            signup_code_service: context.signup_code_service.clone(),
        }
    }

    /// Creates a signup service with the configured signup policy (test-only).
    #[cfg(test)]
    pub fn new(sql_db: SqlDb, signup_mode: SignupMode, user_service: UserService) -> Self {
        Self {
            signup_code_service: SignupCodeService::new(sql_db.clone()),
            sql_db,
            signup_mode,
            user_service,
        }
    }

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

    pub(crate) fn cache_user_quota(&self, user: &UserEntity) {
        self.user_service.cache_user_quota(user);
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
            self.signup_code_service
                .consume_in_tx(code, public_key, uexecutor!(*tx))
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

    /// Whether signups must present a signup token.
    pub fn requires_signup_token(&self) -> bool {
        self.signup_mode == SignupMode::TokenRequired
    }

    /// Looks up a signup token.
    ///
    /// Fails with [`SignupServiceError::InvalidSignupToken`] when the token is unknown.
    pub async fn get_token(
        &self,
        code: &SignupCode,
    ) -> Result<SignupCodeEntity, SignupServiceError> {
        match self.signup_code_service.get(code).await {
            Ok(entity) => Ok(entity),
            Err(sqlx::Error::RowNotFound) => Err(SignupServiceError::InvalidSignupToken),
            Err(e) => Err(e.into()),
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_common::crypto::Keypair;

    async fn service(signup_mode: SignupMode) -> SignupService {
        let db = SqlDb::test().await;
        SignupService::new(db.clone(), signup_mode, UserService::new(db))
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_requires_signup_token_follows_signup_mode() {
        assert!(!service(SignupMode::Open).await.requires_signup_token());
        assert!(service(SignupMode::TokenRequired)
            .await
            .requires_signup_token());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_token_reports_unknown_and_used_tokens() {
        let svc = service(SignupMode::TokenRequired).await;

        let err = svc.get_token(&SignupCode::random()).await.unwrap_err();
        assert!(matches!(err, SignupServiceError::InvalidSignupToken));

        let code = svc
            .signup_code_service
            .create(&UserQuota::default())
            .await
            .unwrap();
        assert!(svc.get_token(&code.id).await.unwrap().used_by.is_none());

        let user = svc
            .create_new_user(&Keypair::random().public_key(), Some(&code.id))
            .await
            .unwrap();
        let used = svc.get_token(&code.id).await.unwrap();
        assert_eq!(used.used_by, Some(user.public_key));
    }
}
