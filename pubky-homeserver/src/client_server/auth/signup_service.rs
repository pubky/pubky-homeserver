//! Signup service — owns signup policy and user creation.

use crate::persistence::sql::{
    signup_code::{SignupCode, SignupCodeRepository},
    uexecutor, SqlDb,
};
use crate::services::user_service::{UserEntity, UserService};
use crate::shared::user_quota::UserQuota;
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
        let quota = if self.signup_mode == SignupMode::TokenRequired {
            Self::validate_and_consume_signup_token(signup_token, public_key, tx).await?
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

    /// Validates a signup token and marks it as consumed by `public_key`.
    async fn validate_and_consume_signup_token(
        signup_token: Option<&SignupCode>,
        public_key: &PublicKey,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    ) -> Result<UserQuota, SignupServiceError> {
        let code_id = signup_token.ok_or(SignupServiceError::SignupTokenRequired)?;
        let code = match SignupCodeRepository::get(code_id, uexecutor!(*tx)).await {
            Ok(code) => code,
            Err(sqlx::Error::RowNotFound) => return Err(SignupServiceError::InvalidSignupToken),
            Err(e) => return Err(SignupServiceError::Internal(e)),
        };
        if code.used_by.is_some() {
            return Err(SignupServiceError::SignupTokenAlreadyUsed);
        }
        let quota = code.quota();
        SignupCodeRepository::mark_as_used(code_id, public_key, uexecutor!(*tx)).await?;
        Ok(quota)
    }
}
