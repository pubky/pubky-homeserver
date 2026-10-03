//! Domain errors for [`AuthService`](super::service::AuthService) operations.
//!
//! These errors capture business-logic failure modes without any HTTP coupling.
//! The HTTP status code mapping lives in [`error_mapping`](super::error_mapping).

use super::crypto::{grant_verifier, pop_verifier};
use super::persistence::{grant::GrantStatus, grant_session::SessionIssueError};
use crate::client_server::auth::SignupServiceError;

/// Domain errors from auth service operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthServiceError {
    /// Grant JWS verification failed (signature, format, or expiry).
    #[error("Invalid grant: {0}")]
    InvalidGrant(#[from] grant_verifier::Error),

    /// PoP proof verification failed.
    #[error("Invalid PoP proof: {0}")]
    InvalidPopProof(#[from] pop_verifier::Error),

    /// User not found for the given public key.
    #[error("User not found")]
    UserNotFound,

    /// User already exists (signup conflict).
    #[error("User already exists")]
    UserAlreadyExists,

    /// Grant not found for the given grant ID.
    #[error("Grant not found")]
    GrantNotFound,

    /// Signup token is required but was not provided.
    #[error("Token required")]
    SignupTokenRequired,

    /// Signup token not found or invalid.
    #[error("Invalid token")]
    InvalidSignupToken,

    /// Signup token has already been used.
    #[error("Token already used")]
    SignupTokenAlreadyUsed,

    /// PoP nonce was already used (replay attack).
    #[error("PoP nonce already used")]
    NonceReplay,

    /// Grant has been revoked.
    #[error("Grant has been revoked")]
    GrantRevoked,

    /// Grant has expired.
    #[error("Grant has expired")]
    GrantExpired,

    /// Signup grant violates sessionless signup policy.
    #[error("Invalid signup grant: {0}")]
    InvalidSignupGrant(String),

    /// Session not found for the given token ID.
    #[error("Session not found")]
    SessionNotFound,

    /// Session token has expired.
    #[error("Session has expired")]
    SessionExpired,

    /// Grant does not belong to the authenticated user.
    #[error("Grant does not belong to authenticated user")]
    GrantOwnershipMismatch,

    /// Session lacks root capability.
    #[error("Root capability required")]
    RootCapabilityRequired,

    /// A new slot would exceed the configured limit.
    #[error("grant_session_limit_reached")]
    SessionLimitReached,

    /// Too many exchanges for this grant in the current window.
    #[error("grant_session_rate_limited")]
    SessionRateLimited,

    /// Database or infrastructure error.
    #[error("Internal error: {0}")]
    Internal(#[from] sqlx::Error),
}

impl From<GrantStatus> for AuthServiceError {
    fn from(status: GrantStatus) -> Self {
        match status {
            GrantStatus::Revoked => Self::GrantRevoked,
            GrantStatus::Expired => Self::GrantExpired,
        }
    }
}

impl From<SignupServiceError> for AuthServiceError {
    fn from(error: SignupServiceError) -> Self {
        match error {
            SignupServiceError::UserAlreadyExists => Self::UserAlreadyExists,
            SignupServiceError::SignupTokenRequired => Self::SignupTokenRequired,
            SignupServiceError::InvalidSignupToken => Self::InvalidSignupToken,
            SignupServiceError::SignupTokenAlreadyUsed => Self::SignupTokenAlreadyUsed,
            SignupServiceError::Internal(e) => Self::Internal(e),
        }
    }
}

impl From<SessionIssueError> for AuthServiceError {
    fn from(error: SessionIssueError) -> Self {
        match error {
            SessionIssueError::Revoked => Self::GrantRevoked,
            SessionIssueError::Expired => Self::GrantExpired,
            SessionIssueError::Capacity => Self::SessionLimitReached,
            SessionIssueError::RateLimited => Self::SessionRateLimited,
            SessionIssueError::Database(error) => Self::Internal(error),
        }
    }
}
