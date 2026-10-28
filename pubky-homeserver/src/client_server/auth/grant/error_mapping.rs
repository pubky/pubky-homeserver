//! HTTP error mapping for [`AuthServiceError`].
//!
//! Converts domain-level auth errors into HTTP status codes at the adapter boundary.

use axum::http::StatusCode;

use super::crypto::grant_verifier;
use super::service_error::AuthServiceError;
use crate::shared::HttpError;

impl From<AuthServiceError> for HttpError {
    fn from(error: AuthServiceError) -> Self {
        match error {
            AuthServiceError::InvalidGrant(ref inner) => match inner {
                grant_verifier::Error::InvalidSignature | grant_verifier::Error::Expired => {
                    HttpError::unauthorized_with_message(error.to_string())
                }
                _ => HttpError::bad_request(error.to_string()),
            },
            AuthServiceError::InvalidPopProof(_) => {
                HttpError::unauthorized_with_message(error.to_string())
            }
            AuthServiceError::UserNotFound | AuthServiceError::GrantNotFound => {
                HttpError::not_found()
            }
            AuthServiceError::UserAlreadyExists => {
                HttpError::new_with_message(StatusCode::CONFLICT, "User already exists")
            }
            AuthServiceError::SignupTokenRequired => HttpError::bad_request("Token required"),
            AuthServiceError::InvalidSignupToken => {
                HttpError::unauthorized_with_message("Invalid token")
            }
            AuthServiceError::SignupTokenAlreadyUsed => {
                HttpError::unauthorized_with_message("Token already used")
            }
            AuthServiceError::NonceReplay => {
                HttpError::unauthorized_with_message("PoP nonce already used")
            }
            AuthServiceError::GrantRevoked => {
                HttpError::unauthorized_with_message("Grant has been revoked")
            }
            AuthServiceError::GrantExpired => {
                HttpError::unauthorized_with_message("Grant has expired")
            }
            AuthServiceError::InvalidSignupGrant(message) => HttpError::bad_request(message),
            AuthServiceError::SessionNotFound => {
                HttpError::unauthorized_with_message("Session not found")
            }
            AuthServiceError::SessionExpired => {
                HttpError::unauthorized_with_message("Session has expired")
            }
            AuthServiceError::GrantOwnershipMismatch => {
                HttpError::forbidden_with_message("Grant does not belong to authenticated user")
            }
            AuthServiceError::RootCapabilityRequired => {
                HttpError::forbidden_with_message("Root capability required")
            }
            AuthServiceError::Internal(e) => {
                HttpError::internal_server_and_log(format!("Auth service: {e}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_server::auth::grant::crypto::pop_verifier;
    use axum::response::IntoResponse;

    fn assert_status(error: AuthServiceError, expected: StatusCode) {
        let resp = HttpError::from(error).into_response();
        assert_eq!(resp.status(), expected);
    }

    #[test]
    fn grant_errors_map_correctly() {
        assert_status(
            AuthServiceError::InvalidGrant(grant_verifier::Error::InvalidSignature),
            StatusCode::UNAUTHORIZED,
        );
        assert_status(
            AuthServiceError::InvalidGrant(grant_verifier::Error::Expired),
            StatusCode::UNAUTHORIZED,
        );
        assert_status(
            AuthServiceError::InvalidGrant(grant_verifier::Error::InvalidFormat),
            StatusCode::BAD_REQUEST,
        );
        assert_status(
            AuthServiceError::InvalidGrant(grant_verifier::Error::InvalidHeaderType),
            StatusCode::BAD_REQUEST,
        );
    }

    #[test]
    fn pop_errors_map_to_unauthorized() {
        assert_status(
            AuthServiceError::InvalidPopProof(pop_verifier::Error::InvalidSignature),
            StatusCode::UNAUTHORIZED,
        );
        assert_status(
            AuthServiceError::InvalidPopProof(pop_verifier::Error::AudienceMismatch),
            StatusCode::UNAUTHORIZED,
        );
        assert_status(
            AuthServiceError::InvalidPopProof(pop_verifier::Error::InvalidFormat),
            StatusCode::UNAUTHORIZED,
        );
        assert_status(
            AuthServiceError::InvalidPopProof(pop_verifier::Error::InvalidHeaderType),
            StatusCode::UNAUTHORIZED,
        );
    }

    #[test]
    fn signup_and_user_errors_map_correctly() {
        assert_status(AuthServiceError::UserNotFound, StatusCode::NOT_FOUND);
        assert_status(AuthServiceError::GrantNotFound, StatusCode::NOT_FOUND);
        assert_status(AuthServiceError::UserAlreadyExists, StatusCode::CONFLICT);
        assert_status(
            AuthServiceError::SignupTokenRequired,
            StatusCode::BAD_REQUEST,
        );
        assert_status(
            AuthServiceError::InvalidSignupToken,
            StatusCode::UNAUTHORIZED,
        );
        assert_status(
            AuthServiceError::SignupTokenAlreadyUsed,
            StatusCode::UNAUTHORIZED,
        );
    }

    #[test]
    fn security_and_session_errors_map_correctly() {
        assert_status(AuthServiceError::NonceReplay, StatusCode::UNAUTHORIZED);
        assert_status(AuthServiceError::GrantRevoked, StatusCode::UNAUTHORIZED);
        assert_status(AuthServiceError::GrantExpired, StatusCode::UNAUTHORIZED);
        assert_status(
            AuthServiceError::InvalidSignupGrant("bad signup grant".into()),
            StatusCode::BAD_REQUEST,
        );
        assert_status(AuthServiceError::SessionNotFound, StatusCode::UNAUTHORIZED);
        assert_status(AuthServiceError::SessionExpired, StatusCode::UNAUTHORIZED);
        assert_status(
            AuthServiceError::GrantOwnershipMismatch,
            StatusCode::FORBIDDEN,
        );
        assert_status(
            AuthServiceError::RootCapabilityRequired,
            StatusCode::FORBIDDEN,
        );
    }
}
