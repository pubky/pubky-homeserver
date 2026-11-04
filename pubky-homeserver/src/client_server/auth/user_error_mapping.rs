//! HTTP error mapping for signup service errors.

use axum::http::StatusCode;

use crate::services::signup_service::SignupServiceError;
use crate::shared::HttpError;

impl From<SignupServiceError> for HttpError {
    fn from(error: SignupServiceError) -> Self {
        match error {
            SignupServiceError::UserAlreadyExists => {
                HttpError::new_with_message(StatusCode::CONFLICT, "User already exists")
            }
            SignupServiceError::SignupTokenRequired => HttpError::bad_request("Token required"),
            SignupServiceError::InvalidSignupToken => {
                HttpError::unauthorized_with_message("Invalid token")
            }
            SignupServiceError::SignupTokenAlreadyUsed => {
                HttpError::unauthorized_with_message("Token already used")
            }
            SignupServiceError::Internal(e) => {
                HttpError::internal_server_and_log(format!("Signup service: {e}"))
            }
        }
    }
}
