//! Signup token resource endpoints.

use crate::client_server::auth::SignupServiceError;
use crate::client_server::AppState;
use crate::persistence::sql::signup_code::SignupCode;
use crate::shared::{HttpError, HttpResult};
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
};

/// Status of a signup token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignupTokenStatus {
    /// Token exists and has not been used yet.
    Valid,
    /// Token has already been used.
    Used,
}

/// Response body for GET /signup_tokens/{token}
#[derive(serde::Serialize)]
pub struct SignupTokenResponse {
    /// Token status.
    pub status: SignupTokenStatus,
    /// When the token was created (ISO 8601 format)
    pub created_at: String,
}

/// Get signup token status.
///
/// Returns the token's status and creation time.
pub async fn get(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> HttpResult<impl IntoResponse> {
    if !state.auth_state.signup_service.requires_signup_token() {
        return Err(HttpError::new_with_message(
            StatusCode::BAD_REQUEST,
            "Signup tokens not required",
        ));
    }

    let signup_code_id = SignupCode::new(token).map_err(|e| {
        HttpError::new_with_message(
            StatusCode::BAD_REQUEST,
            format!("Invalid signup token format: {}", e),
        )
    })?;

    let code = state
        .auth_state
        .signup_service
        .get_token(&signup_code_id)
        .await
        .map_err(|e| match e {
            SignupServiceError::InvalidSignupToken => {
                HttpError::new_with_message(StatusCode::NOT_FOUND, "Token not found")
            }
            e => e.into(),
        })?;

    let status = if code.used_by.is_some() {
        SignupTokenStatus::Used
    } else {
        SignupTokenStatus::Valid
    };
    let response = SignupTokenResponse {
        status,
        created_at: code.created_at.and_utc().to_rfc3339(),
    };

    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(response),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum_test::TestServer;

    use crate::client_server::ClientServer;
    use crate::shared::quota::UserQuota;
    use crate::{AppContext, SignupMode};

    fn test_server(context: &Arc<AppContext>) -> TestServer {
        TestServer::new(ClientServer::create_router(Arc::clone(context)).unwrap())
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_rejects_when_tokens_not_required() {
        let context = AppContext::test_with_config(|c| {
            c.general.signup_mode = SignupMode::Open;
            c.drive.rate_limits.clear();
        })
        .await;
        let server = test_server(&context);
        let code = context
            .signup_code_service
            .create(&UserQuota::default())
            .await
            .unwrap();

        let response = server
            .get(&format!("/signup_tokens/{}", code.id))
            .add_header("host", "localhost")
            .expect_failure()
            .await;
        response.assert_status_bad_request();
        assert_eq!(response.text(), "Signup tokens not required");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_unknown_token_is_not_found() {
        let context = AppContext::test_with_config(|c| {
            c.general.signup_mode = SignupMode::TokenRequired;
            c.drive.rate_limits.clear();
        })
        .await;
        let server = test_server(&context);

        let response = server
            .get("/signup_tokens/AAAA-BBBB-CCCC")
            .add_header("host", "localhost")
            .expect_failure()
            .await;
        response.assert_status_not_found();
        assert_eq!(response.text(), "Token not found");
    }
}
