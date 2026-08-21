//! Signup token resource endpoints.

use crate::persistence::sql::signup_code::{SignupCode, SignupCodeRepository};
use crate::shared::{HttpError, HttpResult};
use crate::{client_server::AppState, SignupMode};
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
    if state.context.config_toml.general.signup_mode != SignupMode::TokenRequired {
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

    let code =
        match SignupCodeRepository::get(&signup_code_id, &mut state.context.sql_db.pool().into())
            .await
        {
            Ok(code) => code,
            Err(sqlx::Error::RowNotFound) => {
                return Err(HttpError::new_with_message(
                    StatusCode::NOT_FOUND,
                    "Token not found",
                ));
            }
            Err(e) => return Err(e.into()),
        };

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
