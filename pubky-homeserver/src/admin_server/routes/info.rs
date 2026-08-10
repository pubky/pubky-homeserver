use super::super::app_state::AppState;
use crate::persistence::sql::signup_code::SignupCodeRepository;
use crate::shared::HttpResult;
use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct InfoResponse {
    num_users: u64,
    num_disabled_users: u64,
    total_disk_used_mb: u64,
    num_signup_codes: u64,
    num_unused_signup_codes: u64,
    public_key: String,
    pkarr_pubky_address: Option<String>,
    pkarr_icann_domain: Option<String>,
    version: String,
}

/// Return summary statistics about the homeserver.
pub async fn info(State(state): State<AppState>) -> HttpResult<(StatusCode, Json<InfoResponse>)> {
    let user_overview = state.user_service.get_overview().await?;
    let signup_code_overview =
        SignupCodeRepository::get_overview(&mut state.sql_db.pool().into()).await?;

    // Build response
    let body = InfoResponse {
        num_users: user_overview.count,
        num_disabled_users: user_overview.disabled_count,
        total_disk_used_mb: user_overview.total_used_mb,
        num_signup_codes: signup_code_overview.num_signup_codes,
        num_unused_signup_codes: signup_code_overview.num_unused_signup_codes,
        public_key: state.metadata.public_key.clone(),
        pkarr_pubky_address: state.metadata.pkarr_pubky_address.clone(),
        pkarr_icann_domain: state.metadata.pkarr_icann_domain.clone(),
        version: state.metadata.version.clone(),
    };

    Ok((StatusCode::OK, Json(body)))
}
