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
    version: &'static str,
}

/// Return summary statistics about the homeserver.
pub async fn info(State(state): State<AppState>) -> HttpResult<(StatusCode, Json<InfoResponse>)> {
    let user_overview = state.context.user_service.get_overview().await?;
    let signup_code_overview =
        SignupCodeRepository::get_overview(&mut state.context.sql_db.pool().into()).await?;

    // Build response
    let body = InfoResponse {
        num_users: user_overview.count,
        num_disabled_users: user_overview.disabled_count,
        total_disk_used_mb: user_overview.total_used_mb,
        num_signup_codes: signup_code_overview.num_signup_codes,
        num_unused_signup_codes: signup_code_overview.num_unused_signup_codes,
        public_key: state.public_key(),
        pkarr_pubky_address: state.pkarr_pubky_address(),
        pkarr_icann_domain: state.pkarr_icann_domain(),
        version: state.version(),
    };

    Ok((StatusCode::OK, Json(body)))
}
