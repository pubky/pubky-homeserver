//! Client-facing homeserver feature information.

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use pubky_common::constants::features::{
    CONDITIONAL_GRANT_REVOCATION, GRANT_PROOF_LOGOUT, PATH_ADDRESSED_STORAGE, WEBDAV_LOCKS,
    WEBSITES,
};
use serde::Serialize;

use crate::client_server::AppState;

#[derive(Serialize)]
struct InfoResponse {
    features: Vec<&'static str>,
}

/// Return the client features supported by this homeserver.
pub async fn get(State(state): State<AppState>) -> impl IntoResponse {
    let mut features = vec![
        PATH_ADDRESSED_STORAGE,
        GRANT_PROOF_LOGOUT,
        WEBDAV_LOCKS,
        CONDITIONAL_GRANT_REVOCATION,
    ];
    if state.context.config_toml.drive.websites {
        features.push(WEBSITES);
    }
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(InfoResponse { features }),
    )
}
