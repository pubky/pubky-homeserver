//! Client-facing homeserver feature information.

use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Serialize;

const FEATURES: &[&str] = &[];

#[derive(Serialize)]
struct InfoResponse {
    features: &'static [&'static str],
}

/// Return the client features supported by this homeserver.
pub async fn get() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(InfoResponse { features: FEATURES }),
    )
}
