//! Per Tenant (user / Pubky) routes.
//!
//! `/storage/{user_z32}/...` identifies the tenant in the URL. Deprecated
//! owner-relative routes retain the legacy Host / `pubky-host` lookup.
//!
//! Session management routes are provided by the auth module via
//! [`crate::client_server::auth::tenant_router`].
//! `LOCK`/`UNLOCK` (see [`lock`]) reach the `/storage` route through the
//! method-router fallback; the deprecated routes do not offer them.
//! Write handlers call [`authorize::authorize_write`] and read handlers call
//! [`crate::client_server::auth::has_read_permission`] to enforce
//! capability-based access control.

use axum::{
    middleware,
    routing::{get, put},
    Router,
};
use tower_http::limit::RequestBodyLimitLayer;

use crate::client_server::{
    cache_policy::private_cache_policy, middleware::storage_metrics, AppState,
};
use crate::observability::Metrics;
use crate::MAX_UPLOAD_BYTES;

mod authorize;
pub mod lock;
pub mod read;
pub mod write;

pub fn router(metrics: Metrics) -> Router<AppState> {
    // PUT streams the body directly, so the limit must wrap the body itself.
    let upload_limit = RequestBodyLimitLayer::new(MAX_UPLOAD_BYTES);

    Router::new()
        .route(
            "/storage/{user_z32}/{*path}",
            get(read::get)
                .head(read::head)
                .merge(put(write::put).layer(upload_limit))
                .delete(write::delete)
                // LOCK and UNLOCK are not in axum's method filter set.
                .fallback(lock::dispatch),
        )
        .route(
            "/{*path}",
            get(read::legacy_get)
                .head(read::legacy_head)
                .merge(put(write::legacy_put).layer(upload_limit))
                .delete(write::legacy_delete),
        )
        .layer(middleware::from_fn(private_cache_policy))
        .layer(middleware::from_fn_with_state(
            metrics,
            storage_metrics::record_request,
        ))
}
