//! Per Tenant (user / Pubky) routes.
//!
//! `/storage/{user_z32}/...` identifies the tenant in the URL. Deprecated
//! owner-relative routes retain the legacy Host / `pubky-host` lookup.
//!
//! Session management routes are provided by the auth module via
//! [`crate::client_server::auth::tenant_router`].
//! Write handlers call [`crate::client_server::auth::has_write_permission`] and
//! read handlers call [`crate::client_server::auth::has_read_permission`] to
//! enforce capability-based access control.

use axum::{extract::DefaultBodyLimit, middleware, routing::get, Router};

use crate::client_server::{cache_policy::private_cache_policy, AppState};

pub mod read;
pub mod write;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/storage/{user_z32}/{*path}",
            get(read::get)
                .head(read::head)
                .put(write::put)
                .delete(write::delete),
        )
        .route(
            "/{*path}",
            get(read::legacy_get)
                .head(read::legacy_head)
                .put(write::legacy_put)
                .delete(write::legacy_delete),
        )
        // TODO: different max size for sessions and other routes?
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        .layer(middleware::from_fn(private_cache_policy))
}
