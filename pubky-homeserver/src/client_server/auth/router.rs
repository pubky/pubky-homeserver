//! Auth router constructors.
//!
//! The auth module provides two routers:
//! - [`base_router`]: Unauthenticated routes (signup, session creation).
//! - [`tenant_router`]: Authenticated session management routes.
//!
//! Cookie and grant routes are fully separated — each has its own URL namespace
//! and its own auth-method-specific middleware.

use axum::{
    routing::{delete, get, post},
    Router,
};

use super::cookie;
use super::grant;
use crate::client_server::auth::AuthState;

/// Base-level auth routes — no authentication middleware.
///
/// These are entry points for creating sessions:
/// - `POST /signup` — cookie-based user creation (deprecated)
/// - `POST /session` — cookie-based signin (deprecated)
/// - `POST /auth/grant/session` — grant-based session creation
/// - `POST /auth/grant/reconnect` — clear an app's reconnection block
pub fn base_router(auth_state: AuthState) -> Router<()> {
    Router::new()
        // Cookie (deprecated)
        .route("/signup", post(cookie::routes::signup))
        .route("/session", post(cookie::routes::signin))
        // Grant
        .route("/auth/grant/signup", post(grant::routes::signup))
        .route(
            "/auth/grant/session",
            post(grant::routes::create_grant_session),
        )
        .route("/auth/grant/reconnect", post(grant::routes::reconnect))
        .with_state(auth_state)
}

/// Tenant-level auth routes — with per-method authentication middleware.
///
/// Global authentication resolves credentials into `AuthSession`; handlers
/// enforce whether they accept cookie or grant sessions.
pub fn tenant_router(auth_state: AuthState) -> Router<()> {
    let cookie_routes = Router::new().route(
        "/session",
        get(cookie::routes::get_session).delete(cookie::routes::signout),
    );

    let grant_routes = Router::new()
        .route(
            "/auth/grant/session",
            get(grant::routes::get_session).delete(grant::routes::signout),
        )
        .route("/auth/grant/sessions", get(grant::routes::list_grants))
        .route(
            "/auth/grant/session/{gid}",
            delete(grant::routes::revoke_grant),
        );

    cookie_routes.merge(grant_routes).with_state(auth_state)
}
