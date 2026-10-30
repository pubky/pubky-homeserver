//! Auth router constructors.
//!
//! The auth module provides two routers:
//! - [`base_router`]: Unauthenticated routes (signup, session creation).
//! - [`tenant_router`]: Authenticated session management routes.
//!
//! Cookie and grant routes are fully separated — each has its own URL namespace
//! and its own auth-method-specific middleware.

use axum::{
    extract::DefaultBodyLimit,
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
            "/auth/grant/session-revocation",
            post(grant::routes::revoke_original_bearer).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/auth/grant/session/{gid}",
            delete(grant::routes::revoke_grant),
        );

    cookie_routes.merge(grant_routes).with_state(auth_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_context::AppContext;
    use crate::client_server::auth::cookie::persistence::{SessionEntity, SessionSecret};
    use crate::client_server::auth::AuthSession;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use pubky_common::{
        auth::{
            grant_revocation::ConditionalGrantRevocation,
            jws::{ClientId, GrantId, RandomId},
        },
        capabilities::{Capabilities, Capability},
        crypto::Keypair,
    };
    use tower::ServiceExt;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn conditional_revocation_preserves_management_route_and_refuses_cookie() {
        let context = AppContext::test().await;
        let router = tenant_router(AuthState::new(&context));
        // Both are valid grant IDs. A static revocation route must not shadow
        // the existing management DELETE route and turn authentication into 405.
        for id in ["revoke", "session-revocation"] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(format!("/auth/grant/session/{id}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let owner = Keypair::random().public_key();
        let cookie = AuthSession::Cookie(SessionEntity {
            id: 1,
            secret: SessionSecret::random(),
            user_id: 1,
            user_pubkey: owner.clone(),
            capabilities: Capabilities::builder().cap(Capability::root()).finish(),
            created_at: chrono::Utc::now().naive_utc(),
        });
        let body = ConditionalGrantRevocation {
            operation_id: RandomId::generate(),
            grant_id: GrantId::generate(),
            pubky: owner,
            client_id: ClientId::new("conditional.test").unwrap(),
        };
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/grant/session-revocation")
                    .header("Content-Type", "application/json")
                    .extension(cookie)
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
