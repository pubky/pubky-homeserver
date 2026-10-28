//! The authenticated user's own account.

use axum::{
    extract::State,
    http::{header, HeaderValue},
    response::IntoResponse,
    Json,
};

use pubky_common::capabilities::Action;
use pubky_common::StoragePath;

use crate::client_server::auth::AuthSession;
use crate::client_server::cache_policy::CACHE_CONTROL_NO_STORE;
use crate::client_server::AppState;
use crate::shared::{HttpError, HttpResult, UserItem};

/// The response depends on the bearer alone: cookie sessions are rejected.
const VARY_AUTHORIZATION: HeaderValue = HeaderValue::from_static("Authorization");

/// `GET /account` — the caller's account in the same shape as the admin
/// `GET /users/{pubkey}` item.
///
/// Grant sessions only: a cookie session gets `401`. The client server's CORS
/// policy is fully permissive and session cookies are `SameSite=None`, so a
/// cookie-authenticated read would let any origin fetch the signed-in user's
/// account with the browser's cookie.
///
/// Requires read access to all storage (`/:r` or `/:rw`): account state is
/// not scoped to any path, so a scoped app has no claim to it, and a read
/// needs no write access. Disabled users can still read it, which is where
/// they learn why their writes are refused.
pub async fn get(
    State(state): State<AppState>,
    auth: AuthSession,
) -> HttpResult<impl IntoResponse> {
    let AuthSession::Grant(_) = &auth else {
        return Err(HttpError::unauthorized());
    };
    if !auth
        .capabilities()
        .grants(&StoragePath::root(), Action::Read)
    {
        return Err(HttpError::forbidden_with_message(
            "Read access to all storage required",
        ));
    }
    let user = state
        .context
        .user_service
        .get_or_http_error(auth.user_key(), false)
        .await?;
    Ok((
        [
            (header::CACHE_CONTROL, CACHE_CONTROL_NO_STORE),
            (header::VARY, VARY_AUTHORIZATION),
        ],
        Json(UserItem::new(&user, &state.context.config_toml)),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::Request;
    use axum::http::{header, StatusCode};
    use axum::middleware::{from_fn, Next};
    use axum::routing::get;
    use axum::Router;
    use axum_test::TestServer;
    use pubky_common::auth::jws::GrantId;
    use pubky_common::capabilities::{Capabilities, Capability};
    use pubky_common::crypto::{Keypair, PublicKey};

    use super::*;
    use crate::app_context::AppContext;
    use crate::client_server::auth::grant::session::GrantSession;
    use crate::client_server::test_utils::signup_cookie;
    use crate::client_server::ClientServer;

    /// A server for `/account` alone, with a grant session holding
    /// `capabilities` already resolved, as the auth middleware would leave it.
    async fn grant_server(
        context: &Arc<AppContext>,
        capabilities: Capabilities,
    ) -> (TestServer, PublicKey) {
        let pubkey = Keypair::random().public_key();
        context.user_service.create(&pubkey).await.unwrap();
        let expires_at = chrono::Utc::now().timestamp() as u64 + 3600;
        let session = AuthSession::Grant(GrantSession::test(
            pubkey.clone(),
            capabilities,
            GrantId::generate(),
            expires_at,
        ));
        let router = Router::new()
            .route("/account", get(super::get))
            .layer(from_fn(move |mut request: Request, next: Next| {
                let session = session.clone();
                async move {
                    request.extensions_mut().insert(session);
                    next.run(request).await
                }
            }))
            .with_state(AppState::new(Arc::clone(context)));
        (TestServer::new(router), pubkey)
    }

    /// A context for requests through the full router. The default IP rate
    /// limit on `/account` needs the client address a real connection carries,
    /// which `TestServer` requests do not have.
    async fn full_router_context() -> Arc<AppContext> {
        AppContext::test_with_config(|config| config.drive.rate_limits.clear()).await
    }

    fn root() -> Capabilities {
        Capabilities::builder().cap(Capability::root()).finish()
    }

    /// Read access to all storage is the bar, so `/:r` is enough and `/:rw`
    /// passes too.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn root_read_grant_sessions_get_their_own_account() {
        let context = AppContext::test().await;
        let read_only = Capabilities::builder().read("/").unwrap().finish();

        for capabilities in [root(), read_only] {
            let (server, pubkey) = grant_server(&context, capabilities).await;

            let response = server.get("/account").await;
            response.assert_status(StatusCode::OK);
            response.assert_header(header::CACHE_CONTROL, "no-store");
            response.assert_header(header::VARY, "Authorization");
            let body: serde_json::Value = response.json();
            assert_eq!(body["pubky"], pubkey.z32());
            assert!(body["created_at"].is_string());
            assert_eq!(body["disabled"], false);
            assert_eq!(body["used_bytes"], 0);
            assert_eq!(body["quota"]["overrides"], serde_json::json!({}));
            // The test config sets no storage default, so the effective quota is unlimited.
            assert_eq!(body["quota"]["effective"]["storage_quota_mb"], "unlimited");
            let mut keys: Vec<_> = body.as_object().unwrap().keys().collect();
            keys.sort();
            assert_eq!(
                keys,
                ["created_at", "disabled", "pubky", "quota", "used_bytes"]
            );
        }
    }

    /// Neither a path-scoped session nor one that can only write may read
    /// account-wide state.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn session_without_root_read_is_forbidden() {
        let context = AppContext::test().await;
        let scoped = Capabilities::builder()
            .read_write("/pub/scoped.app/")
            .unwrap()
            .finish();
        let write_only = Capabilities::builder().write("/").unwrap().finish();
        let keys_only = Capabilities::builder()
            .encryption_keys("/")
            .unwrap()
            .finish();

        for capabilities in [scoped, write_only, keys_only] {
            let (server, _pubkey) = grant_server(&context, capabilities).await;
            server
                .get("/account")
                .await
                .assert_status(StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn disabled_user_can_still_read_account() {
        let context = AppContext::test().await;
        let (server, pubkey) = grant_server(&context, root()).await;
        context.user_service.admin_disable(&pubkey).await.unwrap();

        let response = server.get("/account").await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["disabled"], true);
    }

    /// Cookie sessions must never reach the account: with permissive CORS and
    /// `SameSite=None` cookies, any origin could read it with the browser's cookie.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn cookie_session_is_unauthorized() {
        let context = full_router_context().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router);
        let keypair = Keypair::random();
        let cookie = signup_cookie(&server, &keypair, vec![Capability::root()]).await;

        server
            .get("/account")
            .add_header("host", keypair.public_key().z32())
            .add_header(header::COOKIE, cookie)
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn no_session_is_unauthorized() {
        let context = full_router_context().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router);

        server
            .get("/account")
            .add_header("host", Keypair::random().public_key().z32())
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }
}
