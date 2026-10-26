//! The authenticated user's own account.

use axum::{extract::State, Json};

use crate::client_server::auth::{AuthSession, GrantAuthService};
use crate::client_server::AppState;
use crate::shared::{HttpResult, UserItem};

/// `GET /account` — the caller's account in the same shape as the admin
/// `GET /users/{pubkey}` item.
///
/// Requires a session with root capability: account state is not scoped to
/// any path, so a scoped app has no claim to it. Disabled users can still
/// read it, which is where they learn why their writes are refused.
pub async fn get(State(state): State<AppState>, auth: AuthSession) -> HttpResult<Json<UserItem>> {
    GrantAuthService::require_root_capability(&auth)?;
    let user = state
        .context
        .user_service
        .get_or_http_error(auth.user_key(), false)
        .await?;
    Ok(Json(UserItem::new(&user, &state.context.config_toml)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::{header, StatusCode};
    use axum_test::TestServer;
    use pubky_common::{capabilities::Capability, crypto::Keypair};

    use crate::app_context::AppContext;
    use crate::client_server::test_utils::signup_cookie;
    use crate::client_server::ClientServer;

    async fn setup() -> (Arc<AppContext>, TestServer) {
        let context = AppContext::test().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        (context, TestServer::new(router))
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn root_session_gets_its_own_account() {
        let (_context, server) = setup().await;
        let keypair = Keypair::random();
        let cookie = signup_cookie(&server, &keypair, vec![Capability::root()]).await;

        let response = server
            .get("/account")
            .add_header("host", keypair.public_key().z32())
            .add_header(header::COOKIE, cookie)
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();

        assert_eq!(body["pubky"], keypair.public_key().z32());
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

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn scoped_session_is_forbidden() {
        let (_context, server) = setup().await;
        let keypair = Keypair::random();
        let cookie = signup_cookie(
            &server,
            &keypair,
            vec![Capability::read_write("/pub/scoped.app/").unwrap()],
        )
        .await;

        server
            .get("/account")
            .add_header("host", keypair.public_key().z32())
            .add_header(header::COOKIE, cookie)
            .await
            .assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn no_session_is_unauthorized() {
        let (_context, server) = setup().await;
        let keypair = Keypair::random();

        server
            .get("/account")
            .add_header("host", keypair.public_key().z32())
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn disabled_user_can_still_read_account() {
        let (context, server) = setup().await;
        let keypair = Keypair::random();
        let cookie = signup_cookie(&server, &keypair, vec![Capability::root()]).await;
        context
            .user_service
            .admin_disable(&keypair.public_key())
            .await
            .unwrap();

        let response = server
            .get("/account")
            .add_header("host", keypair.public_key().z32())
            .add_header(header::COOKIE, cookie)
            .await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(body["disabled"], true);
    }
}
