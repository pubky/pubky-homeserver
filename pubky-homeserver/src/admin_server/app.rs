use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use super::routes::{
    admin_events, dav_handler, delete_entry,
    disable_users::{disable_user, enable_user},
    generate_signup_token, info, root, signup_tokens, user_quota,
};
use super::trace::with_trace_layer;
use super::{app_state::AppState, auth_middleware::AdminAuthLayer};
use crate::AppContext;
#[cfg(any(test, feature = "testing"))]
use crate::MockDataDir;
use crate::{AppContextConversionError, PersistentDataDir};
use axum::routing::{any, delete, post};
use axum::{routing::get, Router};
use axum_server::Handle;
use tokio::task::JoinHandle;
use tower_http::cors::CorsLayer;

/// Admin password protected router.
fn create_protected_router(password: &str) -> Router<AppState> {
    Router::new()
        .route(
            "/generate_signup_token",
            get(generate_signup_token::generate_signup_token)
                .post(generate_signup_token::generate_signup_token_with_limits),
        )
        .route("/info", get(info::info))
        .route("/events-stream", get(admin_events::feed_stream))
        .route("/signup_tokens", get(signup_tokens::list_signup_tokens))
        .route("/webdav/{*entry_path}", delete(delete_entry::delete_entry))
        .route("/users/{pubkey}/disable", post(disable_user))
        .route("/users/{pubkey}/enable", post(enable_user))
        .route(
            "/users/{pubkey}/quota",
            get(user_quota::get_user_quota).patch(user_quota::patch_user_quota),
        )
        .layer(AdminAuthLayer::new(password.to_string()))
}

/// Public router without any authentication.
/// NO PASSWORD PROTECTION!
fn create_public_router() -> Router<AppState> {
    Router::new().route("/", get(root::handler))
}

/// Create the app
pub(crate) fn create_app(state: AppState) -> axum::routing::IntoMakeService<Router> {
    let admin_router = create_protected_router(state.admin_password());
    let public_router = create_public_router();
    let app = Router::new()
        .merge(admin_router)
        .merge(public_router)
        .route("/dav{*path}", any(dav_handler::dav_handler))
        .with_state(state)
        .layer(CorsLayer::very_permissive());

    with_trace_layer(app).into_make_service()
}

/// Errors that can occur when building a `AdminServer`.
#[derive(thiserror::Error, Debug)]
pub enum AdminServerBuildError {
    /// Failed to create admin server.
    #[error("Failed to create admin server: {0}")]
    Server(anyhow::Error),

    /// Failed to boostrap from the data directory.
    #[error("Failed to boostrap from the data directory: {0}")]
    DataDir(AppContextConversionError),
}

/// Admin server
///
/// This server is protected by the admin auth middleware.
///
/// When dropped, the server will stop.
pub struct AdminServer {
    http_handle: Handle<SocketAddr>,
    join_handle: JoinHandle<()>,
    socket: SocketAddr,
    password: String,
}

impl AdminServer {
    /// Create a new admin server from a data directory.
    pub async fn from_data_dir(data_dir: PersistentDataDir) -> Result<Self, AdminServerBuildError> {
        let context = AppContext::read_from(data_dir)
            .await
            .map_err(AdminServerBuildError::DataDir)?;
        Self::start(Arc::new(context)).await
    }

    /// Create a new admin server from a data directory path.
    pub async fn from_data_dir_path(data_dir_path: PathBuf) -> Result<Self, AdminServerBuildError> {
        let data_dir = PersistentDataDir::new(data_dir_path);
        Self::from_data_dir(data_dir).await
    }

    /// Create a new admin server from a mock data directory.
    #[cfg(any(test, feature = "testing"))]
    pub async fn from_mock_dir(mock_dir: MockDataDir) -> Result<Self, AdminServerBuildError> {
        let context = AppContext::read_from(mock_dir)
            .await
            .map_err(AdminServerBuildError::DataDir)?;
        Self::start(Arc::new(context)).await
    }

    /// Run the admin server.
    pub async fn start(context: Arc<AppContext>) -> Result<Self, AdminServerBuildError> {
        let state = AppState::new(Arc::clone(&context));
        let socket = context.config_toml.admin.listen_socket;
        let app = create_app(state);
        let listener = std::net::TcpListener::bind(socket)
            .map_err(|e| AdminServerBuildError::Server(e.into()))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| AdminServerBuildError::Server(e.into()))?;
        let socket = listener
            .local_addr()
            .map_err(|e| AdminServerBuildError::Server(e.into()))?;
        let http_handle = Handle::new();
        let inner_http_handle = http_handle.clone();
        let server =
            axum_server::from_tcp(listener).map_err(|e| AdminServerBuildError::Server(e.into()))?;
        let join_handle = tokio::spawn(async move {
            server
                .handle(inner_http_handle)
                .serve(app)
                .await
                .unwrap_or_else(|e| tracing::error!("Admin server error: {}", e));
        });
        Ok(Self {
            http_handle,
            socket,
            join_handle,
            password: context.config_toml.admin.admin_password.clone(),
        })
    }

    /// Get the socket address of the admin server.
    pub fn listen_socket(&self) -> SocketAddr {
        self.socket
    }

    /// Create a signup token for the given homeserver.
    pub async fn create_signup_token(&self) -> anyhow::Result<String> {
        let admin_socket = self.listen_socket();
        let url = format!("http://{}/generate_signup_token", admin_socket);
        let response = reqwest::Client::new()
            .get(url)
            .header("X-Admin-Password", &self.password)
            .send()
            .await?;
        let response = response.error_for_status()?;
        let body = response.text().await?;
        Ok(body)
    }
}

impl Drop for AdminServer {
    fn drop(&mut self) {
        self.http_handle
            .graceful_shutdown(Some(Duration::from_secs(5)));
        self.join_handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axum::http::Method;
    use axum_test::TestServer;
    use base64::Engine;
    use pubky_common::crypto::Keypair;

    use crate::admin_server::AdminAuthExt;
    use crate::persistence::sql::signup_code::{SignupCode, SignupCodeRepository};
    use crate::shared::quota::{BandwidthQuota, UserQuota};

    use super::*;

    fn bw(s: &str) -> BandwidthQuota {
        BandwidthQuota::from_str(s).unwrap()
    }

    fn create_test_server(context: &Arc<AppContext>) -> TestServer {
        AppState::test_server(context)
    }

    /// Seed `paths` as PUT events for a fresh random user, returning that user's pubkey.
    /// Within a test's fresh database, event ids are assigned in `paths` order starting at 1.
    async fn seed_put_events(
        context: &AppContext,
        paths: &[&str],
    ) -> pubky_common::crypto::PublicKey {
        use crate::persistence::files::events::EventType;
        use crate::shared::webdav::{EntryPath, StoragePath};
        use pubky_common::crypto::{Hash, Keypair};

        let pubkey = Keypair::random().public_key();
        let user = context.user_service.create(&pubkey).await.unwrap();
        for p in paths {
            let path = EntryPath::new(pubkey.clone(), StoragePath::new(p).unwrap());
            context
                .events_service
                .create_event(
                    user.id,
                    EventType::Put {
                        content_hash: Hash::from_bytes([0; 32]),
                    },
                    &path,
                    &mut context.sql_db.pool().into(),
                )
                .await
                .unwrap();
        }
        pubkey
    }

    /// GET the admin event stream in **batch** mode (no `live`) and return the raw SSE
    /// body, asserting a 200 with `Cache-Control: no-store`. Only use for non-live requests —
    /// the body is finite, so it can be buffered to a string.
    async fn admin_stream_body(server: &TestServer, query: &str) -> String {
        let response = server
            .get(&format!("/events-stream{query}"))
            .admin_auth()
            .expect_success()
            .await;
        response.assert_status_ok();
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "admin stream must be Cache-Control: no-store"
        );
        response.text()
    }

    /// Count SSE event frames (`event: <TYPE>` lines) in a batch body.
    fn count_sse_events(body: &str) -> usize {
        body.lines().filter(|l| l.starts_with("event: ")).count()
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_root() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let response = server.get("/").expect_success().await;
        response.assert_status_ok();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_generate_signup_token_fail() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        // No password
        let response = server.get("/generate_signup_token").expect_failure().await;
        response.assert_status_unauthorized();

        // wrong password
        let response = server
            .get("/generate_signup_token")
            .add_header("X-Admin-Password", "wrongpassword")
            .expect_failure()
            .await;
        response.assert_status_unauthorized();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_signup_tokens_fail() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);

        let response = server.get("/signup_tokens").expect_failure().await;
        response.assert_status_unauthorized();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_and_list_signup_token_success() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);

        let response = server
            .get("/generate_signup_token")
            .admin_auth()
            .expect_success()
            .await;
        let token = response.text();

        let response = server
            .get("/signup_tokens")
            .admin_auth()
            .expect_success()
            .await;
        response.assert_status_ok();

        let body: serde_json::Value = response.json();
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["token"], token);
        assert!(items[0]["created_at"].as_str().is_some());
        assert_eq!(items[0]["used_at"], serde_json::Value::Null);
        assert_eq!(items[0]["used_by"], serde_json::Value::Null);
        assert_eq!(body["next_cursor"], serde_json::Value::Null);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_signup_tokens_query_params_success() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);

        let token1 = SignupCode::new("0000-0000-0001".to_string()).unwrap();
        let token2 = SignupCode::new("0000-0000-0002".to_string()).unwrap();
        let token3 = SignupCode::new("0000-0000-0003".to_string()).unwrap();
        let token4 = SignupCode::new("0000-0000-0004".to_string()).unwrap();

        for token in [&token1, &token2, &token3, &token4] {
            SignupCodeRepository::create(
                token,
                &UserQuota::default(),
                &mut context.sql_db.pool().into(),
            )
            .await
            .unwrap();
        }

        let used_by = Keypair::random().public_key();
        SignupCodeRepository::mark_as_used(&token1, &used_by, &mut context.sql_db.pool().into())
            .await
            .unwrap();

        // With three unused tokens, limit=1 proves the page size is applied and
        // returns the last item in the page as the cursor.
        let response = server
            .get("/signup_tokens?state=unused&limit=1")
            .admin_auth()
            .expect_success()
            .await;
        response.assert_status_ok();

        let body: serde_json::Value = response.json();
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["token"], token2.to_string());
        assert_eq!(body["next_cursor"], token2.to_string());

        // Increasing the limit changes the page size and advances the cursor.
        let response = server
            .get("/signup_tokens?state=unused&limit=2")
            .admin_auth()
            .expect_success()
            .await;
        response.assert_status_ok();

        let body: serde_json::Value = response.json();
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["token"], token2.to_string());
        assert_eq!(items[1]["token"], token3.to_string());
        assert_eq!(body["next_cursor"], token3.to_string());

        // When the limit reaches all remaining unused tokens, there is no next page.
        let response = server
            .get("/signup_tokens?state=unused&limit=3")
            .admin_auth()
            .expect_success()
            .await;
        response.assert_status_ok();

        let body: serde_json::Value = response.json();
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0]["token"], token2.to_string());
        assert_eq!(items[1]["token"], token3.to_string());
        assert_eq!(items[2]["token"], token4.to_string());
        assert_eq!(body["next_cursor"], serde_json::Value::Null);

        // The cursor starts after the token it names, while keeping the unused filter.
        let response = server
            .get(&format!(
                "/signup_tokens?state=unused&limit=2&cursor={token2}"
            ))
            .admin_auth()
            .expect_success()
            .await;
        response.assert_status_ok();

        let body: serde_json::Value = response.json();
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["token"], token3.to_string());
        assert_eq!(items[1]["token"], token4.to_string());
        assert_eq!(body["next_cursor"], serde_json::Value::Null);
    }

    fn auth_header() -> String {
        let auth = base64::engine::general_purpose::STANDARD.encode("admin:admin");
        format!("Basic {auth}")
    }

    /// PROPFIND and GET on /dav/ root should succeed.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_dav_root_propfind_and_get() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let auth_value = auth_header();

        let propfind = Method::from_bytes(b"PROPFIND").unwrap();
        let response = server
            .method(propfind, "/dav/")
            .add_header("Authorization", auth_value.as_str())
            .add_header("Depth", "1")
            .expect_success()
            .await;
        // WebDAV PROPFIND returns 207 Multi-Status on success
        response.assert_status(axum::http::StatusCode::MULTI_STATUS);

        let response = server
            .get("/dav/")
            .add_header("Authorization", auth_value.as_str())
            .expect_success()
            .await;
        response.assert_status_ok();
    }

    /// PUT a file via WebDAV, GET it back, then DELETE it.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_dav_put_get_delete_file() {
        use pubky_common::crypto::Keypair;

        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let auth_value = auth_header();

        // Register a user so storage finalization can lock and account for the write.
        let keypair = Keypair::from_secret(&[0; 32]);
        let pubkey = keypair.public_key();
        context.user_service.create(&pubkey).await.unwrap();

        let file_content = b"hello webdav";
        let file_url = format!("/dav/{}/pub/test.txt", pubkey.z32());

        // PUT a file
        let response = server
            .put(&file_url)
            .add_header("Authorization", auth_value.as_str())
            .bytes(file_content.to_vec().into())
            .expect_success()
            .await;
        response.assert_status(axum::http::StatusCode::CREATED);

        // GET it back
        let response = server
            .get(&file_url)
            .add_header("Authorization", auth_value.as_str())
            .expect_success()
            .await;
        response.assert_status_ok();
        assert_eq!(response.as_bytes().as_ref(), file_content);

        // PROPFIND on the user's pub directory should list the file
        let propfind = Method::from_bytes(b"PROPFIND").unwrap();
        let dir_url = format!("/dav/{}/pub/", pubkey.z32());
        let response = server
            .method(propfind, &dir_url)
            .add_header("Authorization", auth_value.as_str())
            .add_header("Depth", "1")
            .expect_success()
            .await;
        response.assert_status(axum::http::StatusCode::MULTI_STATUS);
        let body = response.text();
        assert!(body.contains("test.txt"), "PROPFIND should list the file");

        // DELETE the file
        let response = server
            .delete(&file_url)
            .add_header("Authorization", auth_value.as_str())
            .expect_success()
            .await;
        response.assert_status(axum::http::StatusCode::NO_CONTENT);

        // GET should now return 404
        let response = server
            .get(&file_url)
            .add_header("Authorization", auth_value.as_str())
            .expect_failure()
            .await;
        response.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    /// Exceeding user quota through the admin DAV endpoint currently returns 500.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_dav_put_quota_overflow_returns_500() {
        use pubky_common::crypto::Keypair;

        let context = AppContext::test_with_config(|c| c.storage.default_quota_mb = Some(1)).await;
        let server = create_test_server(&context);
        let auth_value = auth_header();

        let keypair = Keypair::from_secret(&[0; 32]);
        let pubkey = keypair.public_key();
        context.user_service.create(&pubkey).await.unwrap();

        let pubkey = keypair.public_key().z32();
        let file1_url = format!("/dav/{pubkey}/pub/one.bin");
        let file2_url = format!("/dav/{pubkey}/pub/two.bin");
        let file_content = vec![0u8; 600_000];

        let response = server
            .put(&file1_url)
            .add_header("Authorization", auth_value.as_str())
            .bytes(file_content.clone().into())
            .expect_success()
            .await;
        response.assert_status(axum::http::StatusCode::CREATED);

        let response = server
            .put(&file2_url)
            .add_header("Authorization", auth_value.as_str())
            .bytes(file_content.into())
            .expect_failure()
            .await;
        response.assert_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_generate_signup_token_with_limits() {
        use crate::persistence::sql::signup_code::{SignupCode, SignupCodeRepository};
        use crate::shared::quota::user_quota::QuotaOverride;

        let context = AppContext::test().await;
        let server = create_test_server(&context);

        // POST with custom limits: null = Default, absent = Default, value = Value(T)
        let body = serde_json::json!({
            "storage_quota_mb": 1024,
            "rate_read": "200mb/m"
        });
        let response = server
            .post("/generate_signup_token")
            .admin_auth()
            .content_type("application/json")
            .bytes(serde_json::to_vec(&body).unwrap().into())
            .expect_success()
            .await;
        response.assert_status_ok();

        // Verify the code was created with custom limits
        let token_str = response.text();
        let code_id = SignupCode::new(token_str).unwrap();
        let code = SignupCodeRepository::get(&code_id, &mut context.sql_db.pool().into())
            .await
            .unwrap();
        let limits = code.quota();
        assert_eq!(limits.storage_quota_mb, QuotaOverride::Value(1024));
        assert_eq!(limits.rate_read, QuotaOverride::Value(bw("200mb/m")));
        assert_eq!(limits.rate_write, QuotaOverride::Default);
    }

    /// The stream rejects unauthenticated and malformed requests.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_stream_rejects_unauthorized_and_invalid() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);

        // Missing password → 401 (the stream lives behind AdminAuthLayer).
        let response = server.get("/events-stream").expect_failure().await;
        response.assert_status_unauthorized();

        // Wrong password → 401.
        let response = server
            .get("/events-stream")
            .add_header("X-Admin-Password", "wrongpassword")
            .expect_failure()
            .await;
        response.assert_status_unauthorized();

        // The malformed-request cases all 400 with a valid password.
        for query in [
            "?cursor=notanumber",
            "?live=true&reverse=true",
            "?limit=abc",
            "?limit=0",
        ] {
            let response = server
                .get(&format!("/events-stream{query}"))
                .admin_auth()
                .expect_failure()
                .await;
            response.assert_status_bad_request();
        }
    }

    /// Batch mode returns every event — public and private — with `limit` enforced and the
    /// SSE framing/no-store header the client expects. Empty DB yields an empty body.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_stream_returns_all_events() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);

        // Empty stream: 200, no-store (asserted in helper), no event frames.
        assert_eq!(count_sse_events(&admin_stream_body(&server, "").await), 0);

        // ids 1=/pub/a.txt, 2=/priv/app/secret.txt in this fresh DB.
        let pubkey = seed_put_events(&context, &["/pub/a.txt", "/priv/app/secret.txt"]).await;

        // Full firehose: both visibilities present, framed as PUT events.
        let body = admin_stream_body(&server, "").await;
        assert_eq!(count_sse_events(&body), 2);
        assert!(
            body.contains(&format!("pubky://{}/pub/a.txt", pubkey.z32())),
            "stream should include the public event: {body}"
        );
        assert!(
            body.contains(&format!("pubky://{}/priv/app/secret.txt", pubkey.z32())),
            "stream should include the private event: {body}"
        );
        assert!(body.contains("event: PUT"), "expected SSE framing: {body}");
        assert!(body.contains("cursor: "), "expected cursor lines: {body}");

        // `limit=1` stops after the first event (the public one).
        let body = admin_stream_body(&server, "?limit=1").await;
        assert_eq!(count_sse_events(&body), 1);
        assert!(body.contains(&format!("pubky://{}/pub/a.txt", pubkey.z32())));
        assert!(!body.contains("/priv/app/secret.txt"));
    }

    /// `user=` is an optional filter: it restricts the stream to the named users.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_stream_user_filter() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);

        let alice = seed_put_events(&context, &["/pub/alice.txt"]).await;
        let bob = seed_put_events(&context, &["/pub/bob.txt"]).await;

        // No filter → both users' events.
        let body = admin_stream_body(&server, "").await;
        assert_eq!(count_sse_events(&body), 2);

        // Filter to alice → only alice's event.
        let body = admin_stream_body(&server, &format!("?user={}", alice.z32())).await;
        assert_eq!(count_sse_events(&body), 1);
        assert!(body.contains(&format!("pubky://{}/pub/alice.txt", alice.z32())));
        assert!(!body.contains(&format!("pubky://{}/pub/bob.txt", bob.z32())));
    }

    /// Repeated `path=` unions the filters (file-vs-directory matching).
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_stream_repeated_path_filter() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);

        let pubkey = seed_put_events(&context, &["/pub/a.txt", "/pub/b.txt", "/priv/x.txt"]).await;

        // Exact file `/pub/a.txt` OR the `/priv/` subtree — not the sibling `/pub/b.txt`.
        let body = admin_stream_body(&server, "?path=/pub/a.txt&path=/priv/").await;
        assert_eq!(count_sse_events(&body), 2);
        assert!(body.contains(&format!("pubky://{}/pub/a.txt", pubkey.z32())));
        assert!(body.contains(&format!("pubky://{}/priv/x.txt", pubkey.z32())));
        assert!(
            !body.contains("/pub/b.txt"),
            "sibling file must be excluded: {body}"
        );
    }

    /// A single global `cursor=` resumes after the given event id.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_stream_cursor_resume() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);

        // ids 1,2,3 in this fresh DB.
        let pubkey = seed_put_events(&context, &["/pub/a.txt", "/pub/b.txt", "/pub/c.txt"]).await;

        // Resume after cursor 1 → only the later two events.
        let body = admin_stream_body(&server, "?cursor=1").await;
        assert_eq!(count_sse_events(&body), 2);
        assert!(
            !body.contains("/pub/a.txt"),
            "cursor=1 must skip the first event: {body}"
        );
        assert!(body.contains(&format!("pubky://{}/pub/b.txt", pubkey.z32())));
        assert!(body.contains(&format!("pubky://{}/pub/c.txt", pubkey.z32())));
    }
}
