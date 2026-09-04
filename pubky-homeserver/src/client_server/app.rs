use super::AppState;

#[cfg(any(test, feature = "testing"))]
use crate::MockDataDir;

use crate::{
    app_context::{AppContext, AppContextConversionError},
    PersistentDataDir,
};
use anyhow::Result;
use futures_util::TryFutureExt;

use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use axum::{
    http::header::RETRY_AFTER,
    middleware as axum_middleware,
    routing::{any, get},
    Router,
};
use axum_server::{
    tls_rustls::{RustlsAcceptor, RustlsConfig},
    Handle,
};
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::CorsLayer;

use super::auth::{self, AuthenticationLayer};
use super::cache_policy;
use super::middleware::{
    rate_limiter::{BandwidthQuotaLimitLayer, RequestRateLimitLayer},
    request_tenant::RequestTenant,
    trace::with_trace_layer,
};
use super::routes::{dav, drive, events, info, root, signup_tokens, tenants};

/// Errors that can occur when building a `HomeserverCore`.
#[derive(Debug, thiserror::Error)]
pub enum ClientServerBuildError {
    /// Failed to run the ICANN web server.
    #[error("ICANN web server error: {0}")]
    IcannWebServer(anyhow::Error),
    /// Failed to run the Pubky TLS web server.
    #[error("Pubky TLS web server error: {0}")]
    PubkyTlsServer(anyhow::Error),
    /// Failed to convert the data directory to an AppContext.
    #[error("AppContext conversion error: {0}")]
    AppContext(#[from] AppContextConversionError),
    /// Failed to build request-count rate limit layer.
    #[error("Request-count rate limit configuration error: {0}")]
    RequestRateLimits(String),
}
/// A Pubky homeserver with ICANN HTTP and Pubky TLS servers.
pub struct ClientServer {
    /// Keep context alive.
    context: Arc<AppContext>,

    pub(crate) icann_http_handle: Handle<SocketAddr>,
    pub(crate) icann_http_socket: SocketAddr,

    pub(crate) pubky_tls_handle: Handle<SocketAddr>,
    pub(crate) pubky_tls_socket: SocketAddr,
}

impl ClientServer {
    /// Run the homeserver with configurations from a data directory.
    pub async fn start_with_persistent_data_dir_path(
        dir_path: PathBuf,
    ) -> Result<Self, ClientServerBuildError> {
        let data_dir = PersistentDataDir::new(dir_path);
        let context = AppContext::read_from(data_dir).await?;
        Self::start(Arc::new(context)).await
    }

    /// Run the homeserver with configurations from a data directory.
    pub async fn start_with_persistent_data_dir(
        dir: PersistentDataDir,
    ) -> Result<Self, ClientServerBuildError> {
        let context = AppContext::read_from(dir).await?;
        Self::start(Arc::new(context)).await
    }

    /// Run the homeserver with configurations from a data directory mock.
    #[cfg(any(test, feature = "testing"))]
    pub async fn start_with_mock_data_dir(
        dir: MockDataDir,
    ) -> Result<Self, ClientServerBuildError> {
        let context = AppContext::read_from(dir).await?;
        Self::start(Arc::new(context)).await
    }

    /// Start homeserver services with the given application context.
    pub async fn start(
        context: Arc<AppContext>,
    ) -> std::result::Result<Self, ClientServerBuildError> {
        let router = Self::create_router(Arc::clone(&context))?;

        let (icann_http_handle, icann_http_socket) =
            Self::start_icann_http_server(&context, router.clone())
                .await
                .map_err(ClientServerBuildError::IcannWebServer)?;
        let (pubky_tls_handle, pubky_tls_socket) = Self::start_pubky_tls_server(&context, router)
            .await
            .map_err(ClientServerBuildError::PubkyTlsServer)?;

        Ok(Self {
            context,
            icann_http_handle,
            pubky_tls_handle,
            icann_http_socket,
            pubky_tls_socket,
        })
    }

    pub(crate) fn create_router(
        context: Arc<AppContext>,
    ) -> std::result::Result<Router, ClientServerBuildError> {
        let state = AppState::new(context);
        super::create_app(state)
    }

    /// Start the ICANN HTTP server
    async fn start_icann_http_server(
        context: &AppContext,
        router: Router,
    ) -> Result<(Handle<SocketAddr>, SocketAddr)> {
        // Icann http server
        let http_listener = TcpListener::bind(context.config_toml.drive.icann_listen_socket)?;
        http_listener.set_nonblocking(true)?;
        let http_socket = http_listener.local_addr()?;
        let http_handle = Handle::new();
        let server = axum_server::from_tcp(http_listener)?;
        tokio::spawn(
            server
                .handle(http_handle.clone())
                .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                .map_err(|error| {
                    tracing::error!(?error, "Homeserver icann http server error");
                    println!("Homeserver icann http server error: {:?}", error);
                }),
        );

        Ok((http_handle, http_socket))
    }

    /// Start the Pubky TLS server
    async fn start_pubky_tls_server(
        context: &AppContext,
        router: Router,
    ) -> Result<(Handle<SocketAddr>, SocketAddr)> {
        // Pubky tls server
        let https_listener = TcpListener::bind(context.config_toml.drive.pubky_listen_socket)?;
        https_listener.set_nonblocking(true)?;
        let https_socket = https_listener.local_addr()?;
        let https_handle = Handle::new();
        let server = axum_server::from_tcp(https_listener)?;
        tokio::spawn(
            server
                .acceptor(RustlsAcceptor::new(RustlsConfig::from_config(Arc::new(
                    context.keypair.to_rpk_rustls_server_config(),
                ))))
                .handle(https_handle.clone())
                .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                .map_err(|error| {
                    tracing::error!(?error, "Homeserver pubky tls server error");
                    println!("Homeserver pubky tls server error: {:?}", error);
                }),
        );

        Ok((https_handle, https_socket))
    }
    /// Get the URL of the icann http server.
    pub fn icann_http_url_string(&self) -> String {
        format!("http://{}", self.icann_http_socket)
    }

    /// Get the URL of the pubky tls server with the Pubky DNS name.
    pub fn pubky_tls_dns_url_string(&self) -> String {
        format!("https://{}", self.context.keypair.public_key().z32())
    }

    /// Get the URL of the pubky tls server with the Pubky IP address.
    pub fn pubky_tls_ip_url_ring(&self) -> String {
        format!("https://{}", self.pubky_tls_socket)
    }

    /// Shutdown the http and tls servers.
    pub fn shutdown(&self) {
        self.icann_http_handle
            .graceful_shutdown(Some(Duration::from_secs(5)));
        self.pubky_tls_handle
            .graceful_shutdown(Some(Duration::from_secs(5)));
    }
}

impl Drop for ClientServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn base() -> Router<AppState> {
    Router::new()
        .route("/", get(root::handler))
        .route("/signup_tokens/{token}", get(signup_tokens::get))
        // Browser file explorer. Same origin as `/dav`, which is what lets it
        // call an endpoint that sets no CORS headers.
        .route("/drive", get(drive::get))
        // Events
        .route("/events/", get(events::feed))
        .route(
            "/events-stream",
            get(events::feed_stream)
                .layer(axum_middleware::from_fn(cache_policy::sse_cache_policy)),
        )

    // TODO: add size limit
    // TODO: revisit if we enable streaming big payloads
    // TODO: maybe add to a separate router (drive router?).
}

pub fn create_app(state: AppState) -> std::result::Result<Router, ClientServerBuildError> {
    let auth_state = state.auth_state.clone();
    let request_rate_limit_layer = RequestRateLimitLayer::from_path_limits(
        state.context.config_toml.drive.rate_limits.clone(),
    )
    .map_err(ClientServerBuildError::RequestRateLimits)?;

    let middleware = ServiceBuilder::new()
        // Request order matters: auth needs CookieManager, and bandwidth limits
        // need AuthSession from authentication. RequestTenant runs outside this
        // stack so tracing and all of these layers see the resolved target.
        .layer(CookieManagerLayer::new())
        .layer(request_rate_limit_layer)
        .layer(AuthenticationLayer::new(auth_state.clone()))
        .layer(BandwidthQuotaLimitLayer::from_context(&state.context));

    let app = base()
        .merge(tenants::router(state.context.metrics.clone()))
        .with_state(state.clone())
        .merge(auth::base_router(auth_state.clone()))
        .merge(auth::tenant_router(auth_state))
        .layer(middleware.clone())
        // Keep feature discovery independent of authentication and database-backed quotas.
        .route("/info", get(info::get));

    // WebDAV gets the same middleware but is deliberately kept out of the CORS
    // layer below: `CorsLayer` answers every OPTIONS request itself, and a
    // WebDAV client reads the `DAV:` compliance header off that response to
    // decide whether the endpoint is mountable at all. Browsers cannot speak
    // WebDAV, so nothing is lost by leaving these routes without CORS.
    //
    // The wildcard abuts `/dav` rather than following a slash so that it also
    // matches `/dav/{user_z32}/`, the tenant root clients PROPFIND first.
    let dav = Router::new()
        .route("/dav{*path}", any(dav::dav_handler))
        .with_state(state)
        .layer(middleware);

    // Resolve the target before tracing and authentication. Valid `/storage/...`
    // requests are therefore logged using their Pubky URL.
    // Keep CORS outermost so tenant-resolution errors are usable by browsers.
    let cors_app = with_trace_layer(app)
        .layer(axum_middleware::from_fn(RequestTenant::resolve))
        .layer(CorsLayer::very_permissive().expose_headers([RETRY_AFTER]));
    // `dav::cors` sits outermost so it answers a browser preflight before
    // authentication can 401 it, while a bare OPTIONS still reaches dav-server.
    let dav_app = with_trace_layer(dav)
        .layer(axum_middleware::from_fn(RequestTenant::resolve))
        .layer(axum_middleware::from_fn(dav::cors));

    Ok(cors_app.merge(dav_app))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::{header, Method, StatusCode};
    use axum_test::TestServer;
    use pubky_common::{auth::AuthToken, capabilities::Capability, crypto::Keypair};

    use crate::{
        app_context::AppContext,
        client_server::ClientServer,
        data_directory::{ConfigToml, MockDataDir},
        shared::quota::{GlobPattern, HttpMethod, LimitKeyType, PathLimit},
    };

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn middleware_dependencies_support_cookie_auth_and_user_rate_limits() {
        let context = AppContext::test_with_config(|c| {
            c.drive.rate_limits = vec![PathLimit {
                path: GlobPattern::new("/session"),
                method: HttpMethod(Method::GET),
                quota: "1r/m".parse().unwrap(),
                key: LimitKeyType::User,
                burst: None,
                whitelist: Vec::new(),
            }];
        })
        .await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router).unwrap();
        let user = Keypair::random();

        let cookie = signup_cookie(&server, &user).await;

        server
            .get("/session")
            .add_header("host", user.public_key().z32())
            .add_header(header::COOKIE, cookie.clone())
            .expect_success()
            .await;

        let response = server
            .get("/session")
            .add_header("host", user.public_key().z32())
            .add_header(header::COOKIE, cookie)
            .add_header(header::ORIGIN, "https://app.example") // Add Origin, to turns this into a CORS request
            .await;

        response.assert_status(StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(header::RETRY_AFTER));

        // Retry-After is not CORS-safelisted, so browsers need it explicitly exposed.
        response.assert_header(header::ACCESS_CONTROL_EXPOSE_HEADERS, "retry-after");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn info_is_public_and_reports_features() {
        let context = AppContext::test_with_config(|c| {
            c.drive.rate_limits = vec![PathLimit {
                path: GlobPattern::new("/info"),
                method: HttpMethod(Method::GET),
                quota: "1r/m".parse().unwrap(),
                key: LimitKeyType::User,
                burst: None,
                whitelist: Vec::new(),
            }];
        })
        .await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router).unwrap();

        let response = server.get("/info").await;

        response.assert_status(StatusCode::OK);
        response.assert_header(header::CONTENT_TYPE, "application/json");
        response.assert_header(header::CACHE_CONTROL, "no-store");
        response.assert_json(&serde_json::json!({
            "features": ["path-addressed-storage"]
        }));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn storage_metrics_only_count_resolved_requests_with_low_cardinality_labels() {
        let data_dir = MockDataDir::new(ConfigToml::minimal_test_config(), None).unwrap();
        let context = Arc::new(AppContext::read_from(data_dir).await.unwrap());
        let metrics = context.metrics.clone();
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router).unwrap();
        let user = Keypair::random();
        let cookie = signup_cookie(&server, &user).await;
        let public_key = user.public_key().z32();
        let unrelated_public_key = Keypair::random().public_key().z32();
        let storage_path = "/pub/metrics-secret.txt";

        server
            .put(&format!(
                "/storage/{public_key}{storage_path}?pubky-host={public_key}"
            ))
            .add_header("pubky-host", public_key.clone())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(vec![1].into())
            .expect_success()
            .await;
        server
            .get(storage_path)
            .add_header("pubky-host", public_key.clone())
            .expect_success()
            .await;
        server
            .get(&format!("/storage/{public_key}{storage_path}"))
            .add_header("pubky-host", unrelated_public_key.clone())
            .expect_success()
            .await;
        server
            .get(&format!("{storage_path}?pubky-host={public_key}"))
            .expect_success()
            .await;
        server
            .get("/favicon.ico")
            .await
            .assert_status(StatusCode::BAD_REQUEST);

        let output = metrics.render().unwrap();
        let samples = output
            .lines()
            .filter(|line| line.starts_with("storage_request_count_total{"))
            .collect::<Vec<_>>();

        assert_eq!(samples.len(), 4, "unexpected metric samples:\n{output}");
        assert!(samples.iter().any(|sample: &&str| {
            sample.contains("addressing_mode=\"path\"")
                && sample.contains("auth_method=\"cookie\"")
                && sample.contains("pubky_host_header=\"matching\"")
                && sample.contains("pubky_host_query=\"true\"")
        }));
        assert!(samples.iter().any(|sample: &&str| {
            sample.contains("addressing_mode=\"legacy\"")
                && sample.contains("auth_method=\"none\"")
                && sample.contains("pubky_host_header=\"matching\"")
                && sample.contains("pubky_host_query=\"false\"")
        }));
        assert!(samples.iter().any(|sample: &&str| {
            sample.contains("addressing_mode=\"path\"")
                && sample.contains("auth_method=\"none\"")
                && sample.contains("pubky_host_header=\"other\"")
                && sample.contains("pubky_host_query=\"false\"")
        }));
        assert!(samples.iter().any(|sample: &&str| {
            sample.contains("addressing_mode=\"legacy\"")
                && sample.contains("auth_method=\"none\"")
                && sample.contains("pubky_host_header=\"absent\"")
                && sample.contains("pubky_host_query=\"true\"")
        }));
        assert!(!output.contains(&public_key));
        assert!(!output.contains(&unrelated_public_key));
        assert!(!output.contains(storage_path));
        assert!(!output.contains(&cookie));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn webdav_serves_the_authenticated_drive_and_no_other() {
        let context = AppContext::test().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router).unwrap();
        let user = Keypair::random();
        let cookie = signup_cookie(&server, &user).await;
        let public_key = user.public_key().z32();
        let propfind = Method::from_bytes(b"PROPFIND").unwrap();

        // Without credentials, the challenge is what makes a client prompt.
        let response = server
            .method(propfind.clone(), &format!("/dav/{public_key}/"))
            .await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        response.assert_header(header::WWW_AUTHENTICATE, r#"Basic realm="pubky""#);

        // A WebDAV write must land on the storage key the REST route reads,
        // which is what stripping only `/dav` buys us.
        server
            .put(&format!("/dav/{public_key}/pub/dav.txt"))
            .add_header("pubky-host", public_key.clone())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(b"hello".to_vec().into())
            .expect_success()
            .await;
        server
            .get(&format!("/storage/{public_key}/pub/dav.txt"))
            .await
            .assert_text("hello");

        // Mounting a drive starts with a PROPFIND of its root.
        server
            .method(propfind, &format!("/dav/{public_key}/"))
            .add_header("pubky-host", public_key.clone())
            .add_header(header::COOKIE, cookie.clone())
            .add_header("depth", "1")
            .await
            .assert_status(StatusCode::MULTI_STATUS);

        // Another drive stays out of reach however the path is spelled.
        let other = Keypair::random().public_key().z32();
        for path in [
            format!("/dav/{other}/pub/dav.txt"),
            format!("/dav/{public_key}/pub/../../{other}/pub/dav.txt"),
        ] {
            server
                .get(&path)
                .add_header("pubky-host", public_key.clone())
                .add_header(header::COOKIE, cookie.clone())
                .await
                .assert_status(StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn webdav_options_advertises_dav_compliance_while_storage_keeps_cors() {
        let context = AppContext::test().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router).unwrap();
        let user = Keypair::random();
        let cookie = signup_cookie(&server, &user).await;
        let public_key = user.public_key().z32();

        // `CorsLayer` answers every OPTIONS request itself, so a `/dav` route
        // sitting under it returns a bare 200. Clients read the `DAV:` header
        // off this response to decide whether the share is mountable at all —
        // without it, nothing mounts.
        let response = server
            .method(Method::OPTIONS, &format!("/dav/{public_key}/"))
            .add_header("pubky-host", public_key.clone())
            .add_header(header::COOKIE, cookie)
            .await;
        response.assert_status_ok();
        let dav = response
            .headers()
            .get("dav")
            .expect("OPTIONS must advertise DAV compliance");
        assert!(
            dav.to_str().unwrap().starts_with('1'),
            "unexpected DAV compliance classes: {dav:?}"
        );

        // The REST routes still need their CORS preflight answered.
        server
            .method(Method::OPTIONS, &format!("/storage/{public_key}/pub/x"))
            .add_header(header::ORIGIN, "https://app.example")
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .await
            .assert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "https://app.example");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn webdav_preflight_is_answered_without_credentials_or_cookies() {
        let context = AppContext::test().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router).unwrap();
        let public_key = Keypair::random().public_key().z32();

        // A browser strips credentials from a preflight, so this must be
        // answered before authentication rather than 401'd.
        let response = server
            .method(Method::OPTIONS, &format!("/dav/{public_key}/"))
            .add_header(header::ORIGIN, "https://webdav.example")
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "PROPFIND")
            .add_header(
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "authorization,depth",
            )
            .await;

        response.assert_status(StatusCode::NO_CONTENT);
        response.assert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");

        let allowed = response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .and_then(|v| v.to_str().ok())
            .expect("preflight must list allowed methods")
            .to_string();
        for method in ["PROPFIND", "MKCOL", "MOVE", "LOCK", "PUT", "DELETE"] {
            assert!(allowed.contains(method), "{method} missing from {allowed}");
        }

        let headers = response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .and_then(|v| v.to_str().ok())
            .expect("preflight must list allowed headers")
            .to_string();
        for name in ["authorization", "depth", "destination"] {
            assert!(headers.contains(name), "{name} missing from {headers}");
        }

        // The session cookie is SameSite=None, so allowing credentials here
        // would let any origin read a signed-in user's drive.
        assert!(
            !response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
            "credentials must never be allowed cross-origin on /dav"
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn webdav_cross_origin_response_exposes_headers_clients_need() {
        let context = AppContext::test().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router).unwrap();
        let user = Keypair::random();
        let cookie = signup_cookie(&server, &user).await;
        let public_key = user.public_key().z32();

        // PROPFIND on a drive with nothing in it is a 404, so give it a file.
        server
            .put(&format!("/dav/{public_key}/pub/cors.txt"))
            .add_header("pubky-host", public_key.clone())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(b"hi".to_vec().into())
            .expect_success()
            .await;

        let response = server
            .method(
                Method::from_bytes(b"PROPFIND").unwrap(),
                &format!("/dav/{public_key}/"),
            )
            .add_header(header::ORIGIN, "https://webdav.example")
            .add_header("pubky-host", public_key.clone())
            .add_header(header::COOKIE, cookie)
            .add_header("depth", "1")
            .await;

        response.assert_status(StatusCode::MULTI_STATUS);
        response.assert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");

        let exposed = response
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .and_then(|v| v.to_str().ok())
            .expect("cross-origin responses must expose WebDAV headers")
            .to_string();
        for name in ["dav", "lock-token", "etag"] {
            assert!(exposed.contains(name), "{name} missing from {exposed}");
        }
    }

    async fn signup_cookie(server: &TestServer, keypair: &Keypair) -> String {
        let auth_token = AuthToken::sign(keypair, vec![Capability::root()]);
        let body_bytes: axum::body::Bytes = auth_token.serialize().into();
        let response = server
            .post("/signup")
            .add_header("host", keypair.public_key().z32())
            .bytes(body_bytes)
            .expect_success()
            .await;

        response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|h| h.to_str().ok())
            .expect("signup should return a session cookie")
            .to_string()
    }
}
