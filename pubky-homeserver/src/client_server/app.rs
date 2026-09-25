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
    http::{header::RETRY_AFTER, HeaderName},
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
    storage_metrics,
    trace::with_trace_layer,
};
use super::routes::{dav, events, info, root, signup_tokens, tenants};

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

    // WebDAV is kept out of the blanket CORS layer below and given `dav::cors`
    // instead. `CorsLayer` answers every OPTIONS request itself, which strips the
    // `DAV:` compliance header a client reads before it will mount anything;
    // `dav::cors` short-circuits only real preflights and lets a bare OPTIONS
    // through to dav-server.
    //
    // The wildcard abuts `/dav` rather than following a slash so that it also
    // matches `/dav/{user_z32}/`, which a client may probe before the folder it
    // mounts.
    //
    // The endpoint is anonymous, but it shares the REST routes' middleware so
    // the same request and bandwidth limits apply to it.
    let dav = if state.context.config_toml.drive.webdav {
        Router::new().route("/dav{*path}", any(dav::dav_handler))
    } else {
        Router::new()
    }
    .layer(axum_middleware::from_fn_with_state(
        state.context.metrics.clone(),
        storage_metrics::record_webdav_request,
    ))
    .with_state(state)
    .layer(middleware);

    // Resolve the target before tracing and authentication. Valid `/storage/...`
    // requests are therefore logged using their Pubky URL.
    // Keep CORS outermost so tenant-resolution errors are usable by browsers.
    let cors_app = with_trace_layer(app)
        .layer(axum_middleware::from_fn(RequestTenant::resolve))
        .layer(CorsLayer::very_permissive().expose_headers([
            RETRY_AFTER,
            // Browsers must be able to read a granted lock.
            HeaderName::from_static("lock-token"),
            HeaderName::from_static("timeout"),
        ]));
    // `dav::cors` sits outermost so it answers a browser preflight itself,
    // while a bare OPTIONS still reaches dav-server.
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
        let server = TestServer::new(router);
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
        // Lock-Token and Timeout ride along so browsers can read a granted lock.
        response.assert_header(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            "retry-after,lock-token,timeout",
        );
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
        let server = TestServer::new(router);

        let response = server.get("/info").await;

        response.assert_status(StatusCode::OK);
        response.assert_header(header::CONTENT_TYPE, "application/json");
        response.assert_header(header::CACHE_CONTROL, "no-store");
        response.assert_json(&serde_json::json!({
            "features": ["path-addressed-storage", "webdav-locks"]
        }));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn storage_metrics_only_count_resolved_requests_with_low_cardinality_labels() {
        let data_dir = MockDataDir::new(ConfigToml::minimal_test_config(), None).unwrap();
        let context = Arc::new(AppContext::read_from(data_dir).await.unwrap());
        let metrics = context.metrics.clone();
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router);
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
    async fn webdav_serves_public_folders_anonymously_and_nothing_else() {
        let context = AppContext::test().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router);
        let user = Keypair::random();
        let cookie = signup_cookie(&server, &user).await;
        let public_key = user.public_key().z32();
        let propfind = Method::from_bytes(b"PROPFIND").unwrap();

        put_public_file(&server, &user, &cookie, "dav.txt", b"hello").await;

        // No credentials: the file is served exactly as `/storage` serves it.
        server
            .get(&format!("/dav/{public_key}/pub/dav.txt"))
            .await
            .assert_text("hello");

        // Mounting starts with a PROPFIND of the folder.
        server
            .method(propfind.clone(), &format!("/dav/{public_key}/pub/"))
            .add_header("depth", "1")
            .await
            .assert_status(StatusCode::MULTI_STATUS);

        // The drive root and the private folder do not exist here, even to the
        // owner: 404 rather than 401 or 403, so nothing is confirmed.
        for path in [
            format!("/dav/{public_key}/"),
            format!("/dav/{public_key}/priv/"),
            format!("/dav/{public_key}/pub/../priv/secret.txt"),
        ] {
            server
                .method(propfind.clone(), &path)
                .add_header("depth", "1")
                .add_header("pubky-host", public_key.clone())
                .add_header(header::COOKIE, cookie.clone())
                .await
                .assert_status(StatusCode::NOT_FOUND);
        }

        // A write is refused before dav-server sees it, and `Allow` says why.
        let response = server
            .put(&format!("/dav/{public_key}/pub/dav.txt"))
            .add_header("pubky-host", public_key.clone())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(b"overwritten".to_vec().into())
            .await;
        response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
        response.assert_header(header::ALLOW, "OPTIONS, GET, HEAD, PROPFIND");
        server
            .get(&format!("/storage/{public_key}/pub/dav.txt"))
            .await
            .assert_text("hello");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn webdav_options_advertises_dav_compliance_while_storage_keeps_cors() {
        let context = AppContext::test().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router);
        let public_key = Keypair::random().public_key().z32();

        // `CorsLayer` answers every OPTIONS request itself, so a `/dav` route
        // sitting under it returns a bare 200. Clients read the `DAV:` header
        // off this response to decide whether the share is mountable at all —
        // without it, nothing mounts.
        let response = server
            .method(Method::OPTIONS, &format!("/dav/{public_key}/pub/"))
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
    async fn webdav_preflight_is_answered_for_any_origin() {
        let context = AppContext::test().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router);
        let public_key = Keypair::random().public_key().z32();

        let response = server
            .method(Method::OPTIONS, &format!("/dav/{public_key}/pub/"))
            .add_header(header::ORIGIN, "https://webdav.example")
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "PROPFIND")
            .add_header(header::ACCESS_CONTROL_REQUEST_HEADERS, "depth")
            .await;

        response.assert_status(StatusCode::NO_CONTENT);
        response.assert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");

        let allowed = response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .and_then(|v| v.to_str().ok())
            .expect("preflight must list allowed methods")
            .to_string();
        for method in ["PROPFIND", "GET", "HEAD"] {
            assert!(allowed.contains(method), "{method} missing from {allowed}");
        }
        for method in ["PUT", "DELETE", "MKCOL", "MOVE", "LOCK"] {
            assert!(!allowed.contains(method), "{method} offered on a read-only share");
        }

        let headers = response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .and_then(|v| v.to_str().ok())
            .expect("preflight must list allowed headers")
            .to_string();
        assert!(headers.contains("depth"), "depth missing from {headers}");

        // Nothing here is authenticated, so nothing should ever invite the
        // browser to attach the session cookie.
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
        let server = TestServer::new(router);
        let user = Keypair::random();
        let cookie = signup_cookie(&server, &user).await;
        let public_key = user.public_key().z32();

        // PROPFIND on a folder with nothing in it is a 404, so give it a file.
        put_public_file(&server, &user, &cookie, "cors.txt", b"hi").await;

        let response = server
            .method(
                Method::from_bytes(b"PROPFIND").unwrap(),
                &format!("/dav/{public_key}/pub/"),
            )
            .add_header(header::ORIGIN, "https://webdav.example")
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
        for name in ["dav", "etag"] {
            assert!(exposed.contains(name), "{name} missing from {exposed}");
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn webdav_is_absent_when_switched_off() {
        let context = AppContext::test_with_config(|c| c.drive.webdav = false).await;
        let server = TestServer::new(ClientServer::create_router(Arc::clone(&context)).unwrap());
        let public_key = Keypair::random().public_key().z32();

        // `/dav` paths fall through to the legacy owner-relative route rather
        // than 404, so the property that matters is that nothing answers as a
        // WebDAV server: no `DAV:` compliance header, and no 207.
        let response = server
            .method(Method::OPTIONS, &format!("/dav/{public_key}/pub/"))
            .await;
        assert!(
            !response.headers().contains_key("dav"),
            "the WebDAV endpoint is still advertising compliance"
        );
        let response = server
            .method(
                Method::from_bytes(b"PROPFIND").unwrap(),
                &format!("/dav/{public_key}/pub/"),
            )
            .await;
        assert_ne!(response.status_code(), StatusCode::MULTI_STATUS);
    }

    /// Write a file into `user`'s public folder over REST, the way an app does.
    async fn put_public_file(
        server: &TestServer,
        user: &Keypair,
        cookie: &str,
        name: &str,
        body: &[u8],
    ) {
        let public_key = user.public_key().z32();
        server
            .put(&format!("/storage/{public_key}/pub/{name}"))
            .add_header("pubky-host", public_key)
            .add_header(header::COOKIE, cookie.to_string())
            .bytes(body.to_vec().into())
            .expect_success()
            .await;
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
