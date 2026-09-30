//! Read-only WebDAV access to every user's public folder.
//!
//! Mounted at `/dav/{user_z32}/pub/...`, this serves the same files as
//! `/storage/{user_z32}/pub/...` to standard WebDAV clients (GNOME Files,
//! Finder, rclone, browsers). It is off unless `[drive] webdav_enabled` is
//! set; without it the client server has no `/dav` route. The endpoint itself
//! — `dav-server`, the verb policy and CORS — is [`DavEndpoint`], shared with
//! the admin server; what this module adds is the policy for *who sees what*.
//!
//! Nothing here is authenticated. `/pub/` is world-readable over REST, and this
//! endpoint exposes exactly that and no more:
//!
//! - The share is [`DavAccess::ReadOnly`]: anything that would write gets
//!   `405`, which is what tells a file manager to mount it read-only.
//! - Only paths under `/pub/` exist. Everything else — the drive root
//!   included — is `404`, so the endpoint never confirms that `/priv/` is there.
//!
//! The confinement to `/pub/` is enforced twice: [`DavTarget`] canonicalizes
//! each path within its drive and refuses anything outside the public folder,
//! and the operator the endpoint is built on is scoped to that folder at the
//! storage boundary, so a mistake in the first cannot reach a private folder or
//! the storage root.
use axum::{
    body::Body,
    extract::{Request, State},
    http::Method,
    response::Response,
    Router,
};

use crate::client_server::AppState;
use crate::shared::{
    webdav::{
        endpoint::{self as dav_endpoint, DavAccess, DavEndpoint},
        target::DavTarget,
    },
    HttpError, HttpResult,
};

/// The `/dav` routes.
pub(crate) fn router(state: AppState) -> Router {
    dav_endpoint::router(DavAccess::ReadOnly, dav_handler).with_state(state)
}

async fn dav_handler(State(state): State<AppState>, req: Request<Body>) -> HttpResult<Response> {
    let target = DavTarget::parse(req.uri().path())?;
    // `OPTIONS` is a capability probe that touches nothing, so it is answered
    // anywhere a drive is named: a client may well send it above the folder it
    // is about to mount.
    if req.method() != Method::OPTIONS && !target.is_public() {
        // Not 403: a refusal would confirm there is something there to refuse.
        return Err(HttpError::not_found());
    }

    // Built per request rather than shared, because the confinement is the
    // point: the operator is scoped to this drive's public folder.
    let operator = state
        .context
        .file_service
        .opendal
        .public_folder_operator(target.tenant());
    Ok(DavEndpoint::new(operator, DavAccess::ReadOnly)
        .handle(req)
        .await)
}

#[cfg(test)]
mod tests {
    //! These drive the whole client server the way a file manager would, so
    //! the path policy in this module is exercised together with the CORS,
    //! rate limits and bandwidth limits it is merged beside. The
    //! path policy itself is pinned in `target.rs`; the endpoint's own
    //! behaviour in `endpoint.rs`.
    use std::time::{Duration, Instant};

    use axum::http::{header, StatusCode};
    use axum_test::{TestRequest, TestResponse, TestServer};
    use pubky_common::{auth::AuthToken, capabilities::Capability, crypto::Keypair};

    use super::*;
    use crate::{app_context::AppContext, client_server::ClientServer, ConfigToml};

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn serves_a_public_file_anonymously_exactly_as_rest_does() {
        let share = Share::new().await;
        share.put("dav.txt", b"hello").await;

        share
            .server
            .get(&share.dav("/pub/dav.txt"))
            .await
            .assert_text("hello");
        share
            .server
            .get(&share.storage("/pub/dav.txt"))
            .await
            .assert_text("hello");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn the_share_is_not_served_unless_the_config_enables_it() {
        // Off is the default, so this is what a deployment that never heard
        // of `webdav_enabled` serves: `/dav` is a path like any other the
        // server has no route for, while REST carries on.
        let share = Share::with_config(|c| {
            c.drive.webdav_enabled = ConfigToml::default().drive.webdav_enabled;
        })
        .await;
        share.put("dav.txt", b"hello").await;
        let unrouted = format!("/no-such-route/{}/pub/dav.txt", share.public_key);

        for method in [
            Method::GET,
            Method::OPTIONS,
            Method::from_bytes(b"PROPFIND").unwrap(),
        ] {
            let request = |path: &str| share.server.method(method.clone(), path);
            let response = request(&share.dav("/pub/dav.txt")).await;

            assert_eq!(
                response.status_code(),
                request(&unrouted).await.status_code(),
                "{method} is answered as a route of its own"
            );
            // `CorsLayer` still answers the OPTIONS, but without the header
            // a file manager decides to mount from.
            assert!(response.maybe_header("dav").is_none(), "{method}");
        }

        share
            .server
            .get(&share.storage("/pub/dav.txt"))
            .await
            .assert_text("hello");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn head_describes_a_file_without_sending_it() {
        let share = Share::new().await;
        share.put("dav.txt", b"hello").await;

        let response = share
            .server
            .method(Method::HEAD, &share.dav("/pub/dav.txt"))
            .await;

        response.assert_status_ok();
        response.assert_header(header::CONTENT_LENGTH, "5");
        assert!(response.as_bytes().is_empty(), "HEAD must carry no body");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_ranged_get_resumes_a_download() {
        // `EXPOSE_HEADERS` promises `content-range` and `accept-ranges`; this
        // is the request they exist for.
        let share = Share::new().await;
        share.put("dav.txt", b"hello").await;

        let response = share
            .server
            .get(&share.dav("/pub/dav.txt"))
            .add_header(header::RANGE, "bytes=1-3")
            .await;

        response.assert_status(StatusCode::PARTIAL_CONTENT);
        response.assert_header(header::CONTENT_RANGE, "bytes 1-3/5");
        response.assert_header(header::ACCEPT_RANGES, "bytes");
        response.assert_text("ell");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn mounting_starts_with_a_propfind_of_the_folder() {
        let share = Share::new().await;
        share.put("dav.txt", b"hello").await;

        let response = propfind(&share.server, &share.dav("/pub/")).await;

        response.assert_status(StatusCode::MULTI_STATUS);
        assert!(response.text().contains("dav.txt"), "{}", response.text());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn nothing_outside_the_public_folder_exists_even_to_its_owner() {
        let share = Share::new().await;
        share.put("dav.txt", b"hello").await;

        // 404 rather than 401 or 403, so nothing is confirmed. The owner's own
        // session changes nothing: this share has no notion of who is asking.
        for path in ["/", "/priv/", "/pub/../priv/secret.txt", "/.DS_Store"] {
            propfind(&share.server, &share.dav(path))
                .add_header("pubky-host", share.public_key.clone())
                .add_header(header::COOKIE, share.cookie.clone())
                .await
                .assert_status(StatusCode::NOT_FOUND);
            share
                .server
                .get(&share.dav(path))
                .add_header(header::COOKIE, share.cookie.clone())
                .await
                .assert_status(StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_bare_options_tells_a_file_manager_the_share_is_read_only() {
        let share = Share::new().await;
        share.put("dav.txt", b"hello").await;

        // No locking class, and an `Allow` with no write verb in it, on the
        // folder and on a file alike. `CorsLayer` would have answered this
        // itself with neither header; see `endpoint::router`.
        for (path, expected) in [
            ("/pub/", &["OPTIONS", "PROPFIND"][..]),
            ("/pub/dav.txt", &["OPTIONS", "GET", "HEAD", "PROPFIND"][..]),
        ] {
            let response = share.server.method(Method::OPTIONS, &share.dav(path)).await;
            response.assert_status_ok();
            response.assert_header("dav", "1");
            assert_eq!(allow_set(&response), verbs(expected), "{path}");
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn options_is_answered_anywhere_a_drive_is_named_and_confirms_nothing() {
        // A client may probe above the folder it is about to mount. The probe
        // touches nothing, so it is answered — and answered identically
        // wherever it lands, so the answer says nothing about what is there.
        let share = Share::new().await;
        share.put("dav.txt", b"hello").await;
        share.put_at("/priv/secret.txt", b"shh").await;
        // Whatever the answer for a public path that does not exist is, every
        // path outside the public folder must get the same one — whether or
        // not something is really there.
        let reference = share
            .server
            .method(Method::OPTIONS, &share.dav("/pub/nothing-here"))
            .await;
        let reference = (header_str(&reference, "dav"), allow_set(&reference));

        for path in ["/", "/priv/", "/priv/secret.txt", "/priv/nothing-here"] {
            let response = share.server.method(Method::OPTIONS, &share.dav(path)).await;
            response.assert_status_ok();
            assert_eq!(
                (header_str(&response, "dav"), allow_set(&response)),
                reference,
                "{path} answers differently from a missing public path"
            );
        }

        // A path that names no drive at all cannot be answered for one.
        for path in ["/dav/", "/dav/not-a-public-key/pub/"] {
            share
                .server
                .method(Method::OPTIONS, path)
                .await
                .assert_status(StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_write_is_refused_with_an_allow_a_file_manager_can_read() {
        let share = Share::new().await;
        share.put("dav.txt", b"hello").await;

        // Even the owner, with a valid session: this share does not write.
        // The refusal happens before dav-server sees the request, and
        // dav-server's own 405 would carry no `Allow`.
        let response = share
            .server
            .put(&share.dav("/pub/dav.txt"))
            .add_header("pubky-host", share.public_key.clone())
            .add_header(header::COOKIE, share.cookie.clone())
            .bytes(b"overwritten".to_vec().into())
            .await;

        response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
        response.assert_header(header::ALLOW, "OPTIONS, GET, HEAD, PROPFIND");
        share
            .server
            .get(&share.storage("/pub/dav.txt"))
            .await
            .assert_text("hello");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_folder_has_no_index_page() {
        // A browser GET on a folder would list it exactly as PROPFIND does,
        // one stat per entry, through a verb a PROPFIND rate limit never
        // sees. So it is refused, with an `Allow` naming what a folder takes.
        let share = Share::new().await;
        share.put("dav.txt", b"hello").await;

        for method in [Method::GET, Method::HEAD] {
            let response = share.server.method(method, &share.dav("/pub/")).await;
            response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
            response.assert_header(header::ALLOW, "OPTIONS, PROPFIND");
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_verb_dav_server_has_never_heard_of_fails_closed() {
        let share = Share::new().await;
        share.put("dav.txt", b"hello").await;

        // Refused before any method set applies, so 501 rather than 405.
        share
            .server
            .method(
                Method::from_bytes(b"FROBNICATE").unwrap(),
                &share.dav("/pub/dav.txt"),
            )
            .await
            .assert_status(StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn options_advertises_dav_compliance_while_storage_keeps_cors() {
        let share = Share::new().await;

        // `CorsLayer` answers every OPTIONS request itself, so a `/dav` route
        // sitting under it returns a bare 200. Clients read the `DAV:` header
        // off this response to decide whether the share is mountable at all —
        // without it, nothing mounts. Nothing exists at this path yet, and
        // dav-server's answer for an unmapped path would offer MKCOL, PUT and
        // LOCK unless told the share is read-only.
        let response = share
            .server
            .method(Method::OPTIONS, &share.dav("/pub/"))
            .await;
        response.assert_status_ok();
        response.assert_header("dav", "1");
        assert_eq!(allow_set(&response), verbs(&["OPTIONS"]));

        // The REST routes still need their CORS preflight answered.
        share
            .server
            .method(Method::OPTIONS, &share.storage("/pub/x"))
            .add_header(header::ORIGIN, "https://app.example")
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .await
            .assert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "https://app.example");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_preflight_is_answered_for_any_origin_without_credentials() {
        let share = Share::new().await;

        let response = share
            .server
            .method(Method::OPTIONS, &share.dav("/pub/"))
            .add_header(header::ORIGIN, "https://webdav.example")
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "PROPFIND")
            // A listing, a resumed download and a conditional fetch each need
            // a header the browser must ask permission for.
            .add_header(
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "depth, range, if-none-match",
            )
            .await;

        response.assert_status(StatusCode::NO_CONTENT);
        response.assert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        response.assert_header(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            "OPTIONS, GET, HEAD, PROPFIND",
        );
        response.assert_header(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            "depth, range, if-none-match",
        );
        // Nothing here is authenticated, so nothing should ever invite the
        // browser to attach the session cookie.
        assert!(
            response
                .maybe_header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "credentials must never be allowed cross-origin on /dav"
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_cross_origin_response_exposes_the_headers_clients_need() {
        let share = Share::new().await;
        share.put("cors.txt", b"hi").await;

        let response = propfind(&share.server, &share.dav("/pub/"))
            .add_header(header::ORIGIN, "https://webdav.example")
            .await;

        response.assert_status(StatusCode::MULTI_STATUS);
        response.assert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        let exposed = header_str(&response, "access-control-expose-headers");
        for name in ["dav", "etag", "content-range"] {
            assert!(exposed.contains(name), "{name} missing from {exposed}");
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn propfind_depth_is_finite_by_default() {
        // dav-server refuses `Depth: infinity` outright, and serves a request
        // with no `Depth` as a one-level listing. Both are what the user guide
        // promises.
        let share = Share::new().await;
        share.put("depth.txt", b"x").await;
        let folder = share.dav("/pub/");
        let request = || {
            share
                .server
                .method(Method::from_bytes(b"PROPFIND").unwrap(), &folder)
                .add_header("x-forwarded-for", CLIENT_IP)
        };

        let response = request().add_header("depth", "infinity").await;
        response.assert_status(StatusCode::NOT_IMPLEMENTED);
        assert!(
            response.text().contains("propfind-finite-depth"),
            "{}",
            response.text()
        );

        let response = request().await;
        response.assert_status(StatusCode::MULTI_STATUS);
        assert!(response.text().contains("depth.txt"), "{}", response.text());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn the_content_type_is_guessed_from_the_name() {
        // REST serves the type a file was stored with; dav-server serves what
        // the extension suggests. A file with no extension is octet-stream
        // over WebDAV whatever it holds — a documented limitation.
        let share = Share::new().await;
        for name in ["picture", "picture.png"] {
            share
                .server
                .put(&share.storage(&format!("/pub/{name}")))
                .add_header("pubky-host", share.public_key.clone())
                .add_header(header::COOKIE, share.cookie.clone())
                .content_type("image/png")
                .bytes(b"\x89PNG".to_vec().into())
                .expect_success()
                .await;
        }

        share
            .server
            .get(&share.storage("/pub/picture"))
            .await
            .assert_header(header::CONTENT_TYPE, "image/png");
        share
            .server
            .get(&share.dav("/pub/picture"))
            .await
            .assert_header(header::CONTENT_TYPE, "application/octet-stream");
        share
            .server
            .get(&share.dav("/pub/picture.png"))
            .await
            .assert_header(header::CONTENT_TYPE, "image/png");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn an_operator_can_rate_limit_propfind_per_client() {
        // No limit on `/dav` ships; this is the one an operator would add,
        // at one request so the test can reach it. The pattern has to be
        // `/dav/**`: fast-glob's `*` stops at `/`, and every real request is
        // at least `/dav/{key}/pub/`.
        let share = Share::with_config(|c| {
            let limit = toml::from_str(
                r#"
                path = "/dav/**"
                method = "PROPFIND"
                quota = "1r/m"
                key = "ip"
                "#,
            )
            .unwrap();
            c.drive.rate_limits.push(limit);
        })
        .await;
        let path = share.dav("/pub/");

        // Nothing exists at the path, so a served request is a 404. What
        // matters is that the second one from the same client is refused,
        // and one from a different client is not.
        propfind(&share.server, &path)
            .await
            .assert_status(StatusCode::NOT_FOUND);
        propfind(&share.server, &path)
            .await
            .assert_status(StatusCode::TOO_MANY_REQUESTS);
        propfind_from(&share.server, &path, "203.0.113.10")
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn anonymous_reads_share_the_rest_routes_bandwidth_limit() {
        // The user guide says bandwidth quotas apply as they do to REST. For
        // an anonymous read that is the per-IP limit; a 3 kB file at 1 kB/s
        // cannot finish in under a second if the limit is really in the path.
        let share = Share::with_config(|c| {
            c.default_quotas.unauthenticated_ip_rate_read = Some("1kb/s".parse().unwrap());
        })
        .await;
        share.put("big.bin", &vec![7u8; 3 * 1024]).await;

        let start = Instant::now();
        let response = share
            .server
            .get(&share.dav("/pub/big.bin"))
            .add_header("x-forwarded-for", CLIENT_IP)
            .await;
        let elapsed = start.elapsed();

        response.assert_status_ok();
        assert_eq!(response.as_bytes().len(), 3 * 1024);
        assert!(
            elapsed > Duration::from_secs(1),
            "3 kB at 1 kB/s finished in {elapsed:?}: the bandwidth limit is not applied to /dav"
        );
    }

    // ── Fixtures ────────────────────────────────────────────────────────

    /// A stand-in client address. Rate and bandwidth limits are keyed by IP
    /// and `TestServer` carries no peer address, so requests say who they are
    /// the way a reverse proxy would.
    const CLIENT_IP: &str = "203.0.113.9";

    /// One signed-up user's drive, seen through the whole client server.
    struct Share {
        server: TestServer,
        cookie: String,
        public_key: String,
    }

    impl Share {
        async fn new() -> Self {
            Self::with_config(|_| {}).await
        }

        /// A share is off unless the config turns it on, so every fixture
        /// does, before `configure` has its say.
        async fn with_config(configure: impl FnOnce(&mut ConfigToml)) -> Self {
            let context = AppContext::test_with_config(|c| {
                c.drive.webdav_enabled = true;
                configure(c);
            })
            .await;
            let router = ClientServer::create_router(context).unwrap();
            let server = TestServer::new(router);
            let user = Keypair::random();
            let cookie = signup_cookie(&server, &user).await;
            Self {
                server,
                cookie,
                public_key: user.public_key().z32(),
            }
        }

        /// `path` on this drive over WebDAV, e.g. `/pub/a.txt`.
        fn dav(&self, path: &str) -> String {
            format!("/dav/{}{path}", self.public_key)
        }

        /// `path` on this drive over REST.
        fn storage(&self, path: &str) -> String {
            format!("/storage/{}{path}", self.public_key)
        }

        /// Write a file into the public folder over REST, the way an app does.
        async fn put(&self, name: &str, body: &[u8]) {
            self.put_at(&format!("/pub/{name}"), body).await;
        }

        /// Write a file at `path` on this drive over REST, as its owner.
        async fn put_at(&self, path: &str, body: &[u8]) {
            self.server
                .put(&self.storage(path))
                .add_header("pubky-host", self.public_key.clone())
                .add_header(header::COOKIE, self.cookie.clone())
                .bytes(body.to_vec().into())
                .expect_success()
                .await;
        }
    }

    fn propfind(server: &TestServer, path: &str) -> TestRequest {
        propfind_from(server, path, CLIENT_IP)
    }

    fn propfind_from(server: &TestServer, path: &str, client_ip: &str) -> TestRequest {
        server
            .method(Method::from_bytes(b"PROPFIND").unwrap(), path)
            .add_header("depth", "1")
            .add_header("x-forwarded-for", client_ip)
    }

    /// The verbs in an `Allow` header, however dav-server spells the list.
    fn allow_set(response: &TestResponse) -> std::collections::BTreeSet<String> {
        verbs(&header_str(response, "allow").split(',').collect::<Vec<_>>())
    }

    fn verbs(list: &[&str]) -> std::collections::BTreeSet<String> {
        list.iter().map(|v| v.trim().to_string()).collect()
    }

    fn header_str(response: &TestResponse, name: &str) -> String {
        response
            .maybe_header(name)
            .unwrap_or_else(|| panic!("{name} header missing"))
            .to_str()
            .unwrap()
            .to_string()
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
