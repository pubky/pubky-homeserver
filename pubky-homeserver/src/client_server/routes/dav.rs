//! Read-only WebDAV access to every user's public folder.
//!
//! Mounted at `/dav/{user_z32}/pub/...`, this serves the same files as
//! `/storage/{user_z32}/pub/...` to standard WebDAV clients (GNOME Files,
//! Finder, rclone, browsers). It is off unless `[drive] webdav` is
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
//! `/dav/{user_z32}/...` is addressed like `/storage/{user_z32}/...`, and
//! [`RequestTenant::resolve_dav`](crate::client_server::middleware::request_tenant::RequestTenant::resolve_dav)
//! resolves both the same way before any other middleware runs. Rate limits
//! and logs therefore see the storage path a request reads, so a limit on
//! `/pub/a.txt` covers the file on either route.
//!
//! The confinement to `/pub/` is enforced twice: the handler refuses any
//! resolved path outside the public folder, and the operator the endpoint is
//! built on is scoped to that folder at the storage boundary, so a mistake in
//! the first cannot reach a private folder or the storage root.
use axum::{
    body::Body,
    extract::{Request, State},
    http::Method,
    response::Response,
    Router,
};

use crate::client_server::AppState;
use crate::constants::PUBLIC_ROOT;
use crate::shared::{
    webdav::{
        endpoint::{self as dav_endpoint, DavAccess, DavEndpoint},
        EntryPath,
    },
    HttpError, HttpResult,
};

/// What the share lets its callers do.
pub(crate) const ACCESS: DavAccess = DavAccess::ReadOnly;

/// The `/dav` routes.
pub(crate) fn router(state: AppState) -> Router {
    dav_endpoint::router(dav_handler).with_state(state)
}

async fn dav_handler(
    State(state): State<AppState>,
    target: EntryPath,
    req: Request<Body>,
) -> HttpResult<Response> {
    // `OPTIONS` is a capability probe that touches nothing, so it is answered
    // anywhere a drive is named: a client may well send it above the folder it
    // is about to mount.
    let is_public = target.path().as_str().starts_with(PUBLIC_ROOT);
    if req.method() != Method::OPTIONS && !is_public {
        // Not 403: a refusal would confirm there is something there to refuse.
        return Err(HttpError::not_found());
    }

    // Built per request rather than shared, because the confinement is the
    // point: the operator is scoped to this drive's public folder.
    let operator = state
        .context
        .file_service
        .opendal
        .public_folder_operator(target.pubkey());
    Ok(DavEndpoint::new(operator, ACCESS).handle(req).await)
}

#[cfg(test)]
mod tests {
    //! These drive the whole client server the way a file manager would, so
    //! the path policy in this module is exercised together with the CORS,
    //! rate limits and bandwidth limits it is merged beside. How a URL names
    //! a drive is pinned in `request_tenant.rs`; the endpoint's own
    //! behaviour in `endpoint.rs`.
    use std::time::{Duration, Instant};

    use axum::http::{header, StatusCode};
    use axum_test::{TestRequest, TestServer};
    use pubky_common::{capabilities::Capability, crypto::Keypair};

    use super::*;
    use crate::client_server::client_identity::with_http_header_identity;
    use crate::client_server::test_utils::signup_cookie;
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
        // of `webdav` serves: `/dav` is a path like any other the
        // server has no route for, while REST carries on.
        let share = Share::with_config(|c| {
            c.drive.webdav = ConfigToml::default().drive.webdav;
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
    async fn the_share_is_served_from_an_operator_confined_to_the_public_folder() {
        // Every request above is stopped by the handler's path check before
        // storage is reached. This pins the second line on its own: the
        // operator the handler serves from cannot reach outside the folder
        // even when asked to directly.
        let context = AppContext::test().await;
        let owner = Keypair::random().public_key();
        let operator = context.file_service.opendal.public_folder_operator(&owner);
        let z32 = owner.z32();

        for path in [format!("{z32}/priv/secret.txt"), format!("{z32}/")] {
            let error = operator.stat(&path).await.unwrap_err();
            assert_eq!(error.kind(), opendal::ErrorKind::PermissionDenied, "{path}");
        }
        let error = operator
            .stat(&format!("{z32}/pub/a.txt"))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), opendal::ErrorKind::NotFound);
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
        let reference = (reference.header("dav"), reference.header("allow"));

        for path in ["/", "/priv/", "/priv/secret.txt", "/priv/nothing-here"] {
            let response = share.server.method(Method::OPTIONS, &share.dav(path)).await;
            response.assert_status_ok();
            assert_eq!(
                (response.header("dav"), response.header("allow")),
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
        response.assert_header("allow", "OPTIONS");

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
    async fn propfind_depth_is_finite_by_default() {
        // dav-server refuses `Depth: infinity` outright, and serves a request
        // with no `Depth` as a one-level listing, so no single PROPFIND walks
        // a whole tree.
        let share = Share::new().await;
        share.put("depth.txt", b"x").await;
        let folder = share.dav("/pub/");
        let request = || {
            share
                .server
                .method(Method::from_bytes(b"PROPFIND").unwrap(), &folder)
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
        // over WebDAV whatever it holds — a known limitation.
        let share = Share::new().await;
        for name in ["picture", "picture.png"] {
            share
                .server
                .put(&share.storage(&format!("/pub/{name}")))
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
        // No limit on `PROPFIND` ships; this is the one an operator would
        // add, at one request so the test can reach it. The pattern is the
        // storage path, as for REST: `/dav/{key}` is not part of it.
        let share = Share::with_config(|c| {
            let limit = toml::from_str(
                r#"
                path = "/pub/**"
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
        // The folder named without its slash is the same folder, not a way
        // around the limit.
        for path in [path.as_str(), path.trim_end_matches('/')] {
            propfind(&share.server, path)
                .await
                .assert_status(StatusCode::TOO_MANY_REQUESTS);
        }
        propfind_from(&share.server, &path, "203.0.113.10")
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_read_limit_on_a_storage_path_covers_the_same_file_over_dav() {
        // One budget for the file, whichever route reads it and however the
        // URL spells it. Otherwise `/dav` would be a way around every limit
        // an operator wrote for `/storage`.
        let share = Share::with_config(|c| {
            let limit = toml::from_str(
                r#"
                path = "/pub/limited.txt"
                method = "GET"
                quota = "2r/m"
                key = "ip"
                "#,
            )
            .unwrap();
            c.drive.rate_limits.push(limit);
        })
        .await;
        share.put("limited.txt", b"x").await;
        share.put("other.txt", b"x").await;

        share
            .server
            .get(&share.storage("/pub/limited.txt"))
            .await
            .assert_status_ok();
        share
            .server
            .get(&share.dav("/pub/limited.txt"))
            .await
            .assert_status_ok();
        for path in ["/pub/limited.txt", "/%70ub/./limited%2etxt"] {
            share
                .server
                .get(&share.dav(path))
                .await
                .assert_status(StatusCode::TOO_MANY_REQUESTS);
        }
        share
            .server
            .get(&share.dav("/pub/other.txt"))
            .await
            .assert_status_ok();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_limit_keyed_by_user_counts_against_the_drive_read() {
        // The user of an anonymous read is the drive's owner, as it is for
        // an anonymous REST read. Without a resolved drive this limit could
        // not be keyed at all and every request would be a 400.
        let share = Share::with_config(|c| {
            let limit = toml::from_str(
                r#"
                path = "/pub/**"
                method = "GET"
                quota = "1r/m"
                key = "user"
                "#,
            )
            .unwrap();
            c.drive.rate_limits.push(limit);
        })
        .await;
        share.put("a.txt", b"x").await;

        share
            .server
            .get(&share.dav("/pub/a.txt"))
            .await
            .assert_status_ok();
        share
            .server
            .get(&share.dav("/pub/a.txt"))
            .await
            .assert_status(StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn anonymous_reads_share_the_rest_routes_bandwidth_limit() {
        // The bandwidth quotas configured for REST apply here too. For an
        // anonymous read that is the per-IP limit; a 3 kB file at 1 kB/s
        // cannot finish in under a second if the limit is really in the path.
        let share = Share::with_config(|c| {
            c.default_quotas.unauthenticated_ip_rate_read = Some("1kb/s".parse().unwrap());
        })
        .await;
        share.put("big.bin", &vec![7u8; 3 * 1024]).await;

        let start = Instant::now();
        let response = share.server.get(&share.dav("/pub/big.bin")).await;
        let elapsed = start.elapsed();

        response.assert_status_ok();
        assert_eq!(response.as_bytes().len(), 3 * 1024);
        assert!(
            elapsed > Duration::from_secs(1),
            "3 kB at 1 kB/s finished in {elapsed:?}: the bandwidth limit is not applied to /dav"
        );
    }

    // ── Fixtures ────────────────────────────────────────────────────────

    /// The header the fixture reads the client address from. Rate and
    /// bandwidth limits are keyed by IP and `TestServer` carries no peer
    /// address, so requests say who they are the way a reverse proxy would.
    const CLIENT_IP_HEADER: &str = "x-real-ip";

    /// The address every request carries unless it names another.
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
                c.drive.webdav = true;
                configure(c);
            })
            .await;
            let router = ClientServer::create_router(context).unwrap();
            let router = with_http_header_identity(router, CLIENT_IP_HEADER).unwrap();
            let mut server = TestServer::new(router);
            server.add_header(CLIENT_IP_HEADER, CLIENT_IP);
            let user = Keypair::random();
            let cookie = signup_cookie(&server, &user, vec![Capability::root()]).await;
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
            // Replace the server's default address rather than add a second.
            .clear_headers()
            .add_header("depth", "1")
            .add_header(CLIENT_IP_HEADER, client_ip)
    }
}
