//! Read-only WebDAV access to every user's public folder.
//!
//! Mounted at `/dav/{user_z32}/pub/...`, this serves the same files as
//! `/storage/{user_z32}/pub/...` to standard WebDAV clients (GNOME Files,
//! Finder, rclone, browsers). The endpoint itself — `dav-server`, the verb
//! policy and CORS — is [`DavEndpoint`], shared with the admin server; what
//! this module adds is the policy for *who sees what*.
//!
//! Nothing here is authenticated. `/pub/` is world-readable over REST, and this
//! endpoint exposes exactly that and no more:
//!
//! - The share is [`DavAccess::ReadOnly`]: anything that would write gets
//!   `405`, which is what tells a file manager to mount it read-only.
//! - Only paths under `/pub/` exist. Everything else — the drive root
//!   included — is `404`, so the endpoint never confirms that `/priv/` is there.
//!
//! Storage keys are `{user_z32}/{path}`, so stripping only the `/dav` prefix
//! leaves the tenant segment in place and `/dav/{user_z32}/pub/x` maps straight
//! onto the storage key `{user_z32}/pub/x`. The confinement to `/pub/` is
//! enforced twice: [`DavTarget`] canonicalizes each path within its drive
//! (collapsing `..` before it can escape) and refuses anything outside the
//! public folder, and the per-request endpoint's storage is wrapped in
//! [`TenantScopeLayer`] so a mistake in the first cannot reach a private folder
//! or the storage root.
use axum::{
    body::Body,
    extract::{Request, State},
    http::Method,
    middleware as axum_middleware,
    response::Response,
    routing::any,
    Router,
};
use percent_encoding::percent_decode_str;
use pubky_common::crypto::PublicKey;

use crate::client_server::{middleware::storage_metrics, AppState};
use crate::constants::PUBLIC_ROOT;
use crate::persistence::files::tenant_scope_layer::TenantScopeLayer;
use crate::shared::{
    webdav::{
        endpoint::{DavAccess, DavEndpoint, DAV_PREFIX, DAV_ROOT_ROUTE, DAV_ROUTE},
        StoragePath,
    },
    HttpError, HttpResult,
};

/// The `/dav` routes.
pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route(DAV_ROOT_ROUTE, any(dav_handler))
        .route(DAV_ROUTE, any(dav_handler))
        .layer(axum_middleware::from_fn_with_state(
            state.context.metrics.clone(),
            storage_metrics::record_webdav_request,
        ))
        .with_state(state)
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

    Ok(scoped_endpoint(&state, &target.tenant).handle(req).await)
}

/// The endpoint for one user's public folder.
///
/// Built per request rather than shared, because the confinement is the point:
/// [`TenantScopeLayer`] refuses keys outside `{user_z32}/pub/` at the storage
/// boundary, so a mistake in [`DavTarget::is_public`] cannot reach a private
/// folder or another drive. The cost is a handful of allocations against a
/// network round trip.
fn scoped_endpoint(state: &AppState, tenant: &PublicKey) -> DavEndpoint {
    let operator = state
        .context
        .file_service
        .opendal
        .operator
        .clone()
        .layer(TenantScopeLayer::public(tenant));

    DavEndpoint::new(operator, DavAccess::ReadOnly)
}

/// A parsed `/dav` request path: which drive, and where inside it.
struct DavTarget {
    tenant: PublicKey,
    path: StoragePath,
}

impl DavTarget {
    /// Parse `/dav/{user_z32}/...` into its drive and the path within it.
    ///
    /// The drive segment is taken before the path is canonicalized, so `..`
    /// is judged by where it lands *inside* the drive and can never climb into
    /// another one: a path that tries is malformed, not a different drive.
    fn parse(uri_path: &str) -> Result<Self, HttpError> {
        let decoded = percent_decode_str(uri_path)
            .decode_utf8()
            .map_err(|_| HttpError::bad_request("WebDAV path is not valid UTF-8"))?;

        let (tenant, path) = decoded
            .strip_prefix(DAV_PREFIX)
            .and_then(|rest| rest.strip_prefix('/'))
            .map(|rest| rest.split_once('/').unwrap_or((rest, "")))
            .filter(|(tenant, _)| !tenant.is_empty())
            .ok_or_else(|| HttpError::bad_request("WebDAV paths are `/dav/{user}/...`"))?;

        let tenant = PublicKey::try_from_z32(tenant)
            .map_err(|e| HttpError::bad_request(format!("Invalid user in WebDAV path: {e}")))?;
        let path = StoragePath::normalize(&format!("/{path}"))
            .map_err(|e| HttpError::bad_request(format!("Invalid WebDAV path: {e}")))?;

        Ok(Self { tenant, path })
    }

    /// Whether this names the public folder or something inside it.
    ///
    /// The folder itself counts with or without its trailing slash, since
    /// clients spell the thing they mount both ways.
    fn is_public(&self) -> bool {
        let path = self.path.as_str();
        path.starts_with(PUBLIC_ROOT) || path == PUBLIC_ROOT.trim_end_matches('/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, response::IntoResponse};
    use pubky_common::crypto::Keypair;

    fn status(result: Result<DavTarget, HttpError>) -> StatusCode {
        result
            .err()
            .expect("expected a rejection")
            .into_response()
            .status()
    }

    fn is_public(path: &str) -> bool {
        DavTarget::parse(path)
            .unwrap_or_else(|e| panic!("{path} should parse: {e:?}"))
            .is_public()
    }

    #[test]
    fn the_public_folder_and_everything_in_it_is_served() {
        let z32 = Keypair::random().public_key().z32();

        for path in [
            format!("/dav/{z32}/pub/"),
            format!("/dav/{z32}/pub"),
            format!("/dav/{z32}/pub/notes/a.txt"),
            format!("/dav/{z32}/pub/deep/nested/dir/"),
        ] {
            assert!(is_public(&path), "{path} should be served");
        }
    }

    #[test]
    fn nothing_outside_the_public_folder_exists() {
        let z32 = Keypair::random().public_key().z32();

        for path in [
            // The drive root would list `/priv/` alongside `/pub/`.
            format!("/dav/{z32}"),
            format!("/dav/{z32}/"),
            format!("/dav/{z32}/priv/"),
            format!("/dav/{z32}/priv/secret.txt"),
            format!("/dav/{z32}/.DS_Store"),
            // A traversal that climbs out of the public folder lands outside it.
            format!("/dav/{z32}/pub/../priv/secret.txt"),
            format!("/dav/{z32}/pub/%2e%2e/priv/secret.txt"),
            // A name that merely starts with `pub` is not the public folder.
            format!("/dav/{z32}/public/x"),
            format!("/dav/{z32}/pubx"),
        ] {
            assert!(!is_public(&path), "{path} should not exist");
        }
    }

    #[test]
    fn a_path_that_climbs_out_of_its_drive_is_malformed() {
        // The drive is fixed before the path is canonicalized, so `..` can
        // never reach another drive or the storage root — it is simply a
        // traversal above the root of this one.
        let z32 = Keypair::random().public_key().z32();
        let other = Keypair::random().public_key().z32();

        for path in [
            format!("/dav/{z32}/../{other}/pub/file.txt"),
            format!("/dav/{z32}/../../etc/passwd"),
            format!("/dav/{z32}/pub/%2e%2e/%2e%2e/{other}/pub/x"),
        ] {
            assert_eq!(
                status(DavTarget::parse(&path)),
                StatusCode::BAD_REQUEST,
                "{path} should be rejected"
            );
        }
    }

    #[test]
    fn paths_that_do_not_name_a_drive_are_rejected() {
        for path in [
            "/storage/whatever",
            "/dav",
            "/dav/",
            "/davos/x",
            "/dav/not-a-pubkey/pub/",
        ] {
            assert_eq!(
                status(DavTarget::parse(path)),
                StatusCode::BAD_REQUEST,
                "{path} should not parse"
            );
        }
    }

    // ── Through the assembled router ────────────────────────────────────
    //
    // The unit tests above pin the path policy; these drive the whole client
    // server the way a file manager would, so CORS, rate limits and metrics
    // are exercised together with it.

    use std::sync::Arc;

    use axum::http::header;
    use axum_test::TestServer;
    use pubky_common::{auth::AuthToken, capabilities::Capability};

    use crate::{app_context::AppContext, client_server::ClientServer};

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn webdav_serves_public_folders_anonymously_and_nothing_else() {
        let context = AppContext::test().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router);
        let user = Keypair::random();
        let cookie = signup_cookie(&server, &user).await;
        let public_key = user.public_key().z32();

        put_public_file(&server, &user, &cookie, "dav.txt", b"hello").await;

        // No credentials: the file is served exactly as `/storage` serves it.
        server
            .get(&format!("/dav/{public_key}/pub/dav.txt"))
            .await
            .assert_text("hello");

        // Mounting starts with a PROPFIND of the folder.
        propfind(&server, &format!("/dav/{public_key}/pub/"))
            .await
            .assert_status(StatusCode::MULTI_STATUS);

        // The drive root and the private folder do not exist here, even to the
        // owner: 404 rather than 401 or 403, so nothing is confirmed.
        for path in [
            format!("/dav/{public_key}/"),
            format!("/dav/{public_key}/priv/"),
            format!("/dav/{public_key}/pub/../priv/secret.txt"),
        ] {
            propfind(&server, &path)
                .add_header("pubky-host", public_key.clone())
                .add_header(header::COOKIE, cookie.clone())
                .await
                .assert_status(StatusCode::NOT_FOUND);
        }

        // A bare OPTIONS is what a file manager reads before mounting: no
        // locking class, and an `Allow` with no write verb in it, on the
        // folder and on a file alike.
        for path in [
            format!("/dav/{public_key}/pub/"),
            format!("/dav/{public_key}/pub/dav.txt"),
        ] {
            let response = server.method(Method::OPTIONS, &path).await;
            response.assert_status_ok();
            response.assert_header("dav", "1");
            let allow = allow_header(&response);
            assert!(allow.contains("PROPFIND"), "{path}: {allow}");
            assert_no_write_verbs(&allow, &path);
        }

        // A write is refused before dav-server sees it — dav-server's own 405
        // carries no `Allow`, and a file manager needs one.
        let response = server
            .put(&format!("/dav/{public_key}/pub/dav.txt"))
            .add_header("pubky-host", public_key.clone())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(b"overwritten".to_vec().into())
            .await;
        response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
        response.assert_header(header::ALLOW, "OPTIONS, GET, HEAD, PROPFIND");

        // A verb dav-server has never heard of fails closed too, just with a
        // different status: it is refused before any method set applies.
        server
            .method(
                Method::from_bytes(b"FROBNICATE").unwrap(),
                &format!("/dav/{public_key}/pub/dav.txt"),
            )
            .await
            .assert_status(StatusCode::NOT_IMPLEMENTED);
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
        //
        // dav-server claims `1,2,3` whatever is attached, so the endpoint
        // rewrites it: class 2 would tell Finder the share takes locks.
        let response = server
            .method(Method::OPTIONS, &format!("/dav/{public_key}/pub/"))
            .await;
        response.assert_status_ok();
        response.assert_header("dav", "1");
        // Nothing exists yet, and dav-server's answer for an unmapped path
        // would offer MKCOL, PUT and LOCK unless told the share is read-only.
        assert_no_write_verbs(&allow_header(&response), "an unmapped path");

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
            // A listing, a resumed download and a conditional fetch each need
            // a header the browser must ask permission for.
            .add_header(
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "depth, range, if-none-match",
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
        for method in ["PROPFIND", "GET", "HEAD"] {
            assert!(allowed.contains(method), "{method} missing from {allowed}");
        }
        for method in ["PUT", "DELETE", "MKCOL", "MOVE", "LOCK"] {
            assert!(
                !allowed.contains(method),
                "{method} offered on a read-only share"
            );
        }

        let headers = response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .and_then(|v| v.to_str().ok())
            .expect("preflight must list allowed headers")
            .to_string();
        for name in ["depth", "range", "if-none-match"] {
            assert!(headers.contains(name), "{name} missing from {headers}");
        }

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

        let response = propfind(&server, &format!("/dav/{public_key}/pub/"))
            .add_header(header::ORIGIN, "https://webdav.example")
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
    async fn webdav_propfind_depth_is_finite_by_default() {
        // dav-server refuses `Depth: infinity` outright, and serves a request
        // with no `Depth` as a one-level listing. Both are what the user guide
        // promises.
        let context = AppContext::test().await;
        let server = TestServer::new(ClientServer::create_router(Arc::clone(&context)).unwrap());
        let user = Keypair::random();
        let cookie = signup_cookie(&server, &user).await;
        let public_key = user.public_key().z32();
        put_public_file(&server, &user, &cookie, "depth.txt", b"x").await;
        let folder = format!("/dav/{public_key}/pub/");
        let request = || {
            server
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
    async fn webdav_guesses_the_content_type_from_the_name() {
        // REST serves the type a file was stored with; dav-server serves what
        // the extension suggests. A file with no extension is octet-stream
        // over WebDAV whatever it holds — a documented limitation.
        let context = AppContext::test().await;
        let server = TestServer::new(ClientServer::create_router(Arc::clone(&context)).unwrap());
        let user = Keypair::random();
        let cookie = signup_cookie(&server, &user).await;
        let public_key = user.public_key().z32();
        for name in ["picture", "picture.png"] {
            server
                .put(&format!("/storage/{public_key}/pub/{name}"))
                .add_header("pubky-host", public_key.clone())
                .add_header(header::COOKIE, cookie.clone())
                .content_type("image/png")
                .bytes(b"\x89PNG".to_vec().into())
                .expect_success()
                .await;
        }

        server
            .get(&format!("/storage/{public_key}/pub/picture"))
            .await
            .assert_header(header::CONTENT_TYPE, "image/png");
        server
            .get(&format!("/dav/{public_key}/pub/picture"))
            .await
            .assert_header(header::CONTENT_TYPE, "application/octet-stream");
        server
            .get(&format!("/dav/{public_key}/pub/picture.png"))
            .await
            .assert_header(header::CONTENT_TYPE, "image/png");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn webdav_propfind_is_rate_limited_per_client() {
        // The shipped limit, tightened to one request so the test can reach
        // it. Until the pattern was `/dav/**` it matched nothing at all:
        // fast-glob's `*` stops at `/`, and every real request is at least
        // `/dav/{key}/pub/`.
        let context = AppContext::test_with_config(|c| {
            let limit = c
                .drive
                .rate_limits
                .iter_mut()
                .find(|l| l.path.0 == "/dav/**")
                .expect("the shipped PROPFIND limit is in the test config");
            limit.quota = "1r/m".parse().unwrap();
        })
        .await;
        let server = TestServer::new(ClientServer::create_router(Arc::clone(&context)).unwrap());
        let public_key = Keypair::random().public_key().z32();
        let path = format!("/dav/{public_key}/pub/");

        // Nothing exists at the path, so a served request is a 404. What
        // matters is that the second one from the same client is refused,
        // and one from a different client is not.
        propfind(&server, &path)
            .await
            .assert_status(StatusCode::NOT_FOUND);
        propfind(&server, &path)
            .await
            .assert_status(StatusCode::TOO_MANY_REQUESTS);
        propfind_from(&server, &path, "203.0.113.10")
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    /// A stand-in client address. The shipped PROPFIND limit is keyed by IP
    /// and `TestServer` carries no peer address, so requests say who they are
    /// the way a reverse proxy would.
    const CLIENT_IP: &str = "203.0.113.9";

    fn propfind(server: &TestServer, path: &str) -> axum_test::TestRequest {
        propfind_from(server, path, CLIENT_IP)
    }

    fn propfind_from(server: &TestServer, path: &str, client_ip: &str) -> axum_test::TestRequest {
        server
            .method(Method::from_bytes(b"PROPFIND").unwrap(), path)
            .add_header("depth", "1")
            .add_header("x-forwarded-for", client_ip)
    }

    fn allow_header(response: &axum_test::TestResponse) -> String {
        response
            .headers()
            .get(header::ALLOW)
            .and_then(|v| v.to_str().ok())
            .expect("OPTIONS must carry Allow")
            .to_string()
    }

    fn assert_no_write_verbs(allow: &str, what: &str) {
        for verb in [
            "PUT",
            "DELETE",
            "MKCOL",
            "COPY",
            "MOVE",
            "LOCK",
            "UNLOCK",
            "PROPPATCH",
        ] {
            assert!(
                !allow.contains(verb),
                "{what} offers {verb}: Allow: {allow}"
            );
        }
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
