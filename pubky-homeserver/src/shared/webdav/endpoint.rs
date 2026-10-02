//! One WebDAV endpoint, shared by the admin and client servers.
//!
//! Both servers put `dav-server` in front of an OpenDAL operator at `/dav`.
//! What differs between them is policy — who may call, over which slice of
//! storage, and whether writes are allowed — and that stays at the call site:
//! each server authenticates its own way, scopes an operator to what the
//! caller may see, and hands it here as a [`DavEndpoint`]. Everything the two
//! endpoints must agree on lives in this module, so they cannot drift: how the
//! handler is built, which verbs a share answers, and how `OPTIONS` is told
//! apart from a CORS preflight.
//!
//! | | admin | client |
//! |---|---|---|
//! | auth | Basic `admin:<password>`, in its handler | none |
//! | operator | `admin_operator`, every drive | app operator scoped to `{key}/pub/` |
//! | access | `ReadWrite`, `FakeLs` | `ReadOnly` |
//!
//! The client endpoint is off unless `[drive] webdav_enabled` is set. The admin
//! one has no switch of its own: it comes and goes with the whole admin server.
//!
//! # Why `dav-server` over the stock `OpendalFs`
//!
//! The alternative was a custom `DavFileSystem` over `FileService`. Writes were
//! exercised under `OpendalFs` first, and every problem found belonged in the
//! OpenDAL layer stack rather than in the filesystem behind `dav-server`:
//! `COPY`/`MOVE` bypassing the database was `WriteFinalizationLayer`'s to fix,
//! and fixing it there covered the admin operator too; directory `DELETE`
//! recurses file by file through the finalization deleter, so nothing is
//! orphaned; and lock keep-alive through a long upload has no token to work
//! with in either design. What `OpendalFs` genuinely cannot express is small —
//! `get_quota` for free-space display, a quota refusal as `507` rather than
//! `500`, an ETag when the backend reports none, a cap on directory listings —
//! and all of it fits a thin `DavFileSystem` wrapper that delegates everything
//! else. That wrapper is the escape hatch if more control is ever needed; a
//! rewrite of the filesystem methods and a streaming `DavFile` is not warranted.
use axum::{
    body::Body,
    extract::{Request, State},
    handler::Handler,
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self as axum_middleware, Next},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use dav_server::{fakels::FakeLs, DavHandler, DavMethodSet};
use dav_server_opendalfs::OpendalFs;
use opendal::Operator;

/// URL prefix stripped before a path is resolved against storage.
pub(crate) const DAV_PREFIX: &str = "/dav";

/// The axum routes for a `/dav` endpoint: the root, and everything beneath
/// it. Two because a catch-all must match at least one character, and `/dav/`
/// itself is the storage root an operator lists.
const DAV_ROOT_ROUTE: &str = "/dav/";
const DAV_ROUTE: &str = "/dav/{*path}";

/// The header a client reads to learn what the share supports.
const DAV_COMPLIANCE_HEADER: &str = "dav";

/// What a read-only share reports in `DAV:` — compliance class 1, no locking.
///
/// dav-server claims `1,2,3` unconditionally, whether or not a lock system is
/// attached, so the header is rewritten. Class 2 would tell Finder the share
/// takes locks, and it would then try to mount writable.
const READ_ONLY_DAV_CLASSES: &str = "1";

/// What a folder on a read-only share answers to: it can be probed and
/// listed, but there is no index page to `GET`.
const READ_ONLY_COLLECTION_ALLOW: &str = "OPTIONS, PROPFIND";

/// How long a browser may cache a preflight result.
const PREFLIGHT_MAX_AGE: &str = "600";

/// Response headers a browser client has to be able to read. Without `dav`
/// here a client cannot detect compliance; without `lock-token` it cannot
/// unlock; without `content-range` it cannot resume a download.
const EXPOSE_HEADERS: &str = "dav, allow, etag, last-modified, content-length, content-type, \
                              content-range, accept-ranges, lock-token, ms-author-via";

/// What a share lets its callers do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DavAccess {
    /// `GET`, `HEAD`, `OPTIONS` and `PROPFIND`. Any other WebDAV verb is
    /// `405`; a verb dav-server does not know at all is `501`.
    ///
    /// The share reports `DAV: 1`, and a bare `OPTIONS` lists only those
    /// verbs in `Allow`. Between them, that is what tells a file manager to
    /// mount it read-only rather than report it broken.
    ///
    /// Folders have no directory index: a `GET` on one is `405`. Listing is
    /// `PROPFIND`'s job, so that is the one verb an operator has to rate
    /// limit. An index page would do the same work through another.
    ReadOnly,
    /// Every WebDAV verb, with the `LOCK` handshake macOS needs before it will
    /// mount writable. The locks are [`FakeLs`]: well-formed tokens that lock
    /// nothing.
    ReadWrite,
}

impl DavAccess {
    /// The verbs served, as dav-server and the `Allow` header both name them.
    /// One list, so what is refused and what is advertised cannot disagree.
    fn methods(self) -> &'static [&'static str] {
        match self {
            Self::ReadOnly => &["OPTIONS", "GET", "HEAD", "PROPFIND"],
            Self::ReadWrite => &[
                "OPTIONS",
                "GET",
                "HEAD",
                "PROPFIND",
                "PROPPATCH",
                "PUT",
                "PATCH",
                "DELETE",
                "MKCOL",
                "COPY",
                "MOVE",
                "LOCK",
                "UNLOCK",
            ],
        }
    }

    /// Whether the share serves `method` at all.
    fn allows(self, method: &Method) -> bool {
        self.methods().contains(&method.as_str())
    }

    fn method_set(self) -> DavMethodSet {
        DavMethodSet::from_vec(self.methods().to_vec())
            .expect("every verb listed is one dav-server knows")
    }

    fn allow_header(self) -> HeaderValue {
        HeaderValue::from_str(&self.methods().join(", "))
            .expect("verb names are valid header characters")
    }
}

/// Mount `handler` at `/dav/` and everything beneath it, with the endpoint's
/// own CORS.
///
/// A server merges this *beside* its other routes, not under its blanket
/// `CorsLayer`: that layer answers every `OPTIONS` itself, which strips the
/// `DAV:` header a file manager reads before it will mount anything. The CORS
/// here answers only real preflights and lets a bare `OPTIONS` through to
/// dav-server.
pub(crate) fn router<H, T, S>(access: DavAccess, handler: H) -> Router<S>
where
    H: Handler<T, S>,
    T: 'static,
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(DAV_ROOT_ROUTE, any(handler.clone()))
        .route(DAV_ROUTE, any(handler))
        .layer(axum_middleware::from_fn_with_state(access, cors))
}

/// `dav-server` over an operator that has already been scoped to what the
/// caller may see.
#[derive(Clone)]
pub(crate) struct DavEndpoint {
    handler: DavHandler,
    access: DavAccess,
}

impl DavEndpoint {
    /// Only [`DAV_PREFIX`] is stripped from the URL, so whatever follows it
    /// is resolved as an object key on `operator` unchanged. A caller that
    /// wants to confine the share does so by scoping the operator.
    pub(crate) fn new(operator: Operator, access: DavAccess) -> Self {
        let builder = DavHandler::builder()
            .filesystem(OpendalFs::new(operator))
            .strip_prefix(DAV_PREFIX)
            // Refuses anything else with 405, and keeps a bare OPTIONS from
            // offering MKCOL, PUT and LOCK on an unmapped path.
            .methods(access.method_set());
        let builder = match access {
            // No index page on the anonymous share: it lists a folder exactly
            // as PROPFIND does, one stat per entry, but through a verb a
            // PROPFIND rate limit never sees.
            DavAccess::ReadOnly => builder.autoindex(false),
            DavAccess::ReadWrite => builder.autoindex(true).locksystem(FakeLs::new()),
        };
        Self {
            handler: builder.build_handler(),
            access,
        }
    }

    /// Serve `req`, then correct two headers dav-server gets wrong.
    ///
    /// Its 405 carries no `Allow`, which RFC 7231 requires and a file manager
    /// reads to decide the share is read-only rather than broken. And its
    /// `DAV:` claims locking whether or not a lock system is attached.
    pub(crate) async fn handle(&self, req: Request<Body>) -> Response {
        let method = req.method().clone();
        let mut response = self.handler.handle(req).await.into_response();

        if response.status() == StatusCode::METHOD_NOT_ALLOWED {
            if !self.access.allows(&method) {
                // The share refused the verb: say what it does take.
                response
                    .headers_mut()
                    .insert(header::ALLOW, self.access.allow_header());
            } else if self.access == DavAccess::ReadOnly {
                // The share takes the verb but this resource does not. On a
                // read-only share that is a GET or HEAD of a folder, which
                // has no index page to serve.
                response.headers_mut().insert(
                    header::ALLOW,
                    HeaderValue::from_static(READ_ONLY_COLLECTION_ALLOW),
                );
            }
        }
        if self.access == DavAccess::ReadOnly
            && response.headers().contains_key(DAV_COMPLIANCE_HEADER)
        {
            response.headers_mut().insert(
                DAV_COMPLIANCE_HEADER,
                HeaderValue::from_static(READ_ONLY_DAV_CLASSES),
            );
        }
        response
    }
}

/// Cross-origin support for a `/dav` route, hand-rolled because the two kinds
/// of `OPTIONS` request must be told apart.
///
/// `tower_http::cors::CorsLayer` answers *every* `OPTIONS` itself. That
/// breaks native clients: a bare `OPTIONS` is a WebDAV capability probe, and
/// only `dav-server` can answer it with the `DAV:` header that Finder and
/// GNOME Files read before they will mount a share. So only a real preflight —
/// one carrying `Access-Control-Request-Method` — is short-circuited here; a
/// bare `OPTIONS` falls through to the handler.
///
/// The origin is `*` and credentials are never allowed, so a browser will not
/// attach the server's `SameSite=None` session cookie. A browser client
/// authenticates the way every other client does, with an `Authorization`
/// header it already holds.
///
/// Whatever request headers the browser asks for are allowed. Enumerating
/// them is a losing game — `Range`, `If-None-Match` and `If-Modified-Since`
/// all need naming or a ranged or conditional `GET` fails its preflight —
/// and there is nothing to protect by refusing: with no credentials in play,
/// any header a browser could send, `curl` already can.
async fn cors(State(access): State<DavAccess>, req: Request<Body>, next: Next) -> Response {
    if req.method() == Method::OPTIONS
        && req
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
    {
        let requested = req.headers().get(header::ACCESS_CONTROL_REQUEST_HEADERS);
        return preflight(access, requested);
    }

    let cross_origin = req.headers().contains_key(header::ORIGIN);
    let mut response = next.run(req).await;

    if cross_origin {
        let headers = response.headers_mut();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static(EXPOSE_HEADERS),
        );
    }

    response
}

/// The preflight answer. No `Allow-Credentials`, so cookies stay unusable.
/// The headers the browser asked for are mirrored back, when it asked.
fn preflight(access: DavAccess, requested_headers: Option<&HeaderValue>) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, access.allow_header());
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static(PREFLIGHT_MAX_AGE),
    );
    if let Some(requested) = requested_headers {
        headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, requested.clone());
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use tempfile::TempDir;

    #[test]
    fn a_read_only_share_advertises_only_read_verbs() {
        let allow = DavAccess::ReadOnly.allow_header();
        assert_eq!(allow.to_str().unwrap(), "OPTIONS, GET, HEAD, PROPFIND");
    }

    #[test]
    fn a_read_write_share_advertises_the_locking_verbs() {
        let allow = DavAccess::ReadWrite.allow_header();
        let allow = allow.to_str().unwrap();
        for verb in ["PUT", "LOCK", "UNLOCK", "MOVE"] {
            assert!(allow.contains(verb), "{verb} missing from {allow}");
        }
    }

    #[test]
    fn every_listed_verb_is_one_dav_server_knows() {
        // `method_set` panics on a name dav-server does not recognise, which
        // would otherwise only surface when a server starts.
        DavAccess::ReadOnly.method_set();
        DavAccess::ReadWrite.method_set();
    }

    // ── Through the router ──────────────────────────────────────────────
    //
    // The admin and client servers each wrap this endpoint in their own
    // policy. These tests pin what the endpoint does on its own, with a
    // handler that adds nothing, so a regression in shared behaviour fails
    // here rather than in one server's tests.

    /// The smallest possible caller: no auth, no scoping, straight through.
    async fn serve(State(endpoint): State<DavEndpoint>, req: Request<Body>) -> Response {
        endpoint.handle(req).await
    }

    /// A share over a fresh filesystem operator holding `pub/a.txt`.
    async fn share(access: DavAccess) -> (TestServer, TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let backend = opendal::services::Fs::default().root(dir.path().to_str().unwrap());
        let operator = Operator::new(backend).unwrap().finish();
        operator.write("pub/a.txt", "hello").await.unwrap();
        let app = router(access, serve).with_state(DavEndpoint::new(operator, access));
        (TestServer::new(app), dir)
    }

    /// The verbs in an `Allow` header, however dav-server spells the list.
    fn allow_set(response: &axum_test::TestResponse) -> std::collections::BTreeSet<String> {
        verbs(&header_str(response, "allow").split(',').collect::<Vec<_>>())
    }

    fn verbs(list: &[&str]) -> std::collections::BTreeSet<String> {
        list.iter().map(|v| v.trim().to_string()).collect()
    }

    fn header_str(response: &axum_test::TestResponse, name: &str) -> String {
        response
            .maybe_header(name)
            .unwrap_or_else(|| panic!("{name} header missing"))
            .to_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn a_bare_options_on_a_read_only_share_reports_class_one_and_read_verbs() {
        let (server, _dir) = share(DavAccess::ReadOnly).await;

        // dav-server tailors `Allow` to the resource; the method set keeps
        // every write verb out of it, and the endpoint rewrites `DAV:` from
        // the `1,2,3,…` dav-server claims regardless.
        for (path, expected) in [
            ("/dav/pub/", &["OPTIONS", "PROPFIND"][..]),
            (
                "/dav/pub/a.txt",
                &["OPTIONS", "GET", "HEAD", "PROPFIND"][..],
            ),
            ("/dav/pub/missing", &["OPTIONS"][..]),
        ] {
            let response = server.method(Method::OPTIONS, path).await;
            response.assert_status_ok();
            response.assert_header("dav", "1");
            assert_eq!(allow_set(&response), verbs(expected), "{path}");
            // A bare OPTIONS is not a preflight: no CORS answer, no CORS headers.
            assert!(response
                .maybe_header(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none());
        }
    }

    #[tokio::test]
    async fn a_bare_options_on_a_read_write_share_keeps_locking() {
        let (server, _dir) = share(DavAccess::ReadWrite).await;

        let response = server.method(Method::OPTIONS, "/dav/pub/").await;

        response.assert_status_ok();
        let dav = header_str(&response, "dav");
        assert!(
            dav.starts_with("1,2"),
            "read-write share must offer locks: {dav}"
        );
        let allow = allow_set(&response);
        for verb in ["COPY", "LOCK", "UNLOCK"] {
            assert!(allow.contains(verb), "{verb} missing from {allow:?}");
        }
    }

    #[tokio::test]
    async fn a_preflight_is_answered_before_dav_server_sees_it() {
        let (server, _dir) = share(DavAccess::ReadOnly).await;

        let response = server
            .method(Method::OPTIONS, "/dav/pub/")
            .add_header(header::ORIGIN, "https://webdav.example")
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "PROPFIND")
            .add_header(header::ACCESS_CONTROL_REQUEST_HEADERS, "depth, range")
            .await;

        response.assert_status(StatusCode::NO_CONTENT);
        response.assert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        response.assert_header(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            "OPTIONS, GET, HEAD, PROPFIND",
        );
        response.assert_header(header::ACCESS_CONTROL_ALLOW_HEADERS, "depth, range");
        response.assert_header(header::ACCESS_CONTROL_MAX_AGE, PREFLIGHT_MAX_AGE);
        // Never credentials: `*` plus credentials is refused by browsers, and
        // the anonymous share must not invite the session cookie anyway.
        assert!(response
            .maybe_header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none());
        // dav-server did not run.
        assert!(response.maybe_header("dav").is_none());
    }

    #[tokio::test]
    async fn a_preflight_asking_for_no_headers_is_granted_none() {
        let (server, _dir) = share(DavAccess::ReadOnly).await;

        let response = server
            .method(Method::OPTIONS, "/dav/pub/")
            .add_header(header::ORIGIN, "https://webdav.example")
            .add_header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .await;

        response.assert_status(StatusCode::NO_CONTENT);
        assert!(response
            .maybe_header(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .is_none());
    }

    #[tokio::test]
    async fn only_cross_origin_responses_carry_cors_headers() {
        let (server, _dir) = share(DavAccess::ReadOnly).await;

        let cross_origin = server
            .get("/dav/pub/a.txt")
            .add_header(header::ORIGIN, "https://webdav.example")
            .await;
        cross_origin.assert_status_ok();
        cross_origin.assert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        cross_origin.assert_header(header::ACCESS_CONTROL_EXPOSE_HEADERS, EXPOSE_HEADERS);

        let same_origin = server.get("/dav/pub/a.txt").await;
        same_origin.assert_status_ok();
        assert!(same_origin
            .maybe_header(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
        assert!(same_origin
            .maybe_header(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .is_none());
    }

    #[tokio::test]
    async fn a_verb_the_share_refuses_gets_an_allow_listing_the_share() {
        let (server, _dir) = share(DavAccess::ReadOnly).await;

        for method in ["PUT", "DELETE", "MKCOL", "LOCK", "PROPPATCH"] {
            let response = server
                .method(
                    Method::from_bytes(method.as_bytes()).unwrap(),
                    "/dav/pub/a.txt",
                )
                .await;
            response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
            // dav-server's own 405 carries no Allow at all.
            response.assert_header("allow", "OPTIONS, GET, HEAD, PROPFIND");
        }
    }

    #[tokio::test]
    async fn a_folder_on_a_read_only_share_has_no_index_page() {
        let (server, _dir) = share(DavAccess::ReadOnly).await;

        for method in [Method::GET, Method::HEAD] {
            let response = server.method(method.clone(), "/dav/pub/").await;
            response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
            // The share takes GET; this resource does not. Say what it does.
            response.assert_header("allow", READ_ONLY_COLLECTION_ALLOW);
        }

        // Listing is PROPFIND's job, and the files themselves still serve.
        server
            .method(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/pub/")
            .add_header("depth", "1")
            .await
            .assert_status(StatusCode::MULTI_STATUS);
        server.get("/dav/pub/a.txt").await.assert_text("hello");
    }

    #[tokio::test]
    async fn a_folder_on_a_read_write_share_is_an_index_page() {
        let (server, _dir) = share(DavAccess::ReadWrite).await;

        let response = server.get("/dav/pub/").await;

        response.assert_status_ok();
        assert!(
            header_str(&response, "content-type").starts_with("text/html"),
            "an index page is HTML"
        );
        assert!(response.text().contains("a.txt"), "{}", response.text());
    }

    #[tokio::test]
    async fn a_folder_named_without_its_slash_is_redirected_to_it() {
        // Browsers follow this; file managers never ask.
        let (server, _dir) = share(DavAccess::ReadOnly).await;

        let response = server.get("/dav/pub").await;

        response.assert_status(StatusCode::FOUND);
        response.assert_header(header::LOCATION, "/dav/pub/");
    }

    #[tokio::test]
    async fn a_verb_dav_server_has_never_heard_of_is_not_implemented() {
        let (server, _dir) = share(DavAccess::ReadWrite).await;

        server
            .method(Method::from_bytes(b"FROBNICATE").unwrap(), "/dav/pub/a.txt")
            .await
            .assert_status(StatusCode::NOT_IMPLEMENTED);
    }
}
