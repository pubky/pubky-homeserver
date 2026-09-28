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
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dav_server::{fakels::FakeLs, DavHandler, DavMethodSet};
use dav_server_opendalfs::OpendalFs;
use opendal::Operator;

/// URL prefix stripped before a path is resolved against storage.
pub(crate) const DAV_PREFIX: &str = "/dav";

/// The axum routes for a `/dav` endpoint: the root, and everything beneath
/// it. Two because a catch-all must match at least one character, and `/dav/`
/// itself is the storage root an operator lists.
pub(crate) const DAV_ROOT_ROUTE: &str = "/dav/";
pub(crate) const DAV_ROUTE: &str = "/dav/{*path}";

/// The header a client reads to learn what the share supports.
const DAV_COMPLIANCE_HEADER: &str = "dav";

/// What a read-only share reports in `DAV:` — compliance class 1, no locking.
///
/// dav-server claims `1,2,3` unconditionally, whether or not a lock system is
/// attached, so the header is rewritten. Class 2 would tell Finder the share
/// takes locks, and it would then try to mount writable.
const READ_ONLY_DAV_CLASSES: &str = "1";

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

    fn method_set(self) -> DavMethodSet {
        DavMethodSet::from_vec(self.methods().to_vec())
            .expect("every verb listed is one dav-server knows")
    }

    fn allow_header(self) -> HeaderValue {
        HeaderValue::from_str(&self.methods().join(", "))
            .expect("verb names are valid header characters")
    }
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
            .autoindex(true)
            // Refuses anything else with 405, and keeps a bare OPTIONS from
            // offering MKCOL, PUT and LOCK on an unmapped path.
            .methods(access.method_set());
        let builder = match access {
            DavAccess::ReadOnly => builder,
            DavAccess::ReadWrite => builder.locksystem(FakeLs::new()),
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
        let mut response = self.handler.handle(req).await.into_response();

        if response.status() == StatusCode::METHOD_NOT_ALLOWED {
            response
                .headers_mut()
                .insert(header::ALLOW, self.access.allow_header());
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
pub(crate) async fn cors(
    State(access): State<DavAccess>,
    req: Request<Body>,
    next: Next,
) -> Response {
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
}
