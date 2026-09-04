//! WebDAV endpoint for authenticated users.
//!
//! Mounted at `/dav/{user_z32}/...`, this exposes one user's drive to standard
//! WebDAV clients (Finder, Nautilus, rclone) through the `dav-server` crate,
//! mirroring the admin server's `/dav` endpoint.
//!
//! Storage keys are `{user_z32}/{path}`, so stripping only the `/dav` prefix
//! leaves the tenant segment in place and the shared `DavHandler` maps
//! `/dav/{user_z32}/pub/x` straight onto the storage key `{user_z32}/pub/x`.
//! Tenant isolation is therefore an authorization concern, enforced here:
//! [`authorize_target`] canonicalizes the path (collapsing `..` before it can
//! escape) and rejects anything whose tenant segment is not the caller.
//!
//! Credentials arrive as either `Authorization: Bearer <token>` or
//! `Authorization: Basic base64(user_z32:<token>)`; both are resolved into an
//! [`AuthSession`] upstream by the authentication layer.
//!
//! Authorization is the same as the REST routes': every request is checked with
//! [`has_read_permission`] or [`has_write_permission`] against the storage path
//! it targets, so capability scopes and the `/pub/` + `/priv/` write-root rule
//! hold here too. The one addition is that the drive root and the two storage
//! roots are readable by their owner whatever the token's scope, because a
//! client has to list them to mount anything at all — and that only reveals a
//! shape every drive shares.
//!
//! [`has_read_permission`]: crate::client_server::auth::has_read_permission
//! [`has_write_permission`]: crate::client_server::auth::has_write_permission
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dav_server::{fakels::FakeLs, DavHandler};
use dav_server_opendalfs::OpendalFs;
use percent_encoding::percent_decode_str;
use pubky_common::crypto::PublicKey;

use crate::client_server::{
    auth::{has_read_permission, has_write_permission, AuthSession},
    AppState,
};
use crate::constants::{PRIVATE_ROOT, PUBLIC_ROOT};
use crate::persistence::files::tenant_scope_layer::TenantScopeLayer;
use crate::shared::{webdav::StoragePath, HttpError, HttpResult};

/// URL prefix the [`DavHandler`] strips before resolving storage keys.
///
/// [`DavHandler`]: dav_server::DavHandler
pub(crate) const DAV_PREFIX: &str = "/dav";

/// Methods a browser client may use cross-origin. The WebDAV verbs are all
/// "non-simple", so every one of them needs naming here or the browser refuses
/// the request before it is sent.
const ALLOW_METHODS: &str =
    "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK";

/// Request headers WebDAV clients send. `Depth` and `Destination` are the ones
/// that make listing and MOVE work; the rest come from the locking verbs.
const ALLOW_HEADERS: &str =
    "authorization, content-type, depth, destination, overwrite, if, lock-token, timeout";

/// Response headers a browser client has to be able to read. Without `dav` here
/// a client cannot detect compliance; without `lock-token` it cannot unlock.
const EXPOSE_HEADERS: &str =
    "dav, allow, etag, last-modified, content-length, content-type, lock-token, ms-author-via";

/// How long a browser may cache the preflight result.
const PREFLIGHT_MAX_AGE: &str = "600";

pub(crate) async fn dav_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> HttpResult<Response> {
    // Not the `AuthSession` extractor: its 401 carries no `WWW-Authenticate`,
    // which is what makes a WebDAV client offer a login prompt.
    let Some(session) = req.extensions().get::<AuthSession>().cloned() else {
        return Ok(unauthorized());
    };

    let (source, destination) = actions_for(req.method());

    let target = DavTarget::parse(req.uri().path())?;
    target.authorize(&session, source)?;
    // MOVE and COPY name their second target in `Destination`, which never
    // passes through routing, so it needs the same check as the request path.
    if let Some(action) = destination {
        let header = req
            .headers()
            .get("Destination")
            .ok_or_else(|| HttpError::bad_request("Missing Destination header"))?
            .to_str()
            .map_err(|_| HttpError::bad_request("Destination header is not valid ASCII"))?;
        DavTarget::parse(destination_path(header))?.authorize(&session, action)?;
    }

    Ok(scoped_handler(&state, &target.tenant)
        .handle(req)
        .await
        .into_response())
}

/// A `DavHandler` whose view of storage is confined to one drive.
///
/// Built per request rather than shared, because the confinement is the point:
/// [`TenantScopeLayer`] refuses keys outside `{user_z32}/` at the storage
/// boundary, so a mistake in [`DavTarget::authorize`] cannot reach another
/// user's files. The cost is a handful of allocations against a network round
/// trip.
///
/// Only `/dav` is stripped from the URL, so the tenant segment survives into the
/// object key and lands on the same key the REST routes use.
fn scoped_handler(state: &AppState, tenant: &PublicKey) -> DavHandler {
    // The app-facing operator, not the admin one: it keeps per-user
    // `allowed_write_paths` and write-collision checks in force.
    let operator = state
        .context
        .file_service
        .opendal
        .operator
        .clone()
        .layer(TenantScopeLayer::new(tenant));

    DavHandler::builder()
        .filesystem(OpendalFs::new(operator))
        .locksystem(FakeLs::new())
        .strip_prefix(DAV_PREFIX)
        .autoindex(true)
        .build_handler()
}

/// 401 with the challenge that makes WebDAV clients prompt for credentials.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, r#"Basic realm="pubky""#)],
        "Unauthorized",
    )
        .into_response()
}

/// What a request needs to be allowed to do to the resource it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Read,
    Write,
}

/// The permissions a method needs: one for the request path, and one for the
/// `Destination` header when the method has one.
///
/// `COPY` only reads its source, where `MOVE` also removes it, so the two
/// differ in the first slot. Everything that changes state — including the
/// locking verbs and `PROPPATCH` — counts as a write; an unknown method is
/// treated as a write so a future verb fails closed.
fn actions_for(method: &Method) -> (Action, Option<Action>) {
    match method.as_str() {
        "GET" | "HEAD" | "OPTIONS" | "PROPFIND" => (Action::Read, None),
        "COPY" => (Action::Read, Some(Action::Write)),
        "MOVE" => (Action::Write, Some(Action::Write)),
        _ => (Action::Write, None),
    }
}

/// A parsed `/dav` request path: which drive, and where inside it.
struct DavTarget {
    tenant: PublicKey,
    path: StoragePath,
}

impl DavTarget {
    /// Parse and canonicalize a `/dav/...` URL path.
    ///
    /// Canonicalization happens before anything is compared, so a path like
    /// `/dav/{me}/pub/../../{other}/priv/` is judged by where it lands rather
    /// than how it is spelled.
    fn parse(uri_path: &str) -> Result<Self, HttpError> {
        let decoded = percent_decode_str(uri_path)
            .decode_utf8()
            .map_err(|_| HttpError::bad_request("WebDAV path is not valid UTF-8"))?;

        let relative = decoded
            .strip_prefix(DAV_PREFIX)
            .ok_or_else(|| HttpError::bad_request("WebDAV paths must start with `/dav/`"))?;

        let canonical = StoragePath::normalize(relative)
            .map_err(|e| HttpError::bad_request(format!("Invalid WebDAV path: {e}")))?;

        // The canonical path is `/{user_z32}/...`, so the first segment names
        // the drive and the remainder is the storage path within it.
        let (tenant, path) = canonical
            .as_str()
            .strip_prefix('/')
            .and_then(|rest| match rest.split_once('/') {
                Some((tenant, path)) => Some((tenant, format!("/{path}"))),
                None if !rest.is_empty() => Some((rest, "/".to_string())),
                None => None,
            })
            .ok_or_else(|| HttpError::bad_request("WebDAV paths must name a user"))?;

        let tenant = PublicKey::try_from_z32(tenant)
            .map_err(|e| HttpError::bad_request(format!("Invalid user in WebDAV path: {e}")))?;
        let path = StoragePath::normalize(&path)
            .map_err(|e| HttpError::bad_request(format!("Invalid WebDAV path: {e}")))?;

        Ok(Self { tenant, path })
    }

    /// Authorize `action` on this target for `session`.
    fn authorize(&self, session: &AuthSession, action: Action) -> Result<(), HttpError> {
        if session.user_key() != &self.tenant {
            return Err(HttpError::forbidden_with_message(
                "Session user does not match target tenant",
            ));
        }

        match action {
            // A client lists the drive root and the storage roots before it can
            // reach anything, so those stay readable by their owner whatever the
            // token's scope. They expose only the shape every drive has.
            Action::Read if self.is_mount_scaffolding() => Ok(()),
            Action::Read => has_read_permission(Some(session), Some(&self.tenant), &self.path),
            Action::Write => has_write_permission(session, &self.tenant, &self.path),
        }
    }

    /// Whether this is the drive root or one of the two storage roots.
    fn is_mount_scaffolding(&self) -> bool {
        matches!(self.path.as_str(), "/" | PUBLIC_ROOT | PRIVATE_ROOT)
            || matches!(self.path.as_str().trim_end_matches('/'), "/pub" | "/priv")
    }
}

/// The path component of a `Destination` header.
///
/// RFC 4918 allows either an absolute URI or an absolute path, so strip an
/// optional scheme and authority, then any query or fragment.
fn destination_path(destination: &str) -> &str {
    let after_authority = match destination.split_once("://") {
        Some((_scheme, rest)) => match rest.find('/') {
            Some(index) => &rest[index..],
            None => "/",
        },
        None => destination,
    };

    after_authority
        .split(['?', '#'])
        .next()
        .unwrap_or(after_authority)
}

/// Cross-origin support for `/dav`, hand-rolled because the two kinds of
/// `OPTIONS` request must be told apart.
///
/// A blanket CORS layer answers *every* `OPTIONS` itself. That breaks native
/// clients: a bare `OPTIONS` is a WebDAV capability probe, and only the
/// `DavHandler` can answer it with the `DAV:` header that Finder and GNOME Files
/// read before they will mount a share. So only a real preflight — one carrying
/// `Access-Control-Request-Method` — is short-circuited here; a bare `OPTIONS`
/// falls through to the handler.
///
/// The preflight is answered before authentication runs, because a browser
/// strips credentials from preflights by design: requiring auth would 401 the
/// request that exists to ask whether the real request is allowed.
///
/// `Access-Control-Allow-Credentials` is deliberately never set, and the origin
/// is `*` rather than mirrored. Browsers refuse to attach cookies under those
/// terms, so a session cookie — which this server sets `SameSite=None` — cannot
/// be used to read a drive from another origin. Browser clients authenticate the
/// way every other client does, with an `Authorization` header they must already
/// hold.
pub(crate) async fn cors(req: Request<Body>, next: Next) -> Response {
    if req.method() == Method::OPTIONS
        && req
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
    {
        return preflight();
    }

    let cross_origin = req.headers().contains_key(header::ORIGIN);
    let mut response = next.run(req).await;

    if cross_origin {
        let headers = response.headers_mut();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            axum::http::HeaderValue::from_static("*"),
        );
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            axum::http::HeaderValue::from_static(EXPOSE_HEADERS),
        );
    }

    response
}

/// The preflight answer. No `Allow-Credentials`, so cookies stay unusable.
fn preflight() -> Response {
    (
        StatusCode::NO_CONTENT,
        [
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::ACCESS_CONTROL_ALLOW_METHODS, ALLOW_METHODS),
            (header::ACCESS_CONTROL_ALLOW_HEADERS, ALLOW_HEADERS),
            (header::ACCESS_CONTROL_MAX_AGE, PREFLIGHT_MAX_AGE),
        ],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_common::auth::jws::GrantId;
    use pubky_common::capabilities::{Capabilities, Capability};
    use pubky_common::crypto::Keypair;

    use crate::client_server::auth::grant::session::GrantSession;

    fn session_with(key: &PublicKey, capabilities: Capabilities) -> AuthSession {
        AuthSession::Grant(GrantSession::test(
            key.clone(),
            capabilities,
            GrantId::generate(),
            9999999999,
        ))
    }

    fn root_session(key: &PublicKey) -> AuthSession {
        session_with(key, Capabilities::from(vec![Capability::root()]))
    }

    /// A token that may only read and write one app's folder.
    fn scoped_session(key: &PublicKey) -> AuthSession {
        session_with(
            key,
            Capabilities::from(vec![Capability::write("/pub/someapp/").unwrap()]),
        )
    }

    fn check(session: &AuthSession, method: &str, path: &str) -> Result<(), HttpError> {
        let method = Method::from_bytes(method.as_bytes()).expect("valid method");
        let (source, _) = actions_for(&method);
        DavTarget::parse(path)?.authorize(session, source)
    }

    fn status(result: Result<(), HttpError>) -> StatusCode {
        result
            .expect_err("expected a rejection")
            .into_response()
            .status()
    }

    #[test]
    fn a_root_token_reaches_its_whole_drive() {
        let key = Keypair::random().public_key();
        let session = root_session(&key);
        let z32 = key.z32();

        for (method, path) in [
            ("PROPFIND", format!("/dav/{z32}")),
            ("PROPFIND", format!("/dav/{z32}/")),
            ("PROPFIND", format!("/dav/{z32}/pub/")),
            ("PROPFIND", format!("/dav/{z32}/priv/")),
            ("GET", format!("/dav/{z32}/pub/notes/a.txt")),
            ("PUT", format!("/dav/{z32}/pub/notes/a.txt")),
            ("PUT", format!("/dav/{z32}/priv/secret.txt")),
            ("MKCOL", format!("/dav/{z32}/pub/newdir/")),
            ("DELETE", format!("/dav/{z32}/priv/secret.txt")),
        ] {
            check(&session, method, &path)
                .unwrap_or_else(|e| panic!("{method} {path} should be allowed: {e:?}"));
        }
    }

    #[test]
    fn a_scoped_token_is_confined_to_its_scope() {
        let key = Keypair::random().public_key();
        let session = scoped_session(&key);
        let z32 = key.z32();

        // Inside the scope it behaves like a root token.
        check(
            &session,
            "PUT",
            &format!("/dav/{z32}/pub/someapp/data.json"),
        )
        .unwrap();
        check(
            &session,
            "GET",
            &format!("/dav/{z32}/pub/someapp/data.json"),
        )
        .unwrap();

        // Outside it, writes are refused — this is the escalation that used to
        // be possible by switching from the REST route to WebDAV.
        for path in [
            format!("/dav/{z32}/pub/other/data.json"),
            format!("/dav/{z32}/priv/secret.txt"),
        ] {
            assert_eq!(
                status(check(&session, "PUT", &path)),
                StatusCode::FORBIDDEN,
                "{path} should not be writable by a scoped token"
            );
        }

        // Reading `/priv/` needs a capability that covers it.
        assert_eq!(
            status(check(
                &session,
                "GET",
                &format!("/dav/{z32}/priv/secret.txt")
            )),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn mounting_works_for_a_scoped_token() {
        // A client lists the drive root before it can reach anything, so the
        // scaffolding stays readable however narrow the token is.
        let key = Keypair::random().public_key();
        let session = scoped_session(&key);
        let z32 = key.z32();

        for path in [
            format!("/dav/{z32}/"),
            format!("/dav/{z32}/pub/"),
            format!("/dav/{z32}/priv/"),
        ] {
            check(&session, "PROPFIND", &path)
                .unwrap_or_else(|e| panic!("{path} must stay listable: {e:?}"));
        }

        // Listing the roots is not the same as reading through them.
        assert_eq!(
            status(check(
                &session,
                "GET",
                &format!("/dav/{z32}/priv/secret.txt")
            )),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn writes_outside_the_storage_roots_are_refused() {
        // Finder writes `.DS_Store` at the mount root; that used to return 201.
        let key = Keypair::random().public_key();
        let session = root_session(&key);
        let z32 = key.z32();

        for path in [
            format!("/dav/{z32}/.DS_Store"),
            format!("/dav/{z32}/Thumbs.db"),
            format!("/dav/{z32}/notes.txt"),
        ] {
            assert_eq!(
                status(check(&session, "PUT", &path)),
                StatusCode::FORBIDDEN,
                "{path} is outside /pub/ and /priv/"
            );
        }
    }

    #[test]
    fn another_drive_is_forbidden_however_the_path_is_spelled() {
        let key = Keypair::random().public_key();
        let session = root_session(&key);
        let z32 = key.z32();
        let other = Keypair::random().public_key().z32();

        for path in [
            format!("/dav/{other}/pub/file.txt"),
            format!("/dav/{z32}/../{other}/pub/file.txt"),
            format!("/dav/{z32}/pub/%2e%2e/%2e%2e/{other}/priv/secret.txt"),
        ] {
            assert_eq!(
                status(check(&session, "GET", &path)),
                StatusCode::FORBIDDEN,
                "{path} should not reach another drive"
            );
        }
    }

    #[test]
    fn traversal_above_the_storage_root_is_rejected() {
        let key = Keypair::random().public_key();
        let session = root_session(&key);
        let z32 = key.z32();

        assert_eq!(
            status(check(
                &session,
                "GET",
                &format!("/dav/{z32}/../../etc/passwd")
            )),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn paths_outside_the_dav_prefix_are_rejected() {
        let session = root_session(&Keypair::random().public_key());

        for path in ["/storage/whatever", "/dav", "/dav/not-a-pubkey/pub/"] {
            assert_eq!(
                status(check(&session, "GET", path)),
                StatusCode::BAD_REQUEST,
                "{path} should not parse"
            );
        }
    }

    #[test]
    fn methods_map_to_the_permissions_they_need() {
        let cases = [
            ("GET", Action::Read, None),
            ("HEAD", Action::Read, None),
            ("OPTIONS", Action::Read, None),
            ("PROPFIND", Action::Read, None),
            ("PUT", Action::Write, None),
            ("DELETE", Action::Write, None),
            ("MKCOL", Action::Write, None),
            ("PROPPATCH", Action::Write, None),
            ("LOCK", Action::Write, None),
            ("UNLOCK", Action::Write, None),
            // COPY leaves its source alone; MOVE removes it.
            ("COPY", Action::Read, Some(Action::Write)),
            ("MOVE", Action::Write, Some(Action::Write)),
            // An unknown verb must fail closed.
            ("FROBNICATE", Action::Write, None),
        ];

        for (method, source, destination) in cases {
            let method = Method::from_bytes(method.as_bytes()).unwrap();
            assert_eq!(actions_for(&method), (source, destination), "{method}");
        }
    }

    #[test]
    fn copy_and_move_destinations_are_authorized_separately() {
        let key = Keypair::random().public_key();
        let session = scoped_session(&key);
        let z32 = key.z32();

        // Source in scope, destination outside it: the destination must fail.
        let destination = DavTarget::parse(&format!("/dav/{z32}/pub/elsewhere/x.txt")).unwrap();
        assert_eq!(
            status(destination.authorize(&session, Action::Write)),
            StatusCode::FORBIDDEN
        );

        // And a destination in another drive is refused outright.
        let other = Keypair::random().public_key().z32();
        let destination = DavTarget::parse(&format!("/dav/{other}/pub/someapp/x.txt")).unwrap();
        assert_eq!(
            status(destination.authorize(&session, Action::Write)),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn destination_path_strips_scheme_authority_and_query() {
        for (raw, expected) in [
            ("https://example.test/dav/abc/pub/x", "/dav/abc/pub/x"),
            ("http://example.test:6286/dav/abc/", "/dav/abc/"),
            ("https://example.test", "/"),
            ("/dav/abc/pub/x", "/dav/abc/pub/x"),
            ("/dav/abc/pub/x?v=1", "/dav/abc/pub/x"),
            ("/dav/abc/pub/x#frag", "/dav/abc/pub/x"),
        ] {
            assert_eq!(destination_path(raw), expected, "for {raw}");
        }
    }
}
