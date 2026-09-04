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
//! Note: within a drive, access is all-or-nothing. Capability scopes and the
//! `/pub/` + `/priv/` write-root rule that [`has_write_permission`] applies to
//! the REST routes are not enforced here, because clients mount and `PROPFIND`
//! the tenant root, which no scoped capability covers. Per-user
//! `allowed_write_paths` and write-collision checks still apply — they live in
//! the OpenDAL operator behind the handler.
//!
//! [`has_write_permission`]: crate::client_server::auth::has_write_permission
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use percent_encoding::percent_decode_str;
use pubky_common::crypto::PublicKey;

use crate::client_server::{auth::AuthSession, AppState};
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

    authorize_target(&session, req.uri().path())?;
    // MOVE/COPY name their target in `Destination`, which never passes through
    // routing — check it against the same tenant rule.
    if let Some(destination) = req.headers().get("Destination") {
        let destination = destination
            .to_str()
            .map_err(|_| HttpError::bad_request("Destination header is not valid ASCII"))?;
        authorize_target(&session, destination_path(destination))?;
    }

    Ok(state.dav_handler.handle(req).await.into_response())
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

/// Reject a WebDAV target that resolves outside the caller's own drive.
///
/// Canonicalization happens before the tenant comparison so that a path like
/// `/dav/{me}/pub/../../{other}/priv/` is judged by where it lands, not by how
/// it is spelled.
fn authorize_target(session: &AuthSession, uri_path: &str) -> Result<(), HttpError> {
    let decoded = percent_decode_str(uri_path)
        .decode_utf8()
        .map_err(|_| HttpError::bad_request("WebDAV path is not valid UTF-8"))?;

    let relative = decoded
        .strip_prefix(DAV_PREFIX)
        .ok_or_else(|| HttpError::bad_request("WebDAV paths must start with `/dav/`"))?;

    let canonical = StoragePath::normalize(relative)
        .map_err(|e| HttpError::bad_request(format!("Invalid WebDAV path: {e}")))?;

    // The canonical path is `/{user_z32}/...`, so the first segment is the tenant.
    let tenant = canonical
        .as_str()
        .split('/')
        .nth(1)
        .filter(|segment| !segment.is_empty())
        .ok_or_else(|| HttpError::bad_request("WebDAV paths must name a user"))?;
    let tenant = PublicKey::try_from_z32(tenant)
        .map_err(|e| HttpError::bad_request(format!("Invalid user in WebDAV path: {e}")))?;

    if &tenant != session.user_key() {
        return Err(HttpError::forbidden_with_message(
            "Session user does not match target tenant",
        ));
    }

    Ok(())
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

    fn session_for(key: &PublicKey) -> AuthSession {
        AuthSession::Grant(GrantSession::test(
            key.clone(),
            Capabilities::from(vec![Capability::root()]),
            GrantId::generate(),
            9999999999,
        ))
    }

    fn rejection_status(result: Result<(), HttpError>) -> StatusCode {
        result
            .expect_err("expected the target to be rejected")
            .into_response()
            .status()
    }

    #[test]
    fn own_drive_is_allowed() {
        let key = Keypair::random().public_key();
        let session = session_for(&key);
        let z32 = key.z32();

        for path in [
            format!("/dav/{z32}"),
            format!("/dav/{z32}/"),
            format!("/dav/{z32}/pub/file.txt"),
            format!("/dav/{z32}/priv/nested/dir/"),
            // Traversal that stays inside the drive is still the caller's own.
            format!("/dav/{z32}/pub/../priv/file.txt"),
        ] {
            authorize_target(&session, &path)
                .unwrap_or_else(|e| panic!("{path} should be allowed: {e:?}"));
        }
    }

    #[test]
    fn another_drive_is_forbidden() {
        let session = session_for(&Keypair::random().public_key());
        let other = Keypair::random().public_key().z32();

        assert_eq!(
            rejection_status(authorize_target(
                &session,
                &format!("/dav/{other}/pub/file.txt")
            )),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn traversal_out_of_own_drive_is_forbidden() {
        let key = Keypair::random().public_key();
        let session = session_for(&key);
        let z32 = key.z32();
        let other = Keypair::random().public_key().z32();

        // Both spellings must be judged by where the path lands, not how it reads.
        for path in [
            format!("/dav/{z32}/../{other}/priv/secret.txt"),
            format!("/dav/{z32}/pub/%2e%2e/%2e%2e/{other}/priv/secret.txt"),
        ] {
            assert_eq!(
                rejection_status(authorize_target(&session, &path)),
                StatusCode::FORBIDDEN,
                "{path} should not reach another drive"
            );
        }
    }

    #[test]
    fn traversal_above_the_storage_root_is_rejected() {
        let key = Keypair::random().public_key();
        let session = session_for(&key);
        let z32 = key.z32();

        assert_eq!(
            rejection_status(authorize_target(
                &session,
                &format!("/dav/{z32}/../../etc/passwd")
            )),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn paths_outside_the_dav_prefix_are_rejected() {
        let session = session_for(&Keypair::random().public_key());

        assert_eq!(
            rejection_status(authorize_target(&session, "/storage/whatever")),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            rejection_status(authorize_target(&session, "/dav")),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            rejection_status(authorize_target(&session, "/dav/not-a-pubkey/pub/")),
            StatusCode::BAD_REQUEST
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
