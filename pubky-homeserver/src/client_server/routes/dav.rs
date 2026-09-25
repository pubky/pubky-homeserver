//! Read-only WebDAV access to every user's public folder.
//!
//! Mounted at `/dav/{user_z32}/pub/...`, this serves the same files as
//! `/storage/{user_z32}/pub/...` to standard WebDAV clients (GNOME Files,
//! Finder, rclone, browsers) through the `dav-server` crate, mirroring the
//! admin server's `/dav` endpoint.
//!
//! Nothing here is authenticated. `/pub/` is world-readable over REST, and this
//! endpoint exposes exactly that and no more:
//!
//! - Only the read verbs are served. Anything that would write gets `405`,
//!   which is what tells a file manager to mount the share read-only.
//! - Only paths under `/pub/` exist. Everything else — the drive root
//!   included — is `404`, so the endpoint never confirms that `/priv/` is there.
//!
//! Storage keys are `{user_z32}/{path}`, so stripping only the `/dav` prefix
//! leaves the tenant segment in place and `/dav/{user_z32}/pub/x` maps straight
//! onto the storage key `{user_z32}/pub/x`. The confinement to `/pub/` is
//! enforced twice: [`DavTarget`] canonicalizes each path (collapsing `..`
//! before it can escape) and refuses anything outside the public folder, and
//! the per-request handler's storage is wrapped in [`TenantScopeLayer`] so a
//! mistake in the first cannot reach a private folder or the storage root.
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dav_server::DavHandler;
use dav_server_opendalfs::OpendalFs;
use percent_encoding::percent_decode_str;
use pubky_common::crypto::PublicKey;

use crate::client_server::AppState;
use crate::constants::PUBLIC_ROOT;
use crate::persistence::files::tenant_scope_layer::TenantScopeLayer;
use crate::shared::{webdav::StoragePath, HttpError, HttpResult};

/// URL prefix the [`DavHandler`] strips before resolving storage keys.
///
/// [`DavHandler`]: dav_server::DavHandler
pub(crate) const DAV_PREFIX: &str = "/dav";

/// The verbs a read-only share answers. Everything else is refused with this
/// list in `Allow`, before dav-server sees the request.
const ALLOWED_METHODS: &str = "OPTIONS, GET, HEAD, PROPFIND";

/// Request headers WebDAV clients send on reads. `Depth` is what makes listing
/// work; `Content-Type` describes the XML body of a `PROPFIND`.
const ALLOW_HEADERS: &str = "content-type, depth";

/// Response headers a browser client has to be able to read. Without `dav`
/// here a client cannot detect compliance.
const EXPOSE_HEADERS: &str = "dav, allow, etag, last-modified, content-length, content-type";

/// How long a browser may cache the preflight result.
const PREFLIGHT_MAX_AGE: &str = "600";

pub(crate) async fn dav_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> HttpResult<Response> {
    if !is_read_method(req.method()) {
        return Ok(method_not_allowed());
    }

    let target = DavTarget::parse(req.uri().path())?;
    // `OPTIONS` is a capability probe that touches nothing, so it is answered
    // anywhere a drive is named: a client may well send it above the folder it
    // is about to mount.
    if req.method() != Method::OPTIONS && !target.is_public() {
        return Ok(not_found());
    }

    Ok(scoped_handler(&state, &target.tenant)
        .handle(req)
        .await
        .into_response())
}

/// Whether `method` only reads. An unknown verb is not a read.
fn is_read_method(method: &Method) -> bool {
    matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "PROPFIND")
}

/// A `DavHandler` whose view of storage is confined to one user's public
/// folder.
///
/// Built per request rather than shared, because the confinement is the point:
/// [`TenantScopeLayer`] refuses keys outside `{user_z32}/pub/` at the storage
/// boundary, so a mistake in [`DavTarget::is_public`] cannot reach a private
/// folder or another drive. The cost is a handful of allocations against a
/// network round trip.
///
/// Only `/dav` is stripped from the URL, so the tenant segment survives into
/// the object key and lands on the same key the REST routes use.
fn scoped_handler(state: &AppState, tenant: &PublicKey) -> DavHandler {
    let operator = state
        .context
        .file_service
        .opendal
        .operator
        .clone()
        .layer(TenantScopeLayer::public(tenant));

    // No lock system: a share that cannot be written has nothing to lock, and
    // advertising compliance class 1 alone is what tells Finder to mount it
    // read-only rather than complain.
    DavHandler::builder()
        .filesystem(OpendalFs::new(operator))
        .strip_prefix(DAV_PREFIX)
        .autoindex(true)
        .build_handler()
}

/// `405` naming the verbs that are served. `Allow` is what a file manager reads
/// to decide the share is read-only rather than broken.
fn method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, ALLOWED_METHODS)],
        "Method Not Allowed",
    )
        .into_response()
}

/// `404` for anything outside a public folder. Not `403`: a refusal would
/// confirm there is something there to refuse.
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not Found").into_response()
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
    /// `/dav/{key}/pub/../priv/` is judged by where it lands rather than how
    /// it is spelled.
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

    /// Whether this names the public folder or something inside it.
    ///
    /// The folder itself counts with or without its trailing slash, since
    /// clients spell the thing they mount both ways.
    fn is_public(&self) -> bool {
        let path = self.path.as_str();
        path.starts_with(PUBLIC_ROOT) || path == PUBLIC_ROOT.trim_end_matches('/')
    }
}

/// Cross-origin support for `/dav`, hand-rolled because the two kinds of
/// `OPTIONS` request must be told apart.
///
/// A blanket CORS layer answers *every* `OPTIONS` itself. That breaks native
/// clients: a bare `OPTIONS` is a WebDAV capability probe, and only the
/// `DavHandler` can answer it with the `DAV:` header that Finder and GNOME
/// Files read before they will mount a share. So only a real preflight — one
/// carrying `Access-Control-Request-Method` — is short-circuited here; a bare
/// `OPTIONS` falls through to the handler.
///
/// Nothing on this endpoint is authenticated, so the origin is simply `*` and
/// no credentials are ever allowed. That keeps the server's session cookie —
/// which is `SameSite=None` — unusable from another origin should `/dav` ever
/// start reading it.
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
            HeaderValue::from_static("*"),
        );
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static(EXPOSE_HEADERS),
        );
    }

    response
}

/// The preflight answer.
fn preflight() -> Response {
    (
        StatusCode::NO_CONTENT,
        [
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::ACCESS_CONTROL_ALLOW_METHODS, ALLOWED_METHODS),
            (header::ACCESS_CONTROL_ALLOW_HEADERS, ALLOW_HEADERS),
            (header::ACCESS_CONTROL_MAX_AGE, PREFLIGHT_MAX_AGE),
        ],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn traversal_into_another_drive_lands_in_its_public_folder() {
        // Every public folder is public, so climbing into another drive is not
        // an escape: the path is judged like any other, by where it lands.
        let mine = Keypair::random().public_key().z32();
        let other = Keypair::random().public_key();
        let other_z32 = other.z32();

        let target =
            DavTarget::parse(&format!("/dav/{mine}/../{other_z32}/pub/file.txt")).unwrap();
        assert_eq!(target.tenant.z32(), other_z32);
        assert!(target.is_public());

        let target =
            DavTarget::parse(&format!("/dav/{mine}/../{other_z32}/priv/file.txt")).unwrap();
        assert!(!target.is_public());
    }

    #[test]
    fn traversal_above_the_storage_root_is_rejected() {
        let z32 = Keypair::random().public_key().z32();

        assert_eq!(
            status(DavTarget::parse(&format!("/dav/{z32}/../../etc/passwd"))),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn paths_outside_the_dav_prefix_are_rejected() {
        for path in ["/storage/whatever", "/dav", "/dav/not-a-pubkey/pub/"] {
            assert_eq!(
                status(DavTarget::parse(path)),
                StatusCode::BAD_REQUEST,
                "{path} should not parse"
            );
        }
    }

    #[test]
    fn only_read_verbs_are_served() {
        let method = |name: &str| Method::from_bytes(name.as_bytes()).unwrap();

        for name in ["GET", "HEAD", "OPTIONS", "PROPFIND"] {
            assert!(is_read_method(&method(name)), "{name} is a read");
        }
        for name in [
            "PUT",
            "DELETE",
            "MKCOL",
            "PROPPATCH",
            "COPY",
            "MOVE",
            "LOCK",
            "UNLOCK",
            // An unknown verb must fail closed.
            "FROBNICATE",
        ] {
            assert!(!is_read_method(&method(name)), "{name} is not a read");
        }
    }
}
