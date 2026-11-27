//! Resolve the tenant targeted by a client-server request.
//!
//! Storage requests carry their owner in `/storage/{owner}/...`, and WebDAV
//! requests in `/dav/{owner}/...`.
//! Other requests retain the legacy Host / `pubky-host` compatibility lookup.

use axum::{
    extract::{FromRequestParts, Request},
    http::{request::Parts, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use percent_encoding::percent_decode_str;
use pubky_common::crypto::PublicKey;

use crate::constants::PUBLIC_ROOT;
use crate::shared::{
    webdav::{EntryPath, StoragePath},
    HttpError,
};

use super::pubky_host::extract_legacy_pubky;

const STORAGE_ROUTE_PREFIX: &str = "/storage/";
const DAV_ROUTE_PREFIX: &str = "/dav/";

/// Tenant and optional owner-relative storage path resolved before auth runs.
#[derive(Debug, Clone)]
pub struct RequestTenant {
    public_key: PublicKey,
    storage_path: Option<StoragePath>,
}

impl RequestTenant {
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn storage_path(&self) -> Option<&StoragePath> {
        self.storage_path.as_ref()
    }

    pub fn pubky_url(&self, request_uri: &Uri) -> String {
        let storage_path = self
            .storage_path
            .as_ref()
            .map_or(request_uri.path(), StoragePath::as_str);
        let mut pubky_url = format!("pubky://{}{}", self.public_key.z32(), storage_path);
        if let Some(query) = request_uri.query() {
            pubky_url.push('?');
            pubky_url.push_str(query);
        }
        pubky_url
    }

    fn from_request(req: &Request) -> Result<Option<Self>, String> {
        if let Some(tenant) = Self::from_storage_route(req.uri().path())? {
            return Ok(Some(tenant));
        }

        Ok(extract_legacy_pubky(req).map(Self::legacy))
    }

    /// Returns `Ok(None)` when the URL is not in the `/storage` namespace.
    fn from_storage_route(raw_path: &str) -> Result<Option<Self>, String> {
        if raw_path == "/storage" || raw_path == "/storage/" {
            return Err("Missing storage owner or path".to_string());
        }

        let Some(remainder) = raw_path.strip_prefix(STORAGE_ROUTE_PREFIX) else {
            return Ok(None);
        };
        let (raw_public_key, raw_storage_path) = remainder
            .split_once('/')
            .ok_or_else(|| "Missing storage path".to_string())?;
        if raw_storage_path.is_empty() {
            return Err("Missing storage path".to_string());
        }

        Self::path_addressed(raw_public_key, raw_storage_path).map(Some)
    }

    /// The drive and path a `/dav/{owner}/...` URL names.
    ///
    /// Unlike `/storage`, the owner alone is enough: `/dav/{owner}` and
    /// `/dav/{owner}/` name the drive root, which a WebDAV client may probe
    /// before it mounts a folder beneath it.
    fn from_dav_route(raw_path: &str) -> Result<Self, String> {
        let remainder = raw_path
            .strip_prefix(DAV_ROUTE_PREFIX)
            .filter(|remainder| !remainder.is_empty())
            .ok_or_else(|| "Missing WebDAV owner".to_string())?;
        let (raw_public_key, raw_storage_path) =
            remainder.split_once('/').unwrap_or((remainder, ""));

        let mut tenant = Self::path_addressed(raw_public_key, raw_storage_path)?;
        // WebDAV clients name a folder with or without its trailing slash.
        // Give the public folder the one spelling storage uses, so `/pub` is
        // the same folder to the handler and to a rate limit on `/pub/**`.
        let names_public_folder = tenant
            .storage_path()
            .is_some_and(|path| path.as_str() == PUBLIC_ROOT.trim_end_matches('/'));
        if names_public_folder {
            tenant.storage_path = Some(
                StoragePath::new(PUBLIC_ROOT)
                    .map_err(|error| format!("Invalid storage path: {error}"))?,
            );
        }
        Ok(tenant)
    }

    /// The owner segment is taken before the path is decoded and normalized,
    /// so `..` is judged inside the drive and can never climb into another
    /// one: a path that tries is malformed, not a different drive.
    fn path_addressed(raw_public_key: &str, raw_storage_path: &str) -> Result<Self, String> {
        let public_key = PublicKey::try_from_z32(raw_public_key)
            .map_err(|_| "Invalid storage owner public key".to_string())?;
        let decoded_path = percent_decode_str(raw_storage_path)
            .decode_utf8()
            .map_err(|_| "Storage path is not valid UTF-8".to_string())?;
        let storage_path = StoragePath::normalize(&format!("/{decoded_path}"))
            .map_err(|error| format!("Invalid storage path: {error}"))?;

        Ok(Self {
            public_key,
            storage_path: Some(storage_path),
        })
    }

    pub(crate) async fn resolve(request: Request, next: Next) -> Response {
        Self::run_resolved(Self::from_request(&request), request, next).await
    }

    /// [`Self::resolve`] for the `/dav` routes, which are all path-addressed.
    pub(crate) async fn resolve_dav(request: Request, next: Next) -> Response {
        let tenant = Self::from_dav_route(request.uri().path()).map(Some);
        Self::run_resolved(tenant, request, next).await
    }

    async fn run_resolved(
        tenant: Result<Option<Self>, String>,
        mut request: Request,
        next: Next,
    ) -> Response {
        match tenant {
            Ok(Some(tenant)) => {
                request.extensions_mut().insert(tenant);
                next.run(request).await
            }
            Ok(None) => next.run(request).await,
            Err(message) => {
                // Tenant-aware limits require a resolved owner; malformed requests are
                // rejected before authentication and storage access.
                tracing::warn!(
                    method = %request.method(),
                    path = request.uri().path(),
                    error = %message,
                    "Failed to resolve request tenant"
                );
                (StatusCode::BAD_REQUEST, message).into_response()
            }
        }
    }

    pub(crate) fn legacy(public_key: PublicKey) -> Self {
        Self {
            public_key,
            storage_path: None,
        }
    }

    /// A request that targets `storage_path` without naming it in the URL,
    /// such as a website page.
    pub(crate) fn mapped(public_key: PublicKey, storage_path: StoragePath) -> Self {
        Self {
            public_key,
            storage_path: Some(storage_path),
        }
    }
}

impl<S> FromRequestParts<S> for RequestTenant
where
    S: Sync + Send,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<RequestTenant>()
            .cloned()
            .ok_or_else(|| HttpError::bad_request("Missing request tenant").into_response())
    }
}

impl<S> FromRequestParts<S> for EntryPath
where
    S: Sync + Send,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let tenant = parts
            .extensions
            .get::<RequestTenant>()
            .ok_or_else(|| HttpError::bad_request("Missing request tenant").into_response())?;
        let path = tenant
            .storage_path()
            .cloned()
            .ok_or_else(|| HttpError::bad_request("Missing storage path").into_response())?;

        Ok(EntryPath::new(tenant.public_key().clone(), path))
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use pubky_common::crypto::Keypair;

    use super::*;

    #[test]
    fn path_addressing_extracts_owner_and_storage_path() {
        let owner = Keypair::random().public_key();
        let path = format!("/storage/{}/pub/example.txt", owner.z32());
        let tenant = RequestTenant::from_storage_route(&path).unwrap().unwrap();

        assert_eq!(tenant.public_key(), &owner);
        assert_eq!(tenant.storage_path().unwrap().as_str(), "/pub/example.txt");
        assert_eq!(
            tenant.pubky_url(&format!("{path}?limit=10").parse().unwrap()),
            format!("pubky://{}/pub/example.txt?limit=10", owner.z32())
        );
    }

    #[test]
    fn path_addressing_rejects_display_and_invalid_keys() {
        let owner = Keypair::random().public_key();
        assert!(RequestTenant::from_storage_route(&format!(
            "/storage/pubky{}/pub/example.txt",
            owner.z32()
        ))
        .is_err());
        assert!(RequestTenant::from_storage_route("/storage/short/pub/example.txt").is_err());
        assert!(RequestTenant::from_storage_route(&format!("/storage/{}/", owner.z32())).is_err());
        assert!(RequestTenant::from_storage_route(&format!(
            "/storage/{}/pub/example.txt",
            "0".repeat(52)
        ))
        .is_err());
    }

    #[test]
    fn dav_addressing_extracts_owner_and_storage_path() {
        let owner = Keypair::random().public_key();
        let z32 = owner.z32();

        for (path, expected) in [
            (format!("/dav/{z32}/pub/notes/a.txt"), "/pub/notes/a.txt"),
            (format!("/dav/{z32}/pub/"), "/pub/"),
            // The public folder has one spelling, with its slash.
            (format!("/dav/{z32}/pub"), "/pub/"),
            (format!("/dav/{z32}/pubx"), "/pubx"),
            (format!("/dav/{z32}/pub/docs"), "/pub/docs"),
            (format!("/dav/{z32}/%70ub/./a%20b"), "/pub/a b"),
            // A traversal is judged by where it lands inside the drive.
            (format!("/dav/{z32}/pub/../priv/s.txt"), "/priv/s.txt"),
            (format!("/dav/{z32}/pub/%2e%2e/priv/s.txt"), "/priv/s.txt"),
            // The owner alone names the drive root.
            (format!("/dav/{z32}"), "/"),
            (format!("/dav/{z32}/"), "/"),
        ] {
            let tenant = RequestTenant::from_dav_route(&path).unwrap();
            assert_eq!(tenant.public_key(), &owner, "{path}");
            assert_eq!(tenant.storage_path().unwrap().as_str(), expected, "{path}");
        }
    }

    #[test]
    fn dav_addressing_rejects_paths_that_climb_out_of_their_drive() {
        // The drive is fixed before the path is normalized, so `..` can never
        // reach another drive or the storage root.
        let z32 = Keypair::random().public_key().z32();
        let other = Keypair::random().public_key().z32();

        for path in [
            format!("/dav/{z32}/../{other}/pub/file.txt"),
            format!("/dav/{z32}/../../etc/passwd"),
            format!("/dav/{z32}/pub/%2e%2e/%2e%2e/{other}/pub/x"),
            // An encoded slash does not end the owner segment.
            format!("/dav/{z32}%2Fpub/x"),
        ] {
            assert!(RequestTenant::from_dav_route(&path).is_err(), "{path}");
        }
    }

    #[test]
    fn dav_addressing_rejects_paths_that_name_no_drive() {
        for path in [
            "/storage/whatever",
            "/dav",
            "/dav/",
            "/davos/x",
            "/dav/not-a-pubkey/pub/",
        ] {
            assert!(RequestTenant::from_dav_route(path).is_err(), "{path}");
        }
    }

    #[test]
    fn storage_path_ignores_legacy_tenant_inputs() {
        let path_owner = Keypair::random().public_key();
        let header_owner = Keypair::random().public_key();
        let req = Request::builder()
            .uri(format!(
                "/storage/{}/pub/example.txt?pubky-host={}",
                path_owner.z32(),
                header_owner.z32()
            ))
            .header("host", header_owner.z32())
            .header("pubky-host", "invalid")
            .body(Body::empty())
            .unwrap();

        let tenant = RequestTenant::from_request(&req).unwrap().unwrap();
        assert_eq!(tenant.public_key(), &path_owner);
        assert!(tenant.storage_path().is_some());
    }

    #[test]
    fn non_storage_routes_keep_legacy_resolution() {
        let owner = Keypair::random().public_key();
        let req = Request::builder()
            .uri("/pub/example.txt")
            .header("pubky-host", owner.z32())
            .body(Body::empty())
            .unwrap();

        let tenant = RequestTenant::from_request(&req).unwrap().unwrap();
        assert_eq!(tenant.public_key(), &owner);
        assert!(tenant.storage_path().is_none());
    }
}
