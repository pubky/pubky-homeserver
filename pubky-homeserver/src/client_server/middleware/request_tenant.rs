//! Resolve the tenant targeted by a client-server request.
//!
//! Storage requests carry their owner in `/storage/{owner}/...`.
//! Other requests retain the legacy Host / `pubky-host` compatibility lookup.

use axum::{
    extract::{FromRequestParts, Request},
    http::{request::Parts, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use percent_encoding::percent_decode_str;
use pubky_common::crypto::PublicKey;

use crate::shared::{
    webdav::{EntryPath, StoragePath},
    HttpError,
};

use super::pubky_host::extract_legacy_pubky;

const STORAGE_ROUTE_PREFIX: &str = "/storage/";

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

        let public_key = PublicKey::try_from_z32(raw_public_key)
            .map_err(|_| "Invalid storage owner public key".to_string())?;
        let decoded_path = percent_decode_str(raw_storage_path)
            .decode_utf8()
            .map_err(|_| "Storage path is not valid UTF-8".to_string())?;
        let storage_path = StoragePath::normalize(&format!("/{decoded_path}"))
            .map_err(|error| format!("Invalid storage path: {error}"))?;

        Ok(Some(Self {
            public_key,
            storage_path: Some(storage_path),
        }))
    }

    pub(crate) async fn resolve(mut request: Request, next: Next) -> Response {
        match Self::from_request(&request) {
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
