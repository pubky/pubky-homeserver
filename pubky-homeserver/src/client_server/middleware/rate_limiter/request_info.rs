//! Pre-extracted request metadata for the rate limiter.
//!
//! Extracts authentication status, method, user pubkey, and client IP
//! from a request so that async bandwidth resolution doesn't need to
//! hold a borrow on the `!Send` `Request<Body>`.

use axum::body::Body;
use axum::http::{Method, Request};

use crate::client_server::auth::AuthSession;

use super::extract_ip::{extract_ip, MissingClientAddress};

/// Pre-extracted request metadata so that `resolve_bandwidth_throttlers`
/// does not need to borrow the `!Send` `Request<Body>` across `.await`.
pub(super) struct RequestInfo {
    pub method: Method,
    pub user_pubkey: Option<pubky_common::crypto::PublicKey>,
    pub client_ip: Result<std::net::IpAddr, MissingClientAddress>,
}

impl RequestInfo {
    pub fn from_request(req: &Request<Body>) -> Self {
        Self {
            method: req.method().clone(),
            user_pubkey: authenticated_pubkey(req),
            client_ip: extract_ip(req),
        }
    }
}

fn authenticated_pubkey(req: &Request<Body>) -> Option<pubky_common::crypto::PublicKey> {
    req.extensions()
        .get::<AuthSession>()
        .map(|session| session.user_key().clone())
}

/// Returns true for HTTP methods that represent writes (uploads).
pub(super) fn is_write_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::PUT | Method::POST | Method::PATCH | Method::DELETE
    )
}
