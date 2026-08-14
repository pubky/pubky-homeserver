//! Legacy tenant identification from HTTP headers and query parameters.
//!
//! New storage routes identify the tenant in the URL path. This module keeps
//! the compatibility resolver isolated for owner-relative legacy routes and
//! cookie-session endpoints.

use axum::{body::Body, http::Request};
use pubky_common::crypto::PublicKey;

/// Extracts a PublicKey by checking, in order:
/// 1. The "host" header.
/// 2. The "pubky-host" header (which overwrites any previously found key).
/// 3. The query parameter "pubky-host" if none was found in headers.
pub(crate) fn extract_legacy_pubky(req: &Request<Body>) -> Option<PublicKey> {
    let mut pubky = None;
    // Check headers in order: "host" then "pubky-host".
    for header in ["host", "pubky-host"].iter() {
        if let Some(val) = req.headers().get(*header) {
            if let Ok(s) = val.to_str() {
                if PublicKey::is_pubky_prefixed(s) {
                    continue;
                }
                if let Ok(key) = PublicKey::try_from_z32(s) {
                    pubky = Some(key);
                }
            }
        }
    }
    // If still no key, fall back to query parameter.
    if pubky.is_none() {
        pubky = req.uri().query().and_then(|query| {
            query.split('&').find_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                if let (Some(key), Some(val)) = (parts.next(), parts.next()) {
                    if key == "pubky-host" {
                        if PublicKey::is_pubky_prefixed(val) {
                            return None;
                        }
                        return PublicKey::try_from_z32(val).ok();
                    }
                }
                None
            })
        });
    }
    pubky
}
