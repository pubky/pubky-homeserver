//! `Authorization` header parsing for grant sessions.
//!
//! Two schemes carry the same opaque session bearer:
//! - `Bearer <token>` — what the Pubky SDK sends.
//! - `Basic base64(username:<token>)` — what standard WebDAV clients
//!   (Finder, Nautilus, rclone) send, since they speak only Basic auth. The
//!   username is ignored: identity comes from the token itself.

use base64::{engine::general_purpose::STANDARD, Engine};

use axum::http::{header, HeaderMap};

use crate::client_server::auth::grant::crypto::session_token::SessionBearer;

/// Which `Authorization` scheme carried the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scheme {
    Bearer,
    Basic,
}

pub(crate) enum BearerTokenExtraction {
    Present(SessionBearer, Scheme),
    InvalidBearer,
    NonBearer,
    Missing,
}

impl BearerTokenExtraction {
    /// Whether the client presented the `Bearer` scheme specifically.
    ///
    /// A token carried by `Basic` deliberately does **not** count. The event
    /// stream uses this to decide whether to stop falling back to cookie auth,
    /// and a `Basic` header is not that signal — it is what a WebDAV client
    /// sends because it can send nothing else. Counting it would silently
    /// change `/events-stream` for any caller whose Basic password happened to
    /// be bearer-shaped.
    pub(crate) fn has_bearer_scheme(&self) -> bool {
        matches!(self, Self::Present(_, Scheme::Bearer) | Self::InvalidBearer)
    }
}

pub(crate) fn extract_bearer_token(headers: &HeaderMap) -> BearerTokenExtraction {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return BearerTokenExtraction::Missing;
    };
    let value = value.as_bytes();

    if let Some(raw_token) = value.strip_prefix(b"Bearer ") {
        return from_bearer_scheme(raw_token);
    }
    if let Some(credentials) = value.strip_prefix(b"Basic ") {
        return from_basic_scheme(credentials);
    }
    BearerTokenExtraction::NonBearer
}

/// The rest of a `Bearer <token>` header is the session bearer verbatim, so a
/// malformed one is a malformed bearer.
fn from_bearer_scheme(raw_token: &[u8]) -> BearerTokenExtraction {
    let Ok(raw_token) = std::str::from_utf8(raw_token) else {
        return BearerTokenExtraction::InvalidBearer;
    };

    match SessionBearer::parse(raw_token) {
        Ok(bearer) => BearerTokenExtraction::Present(bearer, Scheme::Bearer),
        Err(_) => BearerTokenExtraction::InvalidBearer,
    }
}

/// The password half of `Basic base64(username:password)` carries the session
/// bearer. Anything that does not decode into one is `NonBearer` rather than
/// `InvalidBearer`: Basic auth has other legitimate users on this server, so a
/// password that is not a bearer should still fall through to cookie auth.
fn from_basic_scheme(credentials: &[u8]) -> BearerTokenExtraction {
    let Ok(decoded) = STANDARD.decode(credentials) else {
        return BearerTokenExtraction::NonBearer;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return BearerTokenExtraction::NonBearer;
    };
    let Some((_username, password)) = decoded.split_once(':') else {
        return BearerTokenExtraction::NonBearer;
    };

    match SessionBearer::parse(password) {
        Ok(bearer) => BearerTokenExtraction::Present(bearer, Scheme::Basic),
        Err(_) => BearerTokenExtraction::NonBearer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const UNKNOWN_WELL_FORMED_BEARER: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

    fn basic_credentials(username: &str, password: &str) -> String {
        STANDARD.encode(format!("{username}:{password}"))
    }

    fn headers(value: HeaderValue) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, value);
        headers
    }

    fn extraction_name(actual: &BearerTokenExtraction) -> &'static str {
        match actual {
            BearerTokenExtraction::Present(..) => "present",
            BearerTokenExtraction::InvalidBearer => "invalid_bearer",
            BearerTokenExtraction::NonBearer => "non_bearer",
            BearerTokenExtraction::Missing => "missing",
        }
    }

    #[test]
    fn extract_bearer_token_classifies_authorization_header() {
        let cases = [
            (HeaderMap::new(), "missing", false),
            (
                headers(HeaderValue::from_static("Basic dXNlcjpwYXNz")),
                "non_bearer",
                false,
            ),
            (
                headers(HeaderValue::from_static("Bearer ")),
                "invalid_bearer",
                true,
            ),
            (
                headers(HeaderValue::from_bytes(b"Bearer \xff").expect("valid header bytes")),
                "invalid_bearer",
                true,
            ),
            (
                headers(
                    HeaderValue::from_str(&format!("Bearer {UNKNOWN_WELL_FORMED_BEARER}"))
                        .expect("valid header"),
                ),
                "present",
                true,
            ),
            // WebDAV clients send the bearer as the Basic password.
            (
                headers(
                    HeaderValue::from_str(&format!(
                        "Basic {}",
                        basic_credentials("user", UNKNOWN_WELL_FORMED_BEARER)
                    ))
                    .expect("valid header"),
                ),
                "present",
                false,
            ),
            // An empty username is what a client that only knows the token sends.
            (
                headers(
                    HeaderValue::from_str(&format!(
                        "Basic {}",
                        basic_credentials("", UNKNOWN_WELL_FORMED_BEARER)
                    ))
                    .expect("valid header"),
                ),
                "present",
                false,
            ),
            // A password that is not a bearer must still fall through to cookie auth.
            (
                headers(
                    HeaderValue::from_str(&format!("Basic {}", basic_credentials("user", "pass")))
                        .expect("valid header"),
                ),
                "non_bearer",
                false,
            ),
            (
                headers(HeaderValue::from_static("Basic not-base64!")),
                "non_bearer",
                false,
            ),
            (
                headers(
                    HeaderValue::from_str(&format!(
                        "Basic {}",
                        STANDARD.encode("no-colon-separator")
                    ))
                    .expect("valid header"),
                ),
                "non_bearer",
                false,
            ),
        ];

        for (headers, expected, has_bearer_scheme) in cases {
            let actual = extract_bearer_token(&headers);
            assert_eq!(extraction_name(&actual), expected);
            assert_eq!(actual.has_bearer_scheme(), has_bearer_scheme);
        }
    }
}
