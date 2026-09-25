use axum::http::{header, HeaderMap};

use crate::client_server::auth::grant::crypto::session_token::SessionBearer;

pub(crate) enum BearerTokenExtraction {
    Present(SessionBearer),
    InvalidBearer,
    NonBearer,
    Missing,
}

impl BearerTokenExtraction {
    pub(crate) fn has_bearer_scheme(&self) -> bool {
        matches!(self, Self::Present(_) | Self::InvalidBearer)
    }
}

pub(crate) fn extract_bearer_token(headers: &HeaderMap) -> BearerTokenExtraction {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return BearerTokenExtraction::Missing;
    };

    let Some(raw_token) = value.as_bytes().strip_prefix(b"Bearer ") else {
        return BearerTokenExtraction::NonBearer;
    };
    let Ok(raw_token) = std::str::from_utf8(raw_token) else {
        return BearerTokenExtraction::InvalidBearer;
    };

    match SessionBearer::parse(raw_token) {
        Ok(bearer) => BearerTokenExtraction::Present(bearer),
        Err(_) => BearerTokenExtraction::InvalidBearer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const UNKNOWN_WELL_FORMED_BEARER: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

    fn headers(value: HeaderValue) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, value);
        headers
    }

    fn extraction_name(actual: &BearerTokenExtraction) -> &'static str {
        match actual {
            BearerTokenExtraction::Present(_) => "present",
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
        ];

        for (headers, expected, has_bearer_scheme) in cases {
            let actual = extract_bearer_token(&headers);
            assert_eq!(extraction_name(&actual), expected);
            assert_eq!(actual.has_bearer_scheme(), has_bearer_scheme);
        }
    }
}
