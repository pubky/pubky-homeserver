//! This module provides a webdav endpoint that gives full access to all files.
//! It is protected by a basic auth header with the username "admin" and the password set in the config.toml file.
//! The password is set in the config.toml file.
use super::super::app_state::AppState;
use crate::shared::HttpResult;
use axum::{
    body::Body,
    extract::{Request, State},
    http::Response,
    response::IntoResponse,
};
use base64::Engine;

pub async fn dav_handler(
    State(state): State<AppState>,
    req: Request<Body>,
) -> HttpResult<impl IntoResponse> {
    if !is_valid_authorization_header(req.headers(), state.admin_password()) {
        return Ok(Response::builder()
            .status(401)
            .header("WWW-Authenticate", "Basic") // This header will trigger the browser to show the login dialog
            .body(Body::from("Unauthorized"))
            .expect("This response should always be valid"));
    }

    let dav_response = state.inner_dav_handler.handle(req).await;
    Ok(dav_response.into_response())
}

/// Validate if the authorization header is correct.
/// It must be a basic auth header with the username "admin" and the given password
fn is_valid_authorization_header(headers: &axum::http::HeaderMap, should_password: &str) -> bool {
    let auth_header_raw = match headers.get("Authorization") {
        Some(authorization) => authorization,
        None => return false,
    };
    let auth_header = match auth_header_raw.to_str() {
        Ok(auth_header) => auth_header,
        Err(_) => {
            // Not string parsable, so we can't use it
            return false;
        }
    };
    is_valid_authorization_header_str(auth_header, should_password)
}

/// Validate that the authorization header is valid.
/// It must be a basic auth header with the username "admin" and the given password
fn is_valid_authorization_header_str(auth_header: &str, should_password: &str) -> bool {
    // Check if the header starts with "Basic "
    if !auth_header.starts_with("Basic ") {
        return false;
    }

    // Get the base64 encoded part after "Basic "
    let base64_encoded = match auth_header.strip_prefix("Basic ") {
        Some(encoded) => encoded,
        None => return false,
    };

    // Decode the base64 string
    let decoded = match base64::engine::general_purpose::STANDARD.decode(base64_encoded) {
        Ok(decoded) => decoded,
        Err(_) => return false,
    };

    // Convert the decoded bytes to a string
    let decoded_str = match String::from_utf8(decoded) {
        Ok(str) => str,
        Err(_) => return false,
    };

    // Split the decoded string into username and password
    let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        return false;
    }

    // Check if username is "admin" and password matches
    parts[0] == "admin" && parts[1] == should_password
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_authorization_header() {
        let valid_auth = "Basic YWRtaW46cGFzc3dvcmQ="; // base64("admin:password")
        assert!(
            is_valid_authorization_header_str(valid_auth, "password"),
            "Valid authorization header should be valid"
        );

        assert!(
            !is_valid_authorization_header_str("NotBasic YWRtaW46cGFzc3dvcmQ=", "password"),
            "Invalid format should be invalid"
        );
        assert!(
            !is_valid_authorization_header_str("Basic", "password"),
            "Invalid format should be invalid"
        );

        assert!(
            !is_valid_authorization_header_str("Basic invalid-base64", "password"),
            "Invalid base64 should be invalid"
        );

        let wrong_username = "Basic dXNlcjpwYXNzd29yZA=="; // base64("user:password")
        assert!(
            !is_valid_authorization_header_str(wrong_username, "password"),
            "Wrong username should be invalid"
        );

        let wrong_password = "Basic YWRtaW46d3JvbmctcGFzc3dvcmQ="; // base64("admin:wrong-password")
        assert!(
            !is_valid_authorization_header_str(wrong_password, "password"),
            "Wrong password should be invalid"
        );

        let malformed = "Basic YWRtaW4="; // base64("admin") - missing password
        assert!(
            !is_valid_authorization_header_str(malformed, "password"),
            "Malformed credentials should be invalid"
        );
    }
}
