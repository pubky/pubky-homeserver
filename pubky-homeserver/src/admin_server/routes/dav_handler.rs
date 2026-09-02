//! This module provides a WebDAV view with full access to stored files.
//!
//! Empty collections are not persisted, and COPY/MOVE require an absent destination because
//! `dav-server` removes overwrite destinations before invoking the filesystem callback.
//! It is protected by a basic auth header with the username "admin" and the password set in the config.toml file.
//! The password is set in the config.toml file.
use super::super::app_state::AppState;
use crate::admin_server::dav_file_system::AdminDavFileSystem;
use crate::shared::HttpResult;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Method, Response, StatusCode, Uri},
    response::IntoResponse,
};
use base64::Engine;
use dav_server::davpath::DavPath;

pub async fn dav_handler(
    State(state): State<AppState>,
    mut req: Request<Body>,
) -> HttpResult<impl IntoResponse> {
    if !is_valid_authorization_header(req.headers(), state.admin_password()) {
        return Ok(Response::builder()
            .status(401)
            .header("WWW-Authenticate", "Basic") // This header will trigger the browser to show the login dialog
            .body(Body::from("Unauthorized"))
            .expect("This response should always be valid"));
    }
    if is_protected_collection_delete(&req) {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("User collections cannot be deleted"))
            .expect("This response should always be valid"));
    }
    if has_unsupported_mutation_precondition(&req) {
        return Ok(Response::builder()
            .status(StatusCode::NOT_IMPLEMENTED)
            .body(Body::from("Conditional WebDAV mutations are not supported"))
            .expect("This response should always be valid"));
    }
    if req.method().as_str() == "MKCOL" {
        return Ok(Response::builder()
            .status(StatusCode::NOT_IMPLEMENTED)
            .body(Body::from("Empty collections are not supported"))
            .expect("This response should always be valid"));
    }
    if matches!(req.method().as_str(), "COPY" | "MOVE") {
        if copy_move_source_equals_destination(&req) {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Source and destination must differ"))
                .expect("This response should always be valid"));
        }
        if copy_move_destination_is_protected(&req) {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("User collections cannot be overwritten"))
                .expect("This response should always be valid"));
        }
        if let Some(status) =
            unsupported_collection_source_status(&state, req.uri().clone()).await?
        {
            return Ok(Response::builder()
                .status(status)
                .body(Body::from(if status == StatusCode::NOT_FOUND {
                    "Source collection not found"
                } else {
                    "Empty collections are not supported"
                }))
                .expect("This response should always be valid"));
        }
        // dav-server removes overwrite destinations before invoking the filesystem.
        // Requiring a missing destination prevents destructive pre-deletion.
        req.headers_mut()
            .insert("Overwrite", HeaderValue::from_static("F"));
    }

    let request_method = req.method().clone();
    let mut dav_response = state.inner_dav_handler.handle(req).await;
    let status = normalize_dav_status(&request_method, dav_response.status());
    *dav_response.status_mut() = status;
    Ok(dav_response.into_response())
}

fn normalize_dav_status(method: &Method, status: StatusCode) -> StatusCode {
    match (method, status) {
        (&Method::PUT, StatusCode::METHOD_NOT_ALLOWED) => StatusCode::CONFLICT,
        (method, StatusCode::METHOD_NOT_ALLOWED) if matches!(method.as_str(), "COPY" | "MOVE") => {
            StatusCode::PRECONDITION_FAILED
        }
        (&Method::PUT | &Method::PATCH, StatusCode::PAYLOAD_TOO_LARGE) => StatusCode::BAD_REQUEST,
        _ => status,
    }
}

async fn unsupported_collection_source_status(
    state: &AppState,
    uri: Uri,
) -> Result<Option<StatusCode>, crate::persistence::files::FileIoError> {
    let Ok(mut path) = DavPath::new(uri.path()) else {
        return Ok(None);
    };
    if path.set_prefix("/dav").is_err() {
        return Ok(None);
    }
    let Ok(entry_path) = AdminDavFileSystem::directory_entry_path(&path) else {
        return Ok(None);
    };
    if state
        .context
        .file_service
        .contains_directory(&entry_path)
        .await?
    {
        return Ok(None);
    }
    if entry_path.path().as_str() == "/" {
        let user_exists = match state.context.user_service.get(entry_path.pubkey()).await {
            Ok(_) => true,
            Err(sqlx::Error::RowNotFound) => false,
            Err(error) => return Err(error.into()),
        };
        return Ok(Some(if user_exists {
            StatusCode::CONFLICT
        } else {
            StatusCode::NOT_FOUND
        }));
    }
    match state
        .context
        .file_service
        .get_info(&entry_path, &mut state.context.sql_db.pool().into())
        .await
    {
        Ok(_) => Ok(None),
        Err(crate::persistence::files::FileIoError::NotFound) => Ok(Some(StatusCode::NOT_FOUND)),
        Err(error) => Err(error),
    }
}

fn has_unsupported_mutation_precondition(request: &Request<Body>) -> bool {
    let is_mutation = matches!(
        request.method().as_str(),
        "PUT" | "PATCH" | "DELETE" | "COPY" | "MOVE" | "PROPPATCH"
    );
    is_mutation
        && ["if", "if-match", "if-none-match", "if-unmodified-since"]
            .iter()
            .any(|header| request.headers().contains_key(*header))
}

fn copy_move_destination_is_protected(request: &Request<Body>) -> bool {
    let Some(destination) = request
        .headers()
        .get("Destination")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Ok(uri) = destination.parse::<Uri>() else {
        return false;
    };
    is_protected_dav_collection(&uri)
}

fn copy_move_source_equals_destination(request: &Request<Body>) -> bool {
    let Some(destination) = request
        .headers()
        .get("Destination")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Uri>().ok())
    else {
        return false;
    };
    normalized_dav_path(request.uri())
        .zip(normalized_dav_path(&destination))
        .is_some_and(|(source, destination)| source == destination)
}

fn normalized_dav_path(uri: &Uri) -> Option<Vec<u8>> {
    let mut path = DavPath::new(uri.path()).ok()?;
    path.set_prefix("/dav").ok()?;
    Some(path.as_bytes().to_vec())
}

fn is_protected_collection_delete(request: &Request<Body>) -> bool {
    if request.method() != Method::DELETE {
        return false;
    }
    is_protected_dav_collection(request.uri())
}

fn is_protected_dav_collection(uri: &Uri) -> bool {
    let Ok(mut path) = DavPath::new(uri.path()) else {
        return false;
    };
    if path.set_prefix("/dav").is_err() {
        return false;
    }
    let Ok(path) = String::from_utf8(path.as_bytes().to_vec()) else {
        return false;
    };
    let relative = path.trim_matches('/');
    relative.is_empty() || !relative.contains('/')
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

    #[test]
    fn test_protects_dav_root_and_user_collections_from_delete() {
        for path in ["/dav/", "/dav/pubky-user", "/dav/pubky-user/"] {
            let request = Request::builder()
                .method(Method::DELETE)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            assert!(is_protected_collection_delete(&request));
        }
        let request = Request::builder()
            .method(Method::DELETE)
            .uri("/dav/pubky-user/pub/")
            .body(Body::empty())
            .unwrap();
        assert!(!is_protected_collection_delete(&request));
    }

    #[test]
    fn test_normalizes_dav_storage_errors() {
        assert_eq!(
            normalize_dav_status(&Method::PUT, StatusCode::METHOD_NOT_ALLOWED),
            StatusCode::CONFLICT
        );
        assert_eq!(
            normalize_dav_status(&Method::PATCH, StatusCode::PAYLOAD_TOO_LARGE),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            normalize_dav_status(
                &Method::from_bytes(b"COPY").unwrap(),
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            StatusCode::PRECONDITION_FAILED
        );
    }
}
