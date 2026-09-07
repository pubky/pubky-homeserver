//! This module provides a WebDAV view with full access to stored files.
//!
//! Empty collections are not persisted, and COPY/MOVE require an absent destination because
//! `dav-server` removes overwrite destinations before invoking the filesystem callback.
//! It is protected by a basic auth header with the username "admin" and the password set in the config.toml file.
//! The password is set in the config.toml file.
use super::super::app_state::AppState;
use crate::admin_server::dav_file_system::AdminDavFileSystem;
use crate::shared::{HttpError, HttpResult};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Method, Response, StatusCode, Uri},
    response::IntoResponse,
};
use axum_extra::headers::{ContentLength, ContentRange, HeaderMapExt};
use base64::Engine;
use dav_server::{davpath::DavPath, DavMethod};
use futures_util::StreamExt;

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
    let method = DavMethod::try_from(req.method()).ok();
    if has_unsupported_mutation_precondition(&req, method) {
        return Ok(Response::builder()
            .status(StatusCode::NOT_IMPLEMENTED)
            .body(Body::from("Conditional WebDAV mutations are not supported"))
            .expect("This response should always be valid"));
    }
    if method == Some(DavMethod::MkCol) {
        return Ok(Response::builder()
            .status(StatusCode::NOT_IMPLEMENTED)
            .body(Body::from("Empty collections are not supported"))
            .expect("This response should always be valid"));
    }
    if matches!(method, Some(DavMethod::Copy | DavMethod::Move)) {
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

    let expected_length = if matches!(method, Some(DavMethod::Put | DavMethod::Patch)) {
        expected_upload_length(req.headers())?
    } else {
        None
    };
    let mut dav_response = if let Some(mut remaining) = expected_length {
        let (parts, body) = req.into_parts();
        let mut body = body.into_data_stream();
        let mut invalid_length = false;
        let invalid_length_ref = &mut invalid_length;
        // dav-server flushes before checking the final length. Fail the body stream first
        // so a rejected upload cannot reach storage publication.
        let stream = async_stream::stream! {
            loop {
                match body.next().await {
                    Some(Ok(chunk)) if chunk.len() as u64 <= remaining => {
                        remaining -= chunk.len() as u64;
                        yield Ok(chunk);
                    }
                    None if remaining == 0 => break,
                    Some(Err(error)) => {
                        yield Err(error);
                        break;
                    }
                    _ => {
                        *invalid_length_ref = true;
                        yield Err(axum::Error::new("DAV upload length mismatch"));
                        break;
                    }
                }
            }
        };
        let mut response = state
            .inner_dav_handler
            .handle_stream(Request::from_parts(parts, stream))
            .await;
        if invalid_length {
            *response.status_mut() = StatusCode::BAD_REQUEST;
        }
        response
    } else {
        state.inner_dav_handler.handle(req).await
    };
    let status = normalize_dav_status(method, dav_response.status());
    *dav_response.status_mut() = status;
    Ok(dav_response.into_response())
}

fn expected_upload_length(headers: &axum::http::HeaderMap) -> HttpResult<Option<u64>> {
    let range_length = headers
        .typed_get::<ContentRange>()
        .and_then(|range| range.bytes_range())
        .map(|(start, end)| {
            end.checked_sub(start)
                .and_then(|length| length.checked_add(1))
                .ok_or_else(|| HttpError::bad_request("Invalid Content-Range length"))
        })
        .transpose()?;
    Ok(headers
        .typed_get::<ContentLength>()
        .map(|length| length.0)
        .or_else(|| {
            headers
                .get("X-Expected-Entity-Length")?
                .to_str()
                .ok()?
                .parse()
                .ok()
        })
        .or(range_length))
}

fn normalize_dav_status(method: Option<DavMethod>, status: StatusCode) -> StatusCode {
    match (method, status) {
        (Some(DavMethod::Put), StatusCode::METHOD_NOT_ALLOWED) => StatusCode::CONFLICT,
        (Some(DavMethod::Copy | DavMethod::Move), StatusCode::METHOD_NOT_ALLOWED) => {
            StatusCode::PRECONDITION_FAILED
        }
        (Some(DavMethod::Put | DavMethod::Patch), StatusCode::PAYLOAD_TOO_LARGE) => {
            StatusCode::BAD_REQUEST
        }
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

fn has_unsupported_mutation_precondition(
    request: &Request<Body>,
    method: Option<DavMethod>,
) -> bool {
    let is_mutation = matches!(
        method,
        Some(
            DavMethod::Put
                | DavMethod::Patch
                | DavMethod::Delete
                | DavMethod::Copy
                | DavMethod::Move
                | DavMethod::PropPatch
        )
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

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_dav_upload_length_validation_precedes_publication() {
        use crate::shared::webdav::{EntryPath, StoragePath};
        use bytes::Bytes;

        let context = crate::AppContext::test().await;
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let auth = base64::engine::general_purpose::STANDARD.encode(format!(
            "admin:{}",
            context.config_toml.admin.admin_password
        ));
        let headers = [
            (Method::PUT, "X-Expected-Entity-Length", "5"),
            (Method::PUT, "Content-Length", "5"),
            (Method::PUT, "Content-Range", "bytes 0-4/*"),
            (Method::PATCH, "X-Expected-Entity-Length", "5"),
        ];
        for (index, (method, header, value)) in headers.into_iter().enumerate() {
            for existing in [false, true] {
                let path = EntryPath::new(
                    public_key.clone(),
                    StoragePath::new(&format!("/pub/upload-{index}-{existing}.bin")).unwrap(),
                );
                if existing {
                    context
                        .file_service
                        .write(&path, opendal::Buffer::from(b"original".to_vec()))
                        .await
                        .unwrap();
                }
                for (chunks, valid) in [
                    (vec!["first", "extra"], false),
                    (vec!["four"], false),
                    (vec!["fi", "rst"], true),
                ] {
                    let stream = futures_util::stream::iter(chunks.into_iter().map(|chunk| {
                        Ok::<_, std::io::Error>(Bytes::from_static(chunk.as_bytes()))
                    }));
                    let mut request = Request::builder()
                        .method(method.clone())
                        .uri(format!("/dav/{}{}", public_key.z32(), path.path()))
                        .header("Authorization", format!("Basic {auth}"))
                        .header(header, value);
                    if method == Method::PATCH {
                        request = request
                            .header("Content-Type", "application/x-sabredav-partialupdate")
                            .header("X-Update-Range", "bytes=0-4");
                    }
                    let request = request.body(Body::from_stream(stream)).unwrap();
                    let response = dav_handler(State(AppState::new(context.clone())), request)
                        .await
                        .unwrap()
                        .into_response();
                    assert_eq!(response.status().is_success(), valid, "{header}");
                    if !valid {
                        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                    }
                    match context.file_service.get(&path).await {
                        Ok(content) => {
                            assert!(existing || valid);
                            let expected: &[u8] = if !valid {
                                b"original"
                            } else if existing
                                && (header == "Content-Range" || method == Method::PATCH)
                            {
                                b"firstnal"
                            } else {
                                b"first"
                            };
                            assert_eq!(content.as_ref(), expected);
                        }
                        Err(crate::persistence::files::FileIoError::NotFound) => {
                            assert!(!existing && !valid);
                        }
                        Err(error) => panic!("unexpected storage error: {error}"),
                    }
                }
            }
        }
        let path = EntryPath::new(
            public_key.clone(),
            StoragePath::new("/pub/overflow").unwrap(),
        );
        let request = Request::builder()
            .method(Method::PUT)
            .uri(format!("/dav/{}{}", public_key.z32(), path.path()))
            .header("Authorization", format!("Basic {auth}"))
            .header("Content-Range", "bytes 0-18446744073709551615/*")
            .body(Body::from("first"))
            .unwrap();
        let response = dav_handler(State(AppState::new(context.clone())), request)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(matches!(
            context.file_service.get(&path).await,
            Err(crate::persistence::files::FileIoError::NotFound)
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_dav_chunked_upload_and_body_error() {
        use crate::shared::webdav::{EntryPath, StoragePath};
        use bytes::Bytes;

        let context = crate::AppContext::test().await;
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let auth = base64::engine::general_purpose::STANDARD.encode(format!(
            "admin:{}",
            context.config_toml.admin.admin_password
        ));
        let path = EntryPath::new(
            public_key.clone(),
            StoragePath::new("/pub/chunked").unwrap(),
        );
        for fail in [false, true] {
            let mut chunks = vec![Ok(Bytes::from_static(b"first"))];
            let mut request = Request::builder()
                .method(Method::PUT)
                .uri(format!("/dav/{}{}", public_key.z32(), path.path()))
                .header("Authorization", format!("Basic {auth}"));
            if fail {
                request = request.header("X-Expected-Entity-Length", "5");
                chunks.push(Err(std::io::Error::other("interrupted upload")));
            } else {
                chunks.push(Ok(Bytes::from_static(b"second")));
            }
            let request = request
                .body(Body::from_stream(futures_util::stream::iter(chunks)))
                .unwrap();
            let response = dav_handler(State(AppState::new(context.clone())), request)
                .await
                .unwrap()
                .into_response();
            assert_eq!(
                response.status(),
                if fail {
                    StatusCode::BAD_GATEWAY
                } else {
                    StatusCode::CREATED
                }
            );
            assert_eq!(
                context.file_service.get(&path).await.unwrap().as_ref(),
                b"firstsecond"
            );
        }
    }

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
            normalize_dav_status(Some(DavMethod::Put), StatusCode::METHOD_NOT_ALLOWED),
            StatusCode::CONFLICT
        );
        assert_eq!(
            normalize_dav_status(Some(DavMethod::Patch), StatusCode::PAYLOAD_TOO_LARGE),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            normalize_dav_status(Some(DavMethod::Copy), StatusCode::METHOD_NOT_ALLOWED),
            StatusCode::PRECONDITION_FAILED
        );
    }
}
