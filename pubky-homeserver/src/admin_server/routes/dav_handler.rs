//! This module provides a WebDAV view with full access to stored files.
//!
//! Empty collections are not persisted, and COPY/MOVE require an absent destination because
//! `dav-server` removes overwrite destinations before invoking the filesystem callback.
//! It is protected by a basic auth header with the username "admin" and the password set in the config.toml file.
//! The password is set in the config.toml file.
use super::super::app_state::AppState;
use crate::admin_server::dav_file_system::{AdminDavFileSystem, AdminDavMetadata};
use crate::persistence::files::{FileIoError, WriteStreamError};
use crate::shared::HttpResult;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderValue, Method, Response, StatusCode, Uri},
    response::IntoResponse,
};
use axum_extra::headers::{ContentLength, HeaderMapExt, LastModified};
use base64::Engine;
use dav_server::{
    davpath::{DavPath, ParseError},
    fs::{DavMetaData, FsError},
    DavMethod,
};
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

    if method == Some(DavMethod::Put) {
        let result = if has_partial_upload_headers(req.headers()) {
            Err(StatusCode::NOT_IMPLEMENTED)
        } else {
            put_stream(&state, req).await
        };
        return Ok(result.unwrap_or_else(|status| {
            Response::builder()
                .status(status)
                .header(header::CONTENT_LENGTH, "0")
                .header(header::CONNECTION, "close")
                .body(Body::empty())
                .expect("This response should always be valid")
        }));
    }

    let mut dav_response = state.inner_dav_handler.handle(req).await;
    *dav_response.status_mut() = normalize_dav_status(method, dav_response.status());
    Ok(dav_response.into_response())
}

fn has_partial_upload_headers(headers: &axum::http::HeaderMap) -> bool {
    headers.contains_key(header::CONTENT_RANGE)
        || headers.contains_key("X-Update-Range")
        || headers.get(header::CONTENT_TYPE).is_some_and(|value| {
            value.to_str().is_ok_and(|value| {
                value.split(';').next().is_some_and(|mime| {
                    mime.trim()
                        .eq_ignore_ascii_case("application/x-sabredav-partialupdate")
                })
            })
        })
}

async fn put_stream(state: &AppState, req: Request<Body>) -> Result<Response<Body>, StatusCode> {
    let mut path = DavPath::new(req.uri().path()).map_err(|error| match error {
        ParseError::InvalidPath => StatusCode::BAD_REQUEST,
        ParseError::ForbiddenPath => StatusCode::FORBIDDEN,
        ParseError::PrefixMismatch => StatusCode::BAD_GATEWAY,
    })?;
    path.set_prefix("/dav")
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let entry_path = AdminDavFileSystem::file_entry_path(&path).map_err(|error| match error {
        FsError::NotFound | FsError::Exists => StatusCode::CONFLICT,
        FsError::NotImplemented => StatusCode::NOT_IMPLEMENTED,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    })?;
    let expected_length = expected_upload_length(req.headers())?;
    let filesystem = AdminDavFileSystem::new(state.context.file_service.clone());
    let existed = filesystem.metadata_for_path(&path).await.is_ok();
    let mut body = req.into_body().into_data_stream();
    let mut invalid_length = false;
    let invalid_length_ref = &mut invalid_length;
    let mut remaining = expected_length;
    // Publication requires EOF after exactly the declared length. Even a body error
    // after the last expected byte must abort the staged blob.
    let stream = async_stream::stream! {
        while let Some(chunk) = body.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    yield Err(WriteStreamError::Axum(error));
                    return;
                }
            };
            if let Some(left) = remaining.as_mut() {
                let Some(next) = left.checked_sub(chunk.len() as u64) else {
                    *invalid_length_ref = true;
                    yield Err(WriteStreamError::Other(anyhow::anyhow!("DAV upload length mismatch")));
                    return;
                };
                *left = next;
            }
            yield Ok(chunk);
        }
        if remaining.is_some_and(|left| left != 0) {
            *invalid_length_ref = true;
            yield Err(WriteStreamError::Other(anyhow::anyhow!("DAV upload length mismatch")));
        }
    };
    let result = state
        .context
        .file_service
        .admin_write_stream(&entry_path, stream.boxed(), expected_length)
        .await;
    if invalid_length {
        return Err(StatusCode::BAD_REQUEST);
    }
    let entry = result.map_err(|error| match error {
        FileIoError::NotFound
        | FileIoError::SqlDb(sqlx::Error::RowNotFound)
        | FileIoError::PathCollision => StatusCode::CONFLICT,
        FileIoError::DiskSpaceQuotaExceeded => StatusCode::INSUFFICIENT_STORAGE,
        FileIoError::WritePathForbidden => StatusCode::FORBIDDEN,
        FileIoError::StreamBroken(_) => StatusCode::BAD_GATEWAY,
        error => {
            tracing::error!(%error, "Admin DAV upload failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    })?;

    let metadata = AdminDavMetadata::file(&entry);
    let mut response = Response::builder()
        .status(if existed {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::CREATED
        })
        .header(header::ACCEPT_RANGES, "bytes")
        .body(Body::empty())
        .expect("This response should always be valid");
    if !existed {
        response.headers_mut().typed_insert(ContentLength(0));
    }
    if let Some(etag) = metadata.etag() {
        response.headers_mut().insert(
            header::ETAG,
            HeaderValue::from_str(&format!("\"{etag}\""))
                .expect("Base64 entity tags are valid header values"),
        );
    }
    if let Ok(modified) = metadata.modified() {
        response
            .headers_mut()
            .typed_insert(LastModified::from(modified));
    }
    Ok(response)
}

fn expected_upload_length(headers: &axum::http::HeaderMap) -> Result<Option<u64>, StatusCode> {
    let content_length = headers
        .typed_try_get::<ContentLength>()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .map(|length| length.0);
    let expected_length = headers
        .get("X-Expected-Entity-Length")
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(StatusCode::BAD_REQUEST)
        })
        .transpose()?;
    if content_length
        .zip(expected_length)
        .is_some_and(|(length, expected)| length != expected)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(content_length.or(expected_length))
}

fn normalize_dav_status(method: Option<DavMethod>, status: StatusCode) -> StatusCode {
    match (method, status) {
        (Some(DavMethod::Copy | DavMethod::Move), StatusCode::METHOD_NOT_ALLOWED) => {
            StatusCode::PRECONDITION_FAILED
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
    // Only user roots can exist without descendants. Other sources are resolved by DAV.
    if !entry_path.path().is_root()
        || state
            .context
            .file_service
            .contains_directory(&entry_path)
            .await?
    {
        return Ok(None);
    }
    match state.context.user_service.get(entry_path.pubkey()).await {
        Ok(_) => Ok(Some(StatusCode::CONFLICT)),
        Err(sqlx::Error::RowNotFound) => Ok(Some(StatusCode::NOT_FOUND)),
        Err(error) => Err(error.into()),
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
        for (index, header) in ["X-Expected-Entity-Length", "Content-Length"]
            .into_iter()
            .enumerate()
        {
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
                    let request = Request::builder()
                        .method(Method::PUT)
                        .uri(format!("/dav/{}{}", public_key.z32(), path.path()))
                        .header("Authorization", format!("Basic {auth}"))
                        .header(header, "5")
                        .body(Body::from_stream(stream))
                        .unwrap();
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
                            let expected: &[u8] = if !valid { b"original" } else { b"first" };
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
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_dav_rejects_partial_uploads_without_publication() {
        use crate::shared::webdav::{EntryPath, StoragePath};

        let context = crate::AppContext::test().await;
        let public_key = pubky_common::crypto::Keypair::random().public_key();
        context.user_service.create(&public_key).await.unwrap();
        let auth = base64::engine::general_purpose::STANDARD.encode(format!(
            "admin:{}",
            context.config_toml.admin.admin_password
        ));
        let partial_headers = [
            ("Content-Range", "bytes 0-4/*"),
            ("Content-Range", "bytes 0-18446744073709551615/*"),
            ("Content-Range", "invalid"),
            ("X-Update-Range", "bytes=0-4"),
            ("X-Update-Range", "append"),
            ("Content-Type", "application/x-sabredav-partialupdate"),
        ];
        for existing in [false, true] {
            let path = EntryPath::new(
                public_key.clone(),
                StoragePath::new("/pub/partial").unwrap(),
            );
            if existing {
                context
                    .file_service
                    .write(&path, opendal::Buffer::from(b"original".to_vec()))
                    .await
                    .unwrap();
            }
            for method in [Method::PUT, Method::PATCH] {
                for (header, value) in partial_headers {
                    let request = Request::builder()
                        .method(method.clone())
                        .uri(format!("/dav/{}{}", public_key.z32(), path.path()))
                        .header("Authorization", format!("Basic {auth}"))
                        .header(header, value)
                        .body(Body::from("first"))
                        .unwrap();
                    let response = dav_handler(State(AppState::new(context.clone())), request)
                        .await
                        .unwrap()
                        .into_response();
                    assert_eq!(
                        response.status(),
                        if method == Method::PATCH {
                            StatusCode::METHOD_NOT_ALLOWED
                        } else {
                            StatusCode::NOT_IMPLEMENTED
                        },
                        "{method} {header}"
                    );
                    if existing {
                        assert_eq!(
                            context.file_service.get(&path).await.unwrap().as_ref(),
                            b"original"
                        );
                    } else {
                        assert!(matches!(
                            context.file_service.get(&path).await,
                            Err(FileIoError::NotFound)
                        ));
                    }
                }
            }
        }
    }

    #[test]
    fn test_expected_upload_length() {
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(expected_upload_length(&headers), Ok(None));
        headers.insert("X-Expected-Entity-Length", HeaderValue::from_static("5"));
        assert_eq!(expected_upload_length(&headers), Ok(Some(5)));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("5"));
        assert_eq!(expected_upload_length(&headers), Ok(Some(5)));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("4"));
        assert_eq!(
            expected_upload_length(&headers),
            Err(StatusCode::BAD_REQUEST)
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("invalid"));
        assert_eq!(
            expected_upload_length(&headers),
            Err(StatusCode::BAD_REQUEST)
        );
        headers.remove(header::CONTENT_LENGTH);
        headers.insert(
            "X-Expected-Entity-Length",
            HeaderValue::from_static("invalid"),
        );
        assert_eq!(
            expected_upload_length(&headers),
            Err(StatusCode::BAD_REQUEST)
        );
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
        let request = Request::builder()
            .method(Method::PUT)
            .uri(format!("/dav/{}{}", public_key.z32(), path.path()))
            .header("Authorization", format!("Basic {auth}"))
            .body(Body::from_stream(futures_util::stream::iter([
                Ok::<_, std::io::Error>(Bytes::from_static(b"first")),
                Ok(Bytes::from_static(b"second")),
            ])))
            .unwrap();
        let response = dav_handler(State(AppState::new(context.clone())), request)
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);

        for length_header in [
            None,
            Some("Content-Length"),
            Some("X-Expected-Entity-Length"),
        ] {
            let mut request = Request::builder()
                .method(Method::PUT)
                .uri(format!("/dav/{}{}", public_key.z32(), path.path()))
                .header("Authorization", format!("Basic {auth}"));
            if let Some(header) = length_header {
                request = request.header(header, "5");
            }
            let request = request
                .body(Body::from_stream(futures_util::stream::iter([
                    Ok(Bytes::from_static(b"first")),
                    Err(std::io::Error::other("interrupted upload")),
                ])))
                .unwrap();
            let response = dav_handler(State(AppState::new(context.clone())), request)
                .await
                .unwrap()
                .into_response();
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(response.headers().get(header::CONNECTION).unwrap(), "close");
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
        for method in [DavMethod::Copy, DavMethod::Move] {
            assert_eq!(
                normalize_dav_status(Some(method), StatusCode::METHOD_NOT_ALLOWED),
                StatusCode::PRECONDITION_FAILED
            );
        }
    }
}
