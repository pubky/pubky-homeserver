use axum::http::HeaderMap;
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::StatusCode,
    response::IntoResponse,
};
use futures_util::stream::StreamExt;
use percent_encoding::percent_decode_str;
use std::str::FromStr;

use crate::{
    client_server::{
        auth::{has_write_permission, AuthSession},
        middleware::request_tenant::RequestTenant,
        AppState,
    },
    persistence::{
        files::{
            write_finalization_layer::{resolve_storage_max_bytes, would_exceed_limit},
            WriteStreamError,
        },
        sql::{entry::EntryRepository, user::UserEntity, UnifiedExecutor},
    },
    services::user_service::FILE_METADATA_SIZE,
    shared::{
        webdav::{EntryPath, StoragePath, WebDavFilePathAxum, WebDavPathAxum},
        HttpError, HttpResult,
    },
};

pub async fn legacy_delete(
    state: State<AppState>,
    session: AuthSession,
    tenant: RequestTenant,
    Path(path): Path<WebDavPathAxum>,
) -> HttpResult<impl IntoResponse> {
    let entry_path = EntryPath::new(tenant.public_key().clone(), path.inner().to_owned());
    delete(state, session, entry_path).await
}

pub async fn delete(
    State(state): State<AppState>,
    session: AuthSession,
    entry_path: EntryPath,
) -> HttpResult<impl IntoResponse> {
    has_write_permission(&session, entry_path.pubkey(), entry_path.path())?;

    state
        .user_service
        .get_or_http_error(entry_path.pubkey(), false)
        .await?;

    if entry_path.path().is_file() {
        state.file_service.delete(&entry_path).await?;
    } else {
        state.file_service.delete_folder(&entry_path).await?;
    }
    Ok((StatusCode::NO_CONTENT, ()))
}

pub async fn legacy_put(
    state: State<AppState>,
    session: AuthSession,
    tenant: RequestTenant,
    Path(path): Path<WebDavFilePathAxum>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<impl IntoResponse> {
    let entry_path = EntryPath::new(tenant.public_key().clone(), path.inner().to_owned());
    put(state, session, entry_path, headers, body).await
}

pub async fn put(
    State(state): State<AppState>,
    session: AuthSession,
    entry_path: EntryPath,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<impl IntoResponse> {
    if !entry_path.path().is_file() {
        return Err(HttpError::bad_request("Target path must be a file"));
    }
    has_write_permission(&session, entry_path.pubkey(), entry_path.path())?;

    let user = state
        .user_service
        .get_or_http_error(entry_path.pubkey(), true)
        .await?;

    // Early fail: check Content-Length header against the user's storage quota
    // so we can reject before streaming the entire body.
    // We read from the header rather than body.size_hint() because middleware
    // layers (e.g. bandwidth throttling) may replace the body with a stream
    // that loses the size hint.
    let content_length = content_length_from_headers(&headers);
    fail_if_size_hint_exceeds_quota(
        content_length,
        &user,
        state.default_storage_mb,
        &entry_path,
        &mut state.sql_db.pool().into(),
    )
    .await?;

    // Convert body stream to the format expected by file_service
    let body_stream = body.into_data_stream();
    let converted_stream =
        body_stream.map(|chunk_result| chunk_result.map_err(WriteStreamError::Axum));

    state
        .file_service
        .write_stream(&entry_path, converted_stream)
        .await?;
    Ok((StatusCode::CREATED, ()))
}

/// Method router fallback for WebDAV extension methods (COPY, MOVE).
///
/// axum's `MethodFilter` only covers standard HTTP methods, so COPY/MOVE
/// requests land here. Anything else is a 405 — checked before auth so that
/// unsupported methods behave exactly as if no fallback were registered.
pub async fn webdav_extension_method(
    State(state): State<AppState>,
    tenant: RequestTenant,
    req: Request<Body>,
) -> HttpResult<impl IntoResponse> {
    let is_move = match req.method().as_str() {
        "COPY" => false,
        "MOVE" => true,
        _ => {
            return Err(HttpError::method_not_allowed());
        }
    };

    // COPY/MOVE are writes: the authentication middleware must have resolved
    // a session into the request extensions.
    let session = req
        .extensions()
        .get::<AuthSession>()
        .cloned()
        .ok_or_else(|| HttpError::unauthorized_with_message("No valid session"))?;

    let from = source_entry_path(&tenant, req.uri().path())?;
    if !from.path().is_file() {
        return Err(HttpError::bad_request("Source path must be a file"));
    }
    let to = destination_entry_path(&tenant, &req)?;

    has_write_permission(&session, from.pubkey(), from.path())?;
    has_write_permission(&session, to.pubkey(), to.path())?;

    state
        .user_service
        .get_or_http_error(from.pubkey(), false)
        .await?;

    if is_move {
        state.file_service.move_file(&from, &to).await?;
    } else {
        state.file_service.copy(&from, &to).await?;
    }
    Ok((StatusCode::CREATED, ()))
}

/// Resolve the COPY/MOVE source path from the request URI and tenant.
fn source_entry_path(tenant: &RequestTenant, uri_path: &str) -> HttpResult<EntryPath> {
    if let Some(path) = tenant.storage_path() {
        // Path-addressed route: tenant middleware already parsed the path.
        return Ok(EntryPath::new(tenant.public_key().clone(), path.clone()));
    }
    // Legacy owner-relative route: parse the URI path ourselves, mirroring the
    // percent-decoding the tenant middleware applies to storage routes.
    let decoded = percent_decode_str(uri_path.trim_start_matches('/'))
        .decode_utf8()
        .map_err(|_| HttpError::bad_request("Storage path is not valid UTF-8"))?;
    let path = WebDavPathAxum::from_str(&decoded)
        .map_err(|e| HttpError::bad_request(format!("Invalid storage path: {e}")))?;
    Ok(EntryPath::new(
        tenant.public_key().clone(),
        path.inner().to_owned(),
    ))
}

/// Parse the WebDAV `Destination` header into an `EntryPath` on the same tenant.
fn destination_entry_path(tenant: &RequestTenant, req: &Request<Body>) -> HttpResult<EntryPath> {
    let raw = req
        .headers()
        .get("Destination")
        .ok_or_else(|| HttpError::bad_request("Missing Destination header"))?
        .to_str()
        .map_err(|_| HttpError::bad_request("Destination header is not valid UTF-8"))?;

    // Accept either a bare storage path (`/pub/app/file.txt`) or a full
    // path-addressed URL path (`/storage/{user_z32}/pub/app/file.txt`).
    let path_str = match raw.strip_prefix("/storage/") {
        Some(remainder) => {
            let (owner, path) = remainder
                .split_once('/')
                .ok_or_else(|| HttpError::bad_request("Invalid Destination header"))?;
            if owner != tenant.public_key().z32() {
                return Err(HttpError::bad_request(
                    "Cross-user COPY/MOVE destinations are not supported",
                ));
            }
            format!("/{path}")
        }
        None => raw.to_string(),
    };

    let path = StoragePath::normalize(&path_str)
        .map_err(|e| HttpError::bad_request(format!("Invalid Destination path: {e}")))?;
    if !path.is_file() {
        return Err(HttpError::bad_request("Destination path must be a file"));
    }
    Ok(EntryPath::new(tenant.public_key().clone(), path))
}

/// Parse the `Content-Length` header into a `u64`, returning `None` if absent or unparseable.
fn content_length_from_headers(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(axum::http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Check whether the Content-Length size hint would exceed the user's storage quota.
/// Returns Ok if there is no size hint, no quota, or the hint fits within the quota.
async fn fail_if_size_hint_exceeds_quota<'a>(
    content_size_hint: Option<u64>,
    user: &UserEntity,
    default_storage_mb: Option<u64>,
    entry_path: &EntryPath,
    executor: &mut UnifiedExecutor<'a>,
) -> HttpResult<()> {
    let content_size_hint = match content_size_hint {
        Some(size) => size,
        None => return Ok(()),
    };

    let existing_entry = EntryRepository::get_by_path(entry_path, executor)
        .await
        .ok();
    let existing_entry_bytes = existing_entry.as_ref().map_or(0, |e| e.content_length);
    let is_new_file = existing_entry.is_none();

    let mut bytes_delta = content_size_hint as i64 - existing_entry_bytes as i64;
    if is_new_file {
        bytes_delta += FILE_METADATA_SIZE as i64;
    }

    let max_bytes = resolve_storage_max_bytes(user, default_storage_mb);
    if would_exceed_limit(user.used_bytes, bytes_delta, max_bytes) {
        return Err(HttpError::insufficient_storage());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Keypair;

    use crate::persistence::sql::SqlDb;
    use crate::services::user_service::UserService;
    use crate::shared::webdav::StoragePath;

    use super::*;

    /// Helper to build the function args and call `fail_if_size_hint_exceeds_quota`.
    async fn check_hint(
        db: &SqlDb,
        user: &UserEntity,
        default_storage_mb: Option<u64>,
        path: &str,
        size_hint: Option<u64>,
    ) -> HttpResult<()> {
        let entry_path = EntryPath::new(user.public_key.clone(), StoragePath::new(path).unwrap());
        fail_if_size_hint_exceeds_quota(
            size_hint,
            user,
            default_storage_mb,
            &entry_path,
            &mut db.pool().into(),
        )
        .await
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_no_size_hint_always_ok() {
        let db = SqlDb::test().await;
        let pk = Keypair::random().public_key();
        let user = UserService::new(db.clone())
            .create_with_quota_mb(&pk, 1)
            .await;

        // No size hint → always OK regardless of quota
        check_hint(&db, &user, None, "/test.txt", None)
            .await
            .expect("no size hint should always pass");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_small_hint_within_quota() {
        let db = SqlDb::test().await;
        let pk = Keypair::random().public_key();
        let user = UserService::new(db.clone())
            .create_with_quota_mb(&pk, 1)
            .await;

        // 100 bytes + FILE_METADATA_SIZE is well within 1 MB
        check_hint(&db, &user, None, "/test.txt", Some(100))
            .await
            .expect("small file should be within 1 MB quota");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_hint_exceeds_quota() {
        let db = SqlDb::test().await;
        let pk = Keypair::random().public_key();
        let user = UserService::new(db.clone())
            .create_with_quota_mb(&pk, 1)
            .await;

        // 1 MB content + FILE_METADATA_SIZE > 1 MB quota
        check_hint(&db, &user, None, "/test.txt", Some(1024 * 1024))
            .await
            .expect_err("content + metadata should exceed 1 MB quota");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_new_file_accounts_for_metadata_overhead() {
        let db = SqlDb::test().await;
        let pk = Keypair::random().public_key();
        let user = UserService::new(db.clone())
            .create_with_quota_mb(&pk, 1)
            .await;

        let one_mb = 1024u64 * 1024;
        let max_content = one_mb - FILE_METADATA_SIZE;

        // Exactly at limit: content + metadata == quota → OK
        check_hint(&db, &user, None, "/test.txt", Some(max_content))
            .await
            .expect("content + metadata exactly at quota should pass");

        // One byte over: content + metadata > quota → fail
        check_hint(&db, &user, None, "/test.txt", Some(max_content + 1))
            .await
            .expect_err("content + metadata one byte over quota should fail");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_unlimited_quota_allows_anything() {
        let db = SqlDb::test().await;
        // No system default → unlimited for Default users
        let pk = Keypair::random().public_key();
        let user = UserService::new(db.clone()).create(&pk).await.unwrap();

        // Even a huge hint should pass with unlimited quota
        check_hint(&db, &user, None, "/test.txt", Some(10 * 1024 * 1024 * 1024))
            .await
            .expect("unlimited quota should accept any size");
    }

    mod routes {
        use axum::http::{header, Method, StatusCode};

        use crate::client_server::routes::tenants::read::tests::create_environment;

        fn copy_method() -> Method {
            Method::from_bytes(b"COPY").unwrap()
        }

        fn move_method() -> Method {
            Method::from_bytes(b"MOVE").unwrap()
        }

        #[tokio::test]
        #[pubky_test_utils::test]
        async fn copy_and_move_file() {
            let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

            server
                .put(format!("/storage/{}/pub/app/original.txt", public_key.z32()).as_str())
                .add_header(header::COOKIE, cookie.clone())
                .text("content")
                .expect_success()
                .await;

            // COPY duplicates the file.
            server
                .method(
                    copy_method(),
                    format!("/storage/{}/pub/app/original.txt", public_key.z32()).as_str(),
                )
                .add_header(header::COOKIE, cookie.clone())
                .add_header("Destination", "/pub/app/copied.txt")
                .expect_success()
                .await;

            let resp = server
                .get(format!("/storage/{}/pub/app/original.txt", public_key.z32()).as_str())
                .expect_success()
                .await;
            assert_eq!(resp.text(), "content", "source must remain after COPY");
            let resp = server
                .get(format!("/storage/{}/pub/app/copied.txt", public_key.z32()).as_str())
                .expect_success()
                .await;
            assert_eq!(resp.text(), "content");

            // MOVE relocates the copy.
            server
                .method(
                    move_method(),
                    format!("/storage/{}/pub/app/copied.txt", public_key.z32()).as_str(),
                )
                .add_header(header::COOKIE, cookie.clone())
                .add_header("Destination", "/pub/app/moved.txt")
                .expect_success()
                .await;

            server
                .get(format!("/storage/{}/pub/app/copied.txt", public_key.z32()).as_str())
                .expect_failure()
                .await
                .assert_status(StatusCode::NOT_FOUND);
            let resp = server
                .get(format!("/storage/{}/pub/app/moved.txt", public_key.z32()).as_str())
                .expect_success()
                .await;
            assert_eq!(resp.text(), "content");
        }

        #[tokio::test]
        #[pubky_test_utils::test]
        async fn copy_requires_destination_header_and_file_paths() {
            let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

            server
                .put(format!("/storage/{}/pub/app/file.txt", public_key.z32()).as_str())
                .add_header(header::COOKIE, cookie.clone())
                .text("content")
                .expect_success()
                .await;

            // Missing Destination header → 400.
            server
                .method(
                    copy_method(),
                    format!("/storage/{}/pub/app/file.txt", public_key.z32()).as_str(),
                )
                .add_header(header::COOKIE, cookie.clone())
                .expect_failure()
                .await
                .assert_status(StatusCode::BAD_REQUEST);

            // Folder-shaped source → 400.
            server
                .method(
                    copy_method(),
                    format!("/storage/{}/pub/app/", public_key.z32()).as_str(),
                )
                .add_header(header::COOKIE, cookie.clone())
                .add_header("Destination", "/pub/app/other.txt")
                .expect_failure()
                .await
                .assert_status(StatusCode::BAD_REQUEST);

            // Folder-shaped destination → 400.
            server
                .method(
                    copy_method(),
                    format!("/storage/{}/pub/app/file.txt", public_key.z32()).as_str(),
                )
                .add_header(header::COOKIE, cookie.clone())
                .add_header("Destination", "/pub/app/folder/")
                .expect_failure()
                .await
                .assert_status(StatusCode::BAD_REQUEST);

            // Missing source file → 404.
            server
                .method(
                    copy_method(),
                    format!("/storage/{}/pub/app/missing.txt", public_key.z32()).as_str(),
                )
                .add_header(header::COOKIE, cookie.clone())
                .add_header("Destination", "/pub/app/other.txt")
                .expect_failure()
                .await
                .assert_status(StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        #[pubky_test_utils::test]
        async fn delete_folder_recursively() {
            let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

            for path in [
                "/pub/app/folder/a.txt",
                "/pub/app/folder/sub/b.txt",
                "/pub/app/other.txt",
            ] {
                server
                    .put(format!("/storage/{}{}", public_key.z32(), path).as_str())
                    .add_header(header::COOKIE, cookie.clone())
                    .text("x")
                    .expect_success()
                    .await;
            }

            server
                .delete(format!("/storage/{}/pub/app/folder/", public_key.z32()).as_str())
                .add_header(header::COOKIE, cookie.clone())
                .expect_success()
                .await;

            for path in ["/pub/app/folder/a.txt", "/pub/app/folder/sub/b.txt"] {
                server
                    .get(format!("/storage/{}{}", public_key.z32(), path).as_str())
                    .expect_failure()
                    .await
                    .assert_status(StatusCode::NOT_FOUND);
            }
            server
                .get(format!("/storage/{}/pub/app/other.txt", public_key.z32()).as_str())
                .expect_success()
                .await;
        }

        #[tokio::test]
        #[pubky_test_utils::test]
        async fn legacy_routes_support_copy_move_and_folder_delete() {
            let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

            server
                .put("/pub/app/original.txt")
                .add_header("host", public_key.z32())
                .add_header(header::COOKIE, cookie.clone())
                .text("content")
                .expect_success()
                .await;

            server
                .method(copy_method(), "/pub/app/original.txt")
                .add_header("host", public_key.z32())
                .add_header(header::COOKIE, cookie.clone())
                .add_header("Destination", "/pub/app/copied.txt")
                .expect_success()
                .await;

            server
                .method(move_method(), "/pub/app/copied.txt")
                .add_header("host", public_key.z32())
                .add_header(header::COOKIE, cookie.clone())
                .add_header("Destination", "/pub/app/folder/moved.txt")
                .expect_success()
                .await;

            server
                .delete("/pub/app/folder/")
                .add_header("host", public_key.z32())
                .add_header(header::COOKIE, cookie.clone())
                .expect_success()
                .await;

            server
                .get("/pub/app/folder/moved.txt")
                .add_header("host", public_key.z32())
                .expect_failure()
                .await
                .assert_status(StatusCode::NOT_FOUND);
            let resp = server
                .get("/pub/app/original.txt")
                .add_header("host", public_key.z32())
                .expect_success()
                .await;
            assert_eq!(resp.text(), "content");
        }

        #[tokio::test]
        #[pubky_test_utils::test]
        async fn unsupported_methods_are_rejected() {
            let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

            server
                .method(
                    Method::from_bytes(b"PROPFIND").unwrap(),
                    format!("/storage/{}/pub/app/file.txt", public_key.z32()).as_str(),
                )
                .add_header(header::COOKIE, cookie.clone())
                .expect_failure()
                .await
                .assert_status(StatusCode::METHOD_NOT_ALLOWED);
        }
    }
}
