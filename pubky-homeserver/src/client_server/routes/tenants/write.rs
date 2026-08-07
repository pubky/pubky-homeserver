use axum::http::HeaderMap;
use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use futures_util::stream::StreamExt;

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
        webdav::{EntryPath, WebDavFilePathAxum},
        HttpError, HttpResult,
    },
};

pub async fn legacy_delete(
    State(state): State<AppState>,
    session: AuthSession,
    tenant: RequestTenant,
    Path(path): Path<WebDavFilePathAxum>,
) -> HttpResult<impl IntoResponse> {
    let entry_path = EntryPath::new(tenant.public_key().clone(), path.inner().to_owned());
    delete(State(state), session, entry_path).await
}

pub async fn delete(
    State(state): State<AppState>,
    session: AuthSession,
    entry_path: EntryPath,
) -> HttpResult<impl IntoResponse> {
    if !entry_path.path().is_file() {
        return Err(HttpError::bad_request("Target path must be a file"));
    }
    has_write_permission(&session, entry_path.pubkey(), entry_path.path())?;

    state
        .user_service
        .get_or_http_error(entry_path.pubkey(), false)
        .await?;

    state.file_service.delete(&entry_path).await?;
    Ok((StatusCode::NO_CONTENT, ()))
}

pub async fn legacy_put(
    State(state): State<AppState>,
    session: AuthSession,
    tenant: RequestTenant,
    Path(path): Path<WebDavFilePathAxum>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<impl IntoResponse> {
    let entry_path = EntryPath::new(tenant.public_key().clone(), path.inner().to_owned());
    put(State(state), session, entry_path, headers, body).await
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

    use crate::persistence::sql::user::UserRepository;
    use crate::persistence::sql::SqlDb;
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
        let user = UserRepository::create_with_quota_mb(&db, &pk, 1).await;

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
        let user = UserRepository::create_with_quota_mb(&db, &pk, 1).await;

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
        let user = UserRepository::create_with_quota_mb(&db, &pk, 1).await;

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
        let user = UserRepository::create_with_quota_mb(&db, &pk, 1).await;

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
        let user = UserRepository::create(&pk, &mut db.pool().into())
            .await
            .unwrap();

        // Even a huge hint should pass with unlimited quota
        check_hint(&db, &user, None, "/test.txt", Some(10 * 1024 * 1024 * 1024))
            .await
            .expect("unlimited quota should accept any size");
    }
}
