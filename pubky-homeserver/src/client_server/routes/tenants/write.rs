use std::time::Duration;

use axum::http::HeaderMap;
use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use futures_util::stream::{self, Stream, StreamExt};

use super::{authorize::authorize_write, lock};
use crate::{
    client_server::{auth::AuthSession, middleware::request_tenant::RequestTenant, AppState},
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

/// Longest an upload may go without delivering a chunk. A write holds its
/// path's lock while its body streams, so a client that goes silent without
/// closing its connection would otherwise block the path for as long as the
/// request lives. Set to the longest lock lifetime: a vanished uploader blocks
/// a path no longer than a vanished lock holder does.
const UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(lock::MAX_LOCK_TIMEOUT_SECS as u64);

pub async fn legacy_delete(
    state: State<AppState>,
    session: AuthSession,
    tenant: RequestTenant,
    Path(path): Path<WebDavFilePathAxum>,
    headers: HeaderMap,
) -> HttpResult<impl IntoResponse> {
    let entry_path = EntryPath::new(tenant.public_key().clone(), path.inner().to_owned());
    delete(state, session, entry_path, headers).await
}

pub async fn delete(
    State(state): State<AppState>,
    session: AuthSession,
    entry_path: EntryPath,
    headers: HeaderMap,
) -> HttpResult<impl IntoResponse> {
    authorize_write(&state, &session, &entry_path, false).await?;

    lock::with_write_lock(&state.context.sql_db, &entry_path, &headers, async {
        Ok(state.context.file_service.delete(&entry_path).await?)
    })
    .await?;
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
    let user = authorize_write(&state, &session, &entry_path, true).await?;

    // Early fail: check Content-Length header against the user's storage quota
    // so we can reject before streaming the entire body.
    // We read from the header rather than body.size_hint() because middleware
    // layers (e.g. bandwidth throttling) may replace the body with a stream
    // that loses the size hint.
    let content_length = content_length_from_headers(&headers);
    fail_if_size_hint_exceeds_quota(
        content_length,
        &user,
        state.context.config_toml.storage.default_quota_mb,
        &entry_path,
        &mut state.context.sql_db.pool().into(),
    )
    .await?;

    // Convert body stream to the format expected by file_service
    let body_stream = body.into_data_stream();
    let converted_stream = abandon_when_idle(
        body_stream.map(|chunk_result| chunk_result.map_err(WriteStreamError::Axum)),
        UPLOAD_IDLE_TIMEOUT,
    );

    lock::with_write_lock(&state.context.sql_db, &entry_path, &headers, async {
        let file_service = &state.context.file_service;
        Ok(file_service
            .write_stream(&entry_path, converted_stream)
            .await?)
    })
    .await?;
    Ok((StatusCode::CREATED, ()))
}

/// End `chunks` with [`WriteStreamError::Stalled`] once no chunk arrives for
/// `idle`. The timer restarts on every chunk, so a slow upload that keeps
/// moving is not cut off.
fn abandon_when_idle<T, S>(
    chunks: S,
    idle: Duration,
) -> impl Stream<Item = Result<T, WriteStreamError>> + Unpin + Send
where
    S: Stream<Item = Result<T, WriteStreamError>> + Unpin + Send,
    T: Send,
{
    Box::pin(stream::unfold(Some(chunks), move |chunks| async move {
        let mut chunks = chunks?;
        match tokio::time::timeout(idle, chunks.next()).await {
            Ok(chunk) => Some((chunk?, Some(chunks))),
            Err(_) => Some((Err(WriteStreamError::Stalled), None)),
        }
    }))
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

    /// A body that stops arriving ends the stream with `Stalled` instead of
    /// holding the write, and its path's lock, open.
    #[tokio::test]
    async fn abandon_when_idle_ends_a_stalled_stream() {
        let idle = Duration::from_millis(50);

        let complete = stream::iter([Ok(1), Ok(2)]);
        let chunks: Vec<_> = abandon_when_idle(complete, idle).collect().await;
        assert!(matches!(chunks[..], [Ok(1), Ok(2)]));

        let stalled = stream::iter([Ok(1)]).chain(stream::pending());
        let chunks: Vec<_> = abandon_when_idle(stalled, idle).collect().await;
        assert!(matches!(
            chunks[..],
            [Ok(1), Err(WriteStreamError::Stalled)]
        ));
    }

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
}
