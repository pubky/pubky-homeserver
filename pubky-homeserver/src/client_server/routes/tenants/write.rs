use axum::http::{header, HeaderMap, HeaderValue};
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
            content_hash_etag,
            write_finalization_layer::{resolve_storage_max_bytes, would_exceed_limit},
            WritePreconditions, WriteStreamError,
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
    if !entry_path.path().is_file() {
        return Err(HttpError::bad_request("Target path must be a file"));
    }
    has_write_permission(&session, entry_path.pubkey(), entry_path.path())?;

    state
        .context
        .user_service
        .get_or_http_error(entry_path.pubkey(), false)
        .await?;

    let preconditions = parse_preconditions(&headers)?;
    if preconditions.if_none_match_header().is_some() {
        return Err(HttpError::bad_request(
            "If-None-Match is not supported on DELETE",
        ));
    }

    state
        .context
        .file_service
        .delete(&entry_path, &preconditions)
        .await?;
    Ok((StatusCode::NO_CONTENT, ()))
}

/// Parse the conditional headers of a write, rejecting the ones that are not
/// enforced so a client never gets a silently unconditional write.
fn parse_preconditions(headers: &HeaderMap) -> HttpResult<WritePreconditions> {
    if headers.contains_key(header::IF_UNMODIFIED_SINCE) {
        return Err(HttpError::bad_request(
            "If-Unmodified-Since is not supported; use If-Match",
        ));
    }
    WritePreconditions::from_headers(headers).map_err(HttpError::bad_request)
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
        .context
        .user_service
        .get_or_http_error(entry_path.pubkey(), true)
        .await?;

    let preconditions = parse_preconditions(&headers)?;

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
    let converted_stream =
        body_stream.map(|chunk_result| chunk_result.map_err(WriteStreamError::Axum));

    let written = state
        .context
        .file_service
        .write_stream(&entry_path, converted_stream, &preconditions)
        .await?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::ETAG,
        HeaderValue::from_str(&content_hash_etag(&written.hash)).expect("base64 string is valid"),
    );
    Ok((StatusCode::CREATED, response_headers))
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
}

#[cfg(test)]
mod conditional_write_tests {
    use std::sync::Arc;

    use axum::http::{header, StatusCode};
    use axum_test::TestServer;
    use pubky_common::{
        auth::AuthToken,
        capabilities::Capability,
        crypto::{Hasher, Keypair},
    };

    use crate::app_context::AppContext;
    use crate::client_server::ClientServer;
    use crate::persistence::files::content_hash_etag;

    struct Env {
        server: TestServer,
        host: String,
        cookie: String,
    }

    async fn environment() -> Env {
        let context = AppContext::test().await;
        let router = ClientServer::create_router(Arc::clone(&context)).unwrap();
        let server = TestServer::new(router).unwrap();

        let keypair = Keypair::random();
        let host = keypair.public_key().to_z32();
        let auth_token = AuthToken::sign(&keypair, vec![Capability::root()]);
        let body: axum::body::Bytes = auth_token.serialize().into();
        let response = server
            .post("/signup")
            .add_header("host", &host)
            .bytes(body)
            .expect_success()
            .await;
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .expect("signup sets a session cookie")
            .to_string();

        Env {
            server,
            host,
            cookie,
        }
    }

    impl Env {
        fn put(&self, body: &[u8]) -> axum_test::TestRequest {
            self.server
                .put("/pub/foo")
                .add_header("host", &self.host)
                .add_header(header::COOKIE, &self.cookie)
                .bytes(body.to_vec().into())
        }

        fn delete(&self) -> axum_test::TestRequest {
            self.server
                .delete("/pub/foo")
                .add_header("host", &self.host)
                .add_header(header::COOKIE, &self.cookie)
        }

        async fn get_status(&self) -> StatusCode {
            self.server
                .get("/pub/foo")
                .add_header("host", &self.host)
                .await
                .status_code()
        }

        async fn get_body(&self) -> Vec<u8> {
            self.server
                .get("/pub/foo")
                .add_header("host", &self.host)
                .expect_success()
                .await
                .into_bytes()
                .to_vec()
        }

        async fn get_etag(&self) -> String {
            self.server
                .get("/pub/foo")
                .add_header("host", &self.host)
                .expect_success()
                .await
                .headers()
                .get(header::ETAG)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn put_returns_the_etag_that_get_reports() {
        let env = environment().await;

        let response = env.put(b"v1").expect_success().await;
        response.assert_status(StatusCode::CREATED);
        let put_etag = response
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap();

        assert_eq!(put_etag, env.get_etag().await);
        assert!(put_etag.starts_with('"') && put_etag.ends_with('"'));
    }

    /// The ETag must describe the bytes this request wrote, not whatever the
    /// entry row holds afterwards, or a concurrent write's tag could leak
    /// into this client's next If-Match.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn put_etag_is_the_hash_of_the_body_sent() {
        let env = environment().await;

        let response = env.put(b"exactly these bytes").expect_success().await;
        let put_etag = response
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap();

        let mut hasher = Hasher::new();
        hasher.update(b"exactly these bytes");
        assert_eq!(put_etag, content_hash_etag(&hasher.finalize()));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn if_match_delete_compare_and_delete() {
        let env = environment().await;

        env.put(b"v1").expect_success().await;
        let etag_v1 = env.get_etag().await;

        env.delete()
            .add_header(header::IF_MATCH, "\"stale\"")
            .await
            .assert_status(StatusCode::PRECONDITION_FAILED);
        assert_eq!(env.get_body().await, b"v1");

        env.delete()
            .add_header(header::IF_MATCH, &etag_v1)
            .await
            .assert_status(StatusCode::NO_CONTENT);
        assert_eq!(env.get_status().await, StatusCode::NOT_FOUND);

        // Gone now: 404 whether or not If-Match is sent. RFC 9110 §13.2.1
        // ignores preconditions when the unconditional response is not 2xx,
        // unlike PUT to a missing path, where If-Match: * is evaluated and
        // fails with 412.
        env.delete().await.assert_status(StatusCode::NOT_FOUND);
        env.delete()
            .add_header(header::IF_MATCH, &etag_v1)
            .await
            .assert_status(StatusCode::NOT_FOUND);
        env.delete()
            .add_header(header::IF_MATCH, "*")
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn unsupported_conditional_headers_are_rejected_not_ignored() {
        let env = environment().await;
        env.put(b"v1").expect_success().await;

        env.delete()
            .add_header(header::IF_NONE_MATCH, "\"x\"")
            .await
            .assert_status(StatusCode::BAD_REQUEST);
        env.put(b"v2")
            .add_header(header::IF_UNMODIFIED_SINCE, "Sat, 01 Jan 2000 00:00:00 GMT")
            .await
            .assert_status(StatusCode::BAD_REQUEST);
        env.delete()
            .add_header(header::IF_UNMODIFIED_SINCE, "Sat, 01 Jan 2000 00:00:00 GMT")
            .await
            .assert_status(StatusCode::BAD_REQUEST);

        assert_eq!(env.get_body().await, b"v1");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn if_none_match_star_creates_once() {
        let env = environment().await;

        env.put(b"v1")
            .add_header(header::IF_NONE_MATCH, "*")
            .expect_success()
            .await
            .assert_status(StatusCode::CREATED);

        env.put(b"v2")
            .add_header(header::IF_NONE_MATCH, "*")
            .await
            .assert_status(StatusCode::PRECONDITION_FAILED);

        assert_eq!(env.get_body().await, b"v1");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn if_match_compare_and_set() {
        let env = environment().await;

        env.put(b"v1").expect_success().await;
        let etag_v1 = env.get_etag().await;

        // Fresh ETag: the update lands.
        env.put(b"v2")
            .add_header(header::IF_MATCH, &etag_v1)
            .expect_success()
            .await
            .assert_status(StatusCode::CREATED);
        assert_eq!(env.get_body().await, b"v2");

        // Stale ETag: rejected, content untouched.
        env.put(b"v3")
            .add_header(header::IF_MATCH, &etag_v1)
            .await
            .assert_status(StatusCode::PRECONDITION_FAILED);
        assert_eq!(env.get_body().await, b"v2");

        // Missing resource with If-Match: * is also a failed precondition.
        env.server
            .put("/pub/missing")
            .add_header("host", &env.host)
            .add_header(header::COOKIE, &env.cookie)
            .add_header(header::IF_MATCH, "*")
            .bytes(b"x".to_vec().into())
            .await
            .assert_status(StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn malformed_conditional_headers_are_bad_requests() {
        let env = environment().await;

        env.put(b"v1")
            .add_header(header::IF_MATCH, "unquoted")
            .await
            .assert_status(StatusCode::BAD_REQUEST);
        env.put(b"v1")
            .add_header(header::IF_NONE_MATCH, "W/nope")
            .await
            .assert_status(StatusCode::BAD_REQUEST);

        env.server
            .get("/pub/foo")
            .add_header("host", &env.host)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn unconditional_put_still_overwrites() {
        let env = environment().await;

        env.put(b"v1").expect_success().await;
        env.put(b"v2")
            .expect_success()
            .await
            .assert_status(StatusCode::CREATED);
        assert_eq!(env.get_body().await, b"v2");
    }
}
