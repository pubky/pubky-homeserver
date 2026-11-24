use axum::http::HeaderMap;
use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use futures_util::stream::StreamExt;

use super::{authorize::authorize_write, lock::if_header_tokens};
use crate::{
    client_server::{auth::AuthSession, middleware::request_tenant::RequestTenant, AppState},
    persistence::files::{FileIoError, WriteStreamError},
    shared::{
        webdav::{EntryPath, WebDavFilePathAxum},
        HttpResult,
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
    authorize_write(&state, &session, &entry_path, false).await?;

    let delete = state.context.file_service.delete(&entry_path);
    state
        .context
        .lock_service
        .run_write(&entry_path, &if_header_tokens(&headers), delete)
        .await??;
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
    // Opening a writer reserves an upload slot before the storage layer checks the path.
    let quota = user.quota();
    if !quota.is_write_path_allowed(entry_path.path().as_str()) {
        return Err(FileIoError::WritePathForbidden.into());
    }

    // Early fail: check Content-Length header against the user's storage quota
    // so we can reject before streaming the entire body.
    // We read from the header rather than body.size_hint() because middleware
    // layers (e.g. bandwidth throttling) may replace the body with a stream
    // that loses the size hint.
    let content_length = content_length_from_headers(&headers);
    state
        .context
        .file_service
        .check_size_hint(&user, content_length, &entry_path)
        .await?;

    // Convert body stream to the format expected by file_service
    let body_stream = body.into_data_stream();
    let converted_stream =
        body_stream.map(|chunk_result| chunk_result.map_err(WriteStreamError::Axum));

    let write = state
        .context
        .file_service
        .write_stream(&entry_path, converted_stream);
    state
        .context
        .lock_service
        .run_write(&entry_path, &if_header_tokens(&headers), write)
        .await??;
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

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        fs, future,
        num::{NonZeroU32, NonZeroUsize},
        time::Duration,
    };

    use axum::{
        body::{Body, Bytes},
        http::{header, Request, StatusCode},
        Router,
    };
    use axum_test::TestServer;
    use futures_util::{stream, StreamExt};
    use pubky_common::{capabilities::Capability, crypto::Keypair};
    use tokio::{
        sync::oneshot,
        time::{self, timeout},
    };
    use tower::ServiceExt;

    use crate::{
        client_server::test_utils::signup_cookie,
        persistence::files::test_support::FILE_SYSTEM_STAGING_DIR, shared::quota::UserQuotaPatch,
        storage_config::StorageConfigToml, AppContext, ClientServer,
    };

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn idle_uploads_discard_staged_data_and_preserve_the_file_on_both_put_routes() {
        let context = AppContext::test_with_config(|config| {
            config.storage.backend = StorageConfigToml::FileSystem;
            // Exercise the error path through the bandwidth middleware as well.
            config.default_quotas.rate_write = Some("1mb/s".parse().unwrap());
        })
        .await;
        let staging_dir = context.data_path.join(FILE_SYSTEM_STAGING_DIR);
        let router = ClientServer::create_router(context).unwrap();
        let server = TestServer::new(router.clone());
        let owner = Keypair::random();
        let cookie = signup_cookie(&server, &owner, vec![Capability::root()]).await;
        let owner_id = owner.public_key().z32();
        let addressed = format!("/storage/{owner_id}/pub/upload");

        for path in [addressed.as_str(), "/pub/upload"] {
            for prefix in [None, Some(Bytes::from_static(b"partial overwrite"))] {
                server
                    .put(&addressed)
                    .add_header(header::COOKIE, &cookie)
                    .text("original")
                    .await
                    .assert_status(StatusCode::CREATED);

                let (waiting, body_polled) = oneshot::channel();
                let stall = stream::once(async move {
                    waiting.send(()).unwrap();
                    future::pending().await
                });
                let chunks = stream::iter(prefix.map(Ok::<_, Infallible>)).chain(stall);
                let mut request = Request::put(path).header(header::COOKIE, &cookie);
                if path == "/pub/upload" {
                    request = request.header("pubky-host", &owner_id);
                }
                let upload = request.body(Body::from_stream(chunks)).unwrap();
                let status = upload_across_idle_interval(&router, upload, body_polled).await;

                assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
                assert!(fs::read_dir(&staging_dir).unwrap().next().is_none());
                server.get(&addressed).await.assert_text("original");

                // EOF without any bytes is a valid replacement.
                server
                    .put(&addressed)
                    .add_header(header::COOKIE, &cookie)
                    .await
                    .assert_status(StatusCode::CREATED);
                server.get(&addressed).await.assert_text("");
            }
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn bandwidth_throttling_can_take_longer_than_the_upload_idle_timeout() {
        let context = AppContext::test_with_config(|config| {
            config.default_quotas.rate_write = Some("1kb/s".parse().unwrap());
            config.default_quotas.rate_write_burst = Some(NonZeroU32::MIN);
        })
        .await;
        let router = ClientServer::create_router(context).unwrap();
        let server = TestServer::new(router.clone());
        let owner = Keypair::random();
        let cookie = signup_cookie(&server, &owner, vec![Capability::root()]).await;
        let path = format!("/storage/{}/pub/upload", owner.public_key().z32());

        // The limiter must wait to deliver this frame because it exceeds the burst.
        let contents = Bytes::from(vec![b'a'; 3 * 1024]);
        let chunk = contents.clone();
        let (available, body_polled) = oneshot::channel();
        let body = Body::from_stream(stream::once(async move {
            available.send(()).unwrap();
            Ok::<_, Infallible>(chunk)
        }));
        let upload = Request::put(&path)
            .header(header::COOKIE, cookie)
            .body(body)
            .unwrap();
        let status = upload_across_idle_interval(&router, upload, body_polled).await;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(server.get(&path).await.as_bytes(), &contents);
    }

    async fn upload_across_idle_interval(
        router: &Router,
        request: Request<Body>,
        body_polled: oneshot::Receiver<()>,
    ) -> StatusCode {
        let upload = tokio::spawn(router.clone().oneshot(request));
        timeout(Duration::from_secs(10), body_polled)
            .await
            .expect("writer should poll the body")
            .unwrap();
        // Jump past the deadline after the handler has opened its writer, then
        // restore real time for filesystem cleanup and database finalization.
        time::pause();
        time::advance(Duration::from_secs(61)).await;
        time::resume();
        timeout(Duration::from_secs(10), upload)
            .await
            .expect("upload should finish")
            .unwrap()
            .unwrap()
            .status()
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn concurrent_upload_limit_is_shared_by_both_routes_and_scoped_to_the_user() {
        let context = AppContext::test_with_config(|config| {
            config.storage.max_concurrent_uploads_per_user_per_replica = NonZeroUsize::MIN;
        })
        .await;
        let router = ClientServer::create_router(context.clone()).unwrap();
        let server = TestServer::new(router.clone());
        let owner = Keypair::random();
        let other = Keypair::random();
        let cookie = signup_cookie(&server, &owner, vec![Capability::root()]).await;
        let other_cookie = signup_cookie(&server, &other, vec![Capability::root()]).await;
        let quota = UserQuotaPatch {
            allowed_write_paths: Some(Some(vec!["/pub/allowed/".parse().unwrap()])),
            ..Default::default()
        };
        context
            .user_service
            .patch_quota(&owner.public_key(), &quota)
            .await
            .unwrap();
        let owner_id = owner.public_key().z32();
        let addressed_path = format!("/storage/{owner_id}/pub/allowed/upload");
        let legacy_put = || {
            server
                .put("/pub/allowed/other")
                .add_header("pubky-host", &owner_id)
                .add_header(header::COOKIE, &cookie)
        };

        for (body_result, expected_status) in [
            (Ok(Bytes::from_static(b"complete")), StatusCode::CREATED),
            (
                Err(std::io::Error::other("body interrupted")),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let (started, wait_for_start) = oneshot::channel();
            let (finish, wait_for_body) = oneshot::channel();
            // The router polls this stream only after opening the writer.
            let body = Body::from_stream(stream::once(async move {
                started.send(()).unwrap();
                wait_for_body.await.unwrap()
            }));
            let first = Request::put(&addressed_path)
                .header(header::COOKIE, &cookie)
                .body(body)
                .unwrap();
            let upload = tokio::spawn(router.clone().oneshot(first));
            timeout(Duration::from_secs(5), wait_for_start)
                .await
                .unwrap()
                .unwrap();

            let refused = legacy_put().await;
            refused.assert_status(StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(refused.headers()[header::RETRY_AFTER], "1");

            // A forbidden path gets 403 even when the only slot is occupied.
            let body = Body::from_stream(stream::pending::<Result<Bytes, Infallible>>());
            let forbidden = Request::put(format!("/storage/{owner_id}/pub/forbidden"))
                .header(header::COOKIE, &cookie)
                .body(body)
                .unwrap();
            let response = timeout(Duration::from_secs(5), router.clone().oneshot(forbidden))
                .await
                .expect("a forbidden upload must be rejected before reading its body")
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);

            server
                .put("/pub/other")
                .add_header("pubky-host", other.public_key().z32())
                .add_header(header::COOKIE, &other_cookie)
                .text("independent upload")
                .await
                .assert_status(StatusCode::CREATED);

            finish.send(body_result).unwrap();
            assert_eq!(upload.await.unwrap().unwrap().status(), expected_status);
            legacy_put()
                .text("slot released")
                .await
                .assert_status(StatusCode::CREATED);
        }
    }
}
