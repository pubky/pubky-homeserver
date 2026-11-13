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
    persistence::files::WriteStreamError,
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
