//! Admin-only event stream (SSE): the same query contract as the client `/events-stream` but,
//! gated by the admin password, streams **all** events including private (`/priv/...`) paths with
//! no credential to re-check. Response is `no-store`.

use std::convert::Infallible;

use axum::{
    extract::{RawQuery, State},
    http::{header, HeaderValue},
    response::{
        sse::{KeepAlive, Sse},
        IntoResponse,
    },
};
use futures_util::StreamExt;

use super::super::app_state::AppState;
use crate::{
    persistence::sql::events::PathFilter,
    services::events_service::{EventStreamFilter, EventStreamQuery, NoGuard},
    shared::HttpResult,
};

/// Admin-only SSE stream over **all** events (public and private). See [`EventStreamQuery`] for
/// the query parameters; the streaming lives in [`EventsService::stream`]. Response is
/// `text/event-stream`, `Cache-Control: no-store`.
pub async fn feed_stream(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
) -> HttpResult<impl IntoResponse> {
    let query = EventStreamQuery::parse(raw_query.as_deref().unwrap_or(""))?;
    let cursor = query.resume.resolve(&state.context.user_service).await?;

    let sse = Sse::new(
        state
            .context
            .events_service
            .stream(
                EventStreamFilter {
                    cursor,
                    paths: query.paths.into_iter().map(PathFilter::from).collect(),
                    mode: query.mode,
                    limit: query.limit,
                },
                NoGuard,
            )
            .map(|event| Ok::<_, Infallible>(event.to_sse_event())),
    )
    .keep_alive(KeepAlive::default());

    // The feed surfaces private paths; never cache it.
    Ok((
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        sse,
    ))
}
