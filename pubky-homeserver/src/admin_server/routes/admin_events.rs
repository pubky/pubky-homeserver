//! Admin-only event stream (SSE): mirrors the client `/events-stream` but, gated by the admin
//! password, streams **all** events including private (`/priv/...`) paths. `user=` is an optional
//! filter (omit for every user); a single global `cursor` paginates. Response is `no-store`.

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
    services::events_service::{AdminStreamQuery, AllEventsFilter, EventStreamError},
    shared::HttpResult,
};

/// Resolve a parsed query into a service-layer [`AllEventsFilter`]: `404` for an unknown `user=`.
/// This is the route's only real work — the streaming itself lives in
/// [`EventsService::all_events_stream`].
async fn resolve_filter(
    state: &AppState,
    query: AdminStreamQuery,
) -> Result<AllEventsFilter, EventStreamError> {
    // None = all users (firehose); otherwise resolve each pubkey to its id.
    let user_ids = if query.users.is_empty() {
        None
    } else {
        Some(state.context.user_service.get_ids(&query.users).await?)
    };

    Ok(AllEventsFilter {
        start_cursor: query.cursor,
        user_ids,
        paths: query.paths.into_iter().map(PathFilter::from).collect(),
        mode: query.mode,
        limit: query.limit,
    })
}

/// Admin-only SSE stream over **all** events (public and private). See [`AdminStreamQuery`] for the
/// query parameters; the streaming lives in [`EventsService::all_events_stream`]. Response is
/// `text/event-stream`, `Cache-Control: no-store`.
pub async fn feed_stream(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
) -> HttpResult<impl IntoResponse> {
    let query = AdminStreamQuery::parse(raw_query.as_deref().unwrap_or(""))?;
    let filter = resolve_filter(&state, query).await?;

    let sse = Sse::new(
        state
            .context
            .events_service
            .all_events_stream(state.context.metrics.clone(), filter)
            .map(|event| Ok::<_, Infallible>(event.to_sse_event())),
    )
    .keep_alive(KeepAlive::default());

    // The feed surfaces private paths; never cache it.
    Ok((
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        sse,
    ))
}
