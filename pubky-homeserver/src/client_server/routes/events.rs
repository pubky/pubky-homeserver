//! Event streaming endpoints.
//!
//! Provides two ways to consume file change events:
//! - `GET /events/` — Historical plain-text feed with cursor-based pagination.
//! - `GET /events-stream` — Server-Sent Events with a two-phase approach:
//!   first replays historical events from the database, then switches to
//!   real-time broadcast for live updates.

use axum::{
    body::Body,
    extract::{RawQuery, State},
    http::{header, HeaderMap, Response, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
};
use futures_util::stream::Stream;
use pubky_common::crypto::PublicKey;
use serde::Deserialize;
use std::{collections::HashMap, convert::Infallible, time::Instant};
use tower_cookies::Cookies;
use url::form_urlencoded;

use crate::{
    client_server::{
        auth::{
            grant::bearer::extract_bearer_token, has_read_permission, AuthSession,
            PendingStreamAuth,
        },
        query_params::ListQueryParams,
        AppState,
    },
    constants::{PRIVATE_ROOT, PUBLIC_ROOT},
    observability::ConnectionGuard,
    persistence::{
        files::events::{
            EventCursor, EventEntity, EventsService, PathFilter, MAX_EVENT_STREAM_USERS,
        },
        sql::SqlDb,
    },
    shared::{webdav::StoragePath, HttpError, HttpResult},
};

#[derive(Debug, thiserror::Error)]
pub enum EventStreamError {
    #[error("User not found")]
    UserNotFound,
    #[error("{0}")]
    InvalidParameter(String),
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
}

impl From<EventStreamError> for HttpError {
    fn from(error: EventStreamError) -> Self {
        match error {
            EventStreamError::UserNotFound => HttpError::not_found(),
            EventStreamError::DatabaseError(e) => HttpError::from(e),
            _ => HttpError::bad_request(error.to_string()),
        }
    }
}

/// Query parameters for the event stream SSE endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawEventStreamQueryParams")]
pub struct EventStreamQueryParams {
    /// Maximum total events to send before closing connection.
    pub limit: Option<u16>,
    /// Return events in reverse chronological order
    /// **Cannot be combined with `live=true`** (returns 400 error).
    pub reverse: bool,
    /// Enable live streaming mode
    pub live: bool,
    /// One or more user public keys to filter events for.
    /// - Format: z-base-32 encoded public key (e.g., "o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo")
    /// - Single user: `?user=pubkey1`
    /// - Single user with cursor: `?user=pubkey1:cursor`
    /// - Multiple users: `?user=pubkey1&user=pubkey2:cursor2`
    pub user_cursors: Vec<(PublicKey, Option<String>)>,
    /// Repeatable path filters. Each value is a path WITHOUT the `pubky://`
    /// scheme or user pubkey, e.g. `/pub/files/`, `pub/files/`, `/priv/app/`..
    pub paths: Vec<StoragePath>,
}

#[derive(Clone, Copy)]
enum EventStreamTenantScope<'a> {
    PublicOnly,
    PrivateSingleTenant(&'a PublicKey),
    PrivateUnsupported,
}

impl<'a> EventStreamTenantScope<'a> {
    fn from_query(paths: &[StoragePath], user_cursors: &'a [(PublicKey, Option<String>)]) -> Self {
        if !paths
            .iter()
            .any(|path| path.as_str().starts_with(PRIVATE_ROOT))
        {
            return Self::PublicOnly;
        }

        match user_cursors {
            [(tenant, _)] => Self::PrivateSingleTenant(tenant),
            _ => Self::PrivateUnsupported,
        }
    }

    fn tenant(self) -> Option<&'a PublicKey> {
        match self {
            Self::PrivateSingleTenant(tenant) => Some(tenant),
            Self::PublicOnly | Self::PrivateUnsupported => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawEventStreamQueryParams {
    #[serde(default)]
    user: Vec<String>,
    limit: Option<u16>,
    #[serde(default)]
    reverse: bool,
    #[serde(default)]
    live: bool,
    #[serde(default)]
    paths: Vec<String>,
}

/// Parse query string manually to handle repeated `user` parameters.
/// URL query string format like: `user=pubkey1&user=pubkey2:cursor&limit=10&live=true`
fn parse_query_params(query: &str) -> Result<EventStreamQueryParams, EventStreamError> {
    let mut users = Vec::new();
    let mut limit = None;
    let mut reverse = false;
    let mut live = false;
    let mut paths = Vec::new();

    // Parse using form_urlencoded which handles URL decoding
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "user" => users.push(value.to_string()),
            "limit" => {
                let parsed = value.parse::<u16>().map_err(|_| {
                    EventStreamError::InvalidParameter(format!("Invalid limit: {}", value))
                })?;
                if parsed == 0 {
                    return Err(EventStreamError::InvalidParameter(
                        "limit must be at least 1".to_string(),
                    ));
                }
                limit = Some(parsed);
            }
            "reverse" => {
                reverse = value == "true" || value == "1";
            }
            "live" => {
                live = value == "true" || value == "1";
            }
            // `path` is repeatable; empty values are ignored.
            "path" if !value.is_empty() => {
                paths.push(value.to_string());
            }
            _ => {} // Ignore unknown parameters
        }
    }

    let raw = RawEventStreamQueryParams {
        user: users,
        limit,
        reverse,
        live,
        paths,
    };

    raw.try_into()
}

impl TryFrom<RawEventStreamQueryParams> for EventStreamQueryParams {
    type Error = EventStreamError;

    fn try_from(raw: RawEventStreamQueryParams) -> Result<Self, Self::Error> {
        if raw.live && raw.reverse {
            return Err(EventStreamError::InvalidParameter(
                "Cannot use live mode with reverse ordering".to_string(),
            ));
        }

        // Parse user values into (pubkey, optional_cursor) pairs
        // Format: "pubkey" or "pubkey:cursor"
        let mut user_cursors = Vec::new();
        for value in raw.user {
            if value.is_empty() {
                continue;
            }

            let (pubkey_str, cursor_str) = if let Some((pubkey, cursor)) = value.split_once(':') {
                (pubkey, Some(cursor))
            } else {
                (value.as_str(), None)
            };

            if PublicKey::is_pubky_prefixed(pubkey_str) {
                return Err(EventStreamError::InvalidPublicKey(pubkey_str.to_string()));
            }
            let pubkey = PublicKey::try_from_z32(pubkey_str)
                .map_err(|_| EventStreamError::InvalidPublicKey(pubkey_str.to_string()))?;

            user_cursors.push((pubkey, cursor_str.map(|s| s.to_string())));
        }

        if user_cursors.is_empty() {
            return Err(EventStreamError::InvalidParameter(
                "user parameter is required".to_string(),
            ));
        }

        if user_cursors.len() > MAX_EVENT_STREAM_USERS {
            return Err(EventStreamError::InvalidParameter(format!(
                "Too many users. Maximum allowed: {}",
                MAX_EVENT_STREAM_USERS
            )));
        }

        // Parse each repeated `path` value. Empty values were already dropped
        // during query parsing.
        let mut paths = Vec::with_capacity(raw.paths.len());
        for p in raw.paths {
            let normalized_path = if p.starts_with('/') {
                p
            } else {
                format!("/{}", p)
            };

            let path = StoragePath::normalize(&normalized_path).map_err(|_| {
                EventStreamError::InvalidParameter(format!("Invalid path: {}", normalized_path))
            })?;
            paths.push(path);
        }

        Ok(EventStreamQueryParams {
            limit: raw.limit,
            reverse: raw.reverse,
            live: raw.live,
            user_cursors,
            paths,
        })
    }
}

/// Render a batch of events as the plain-text feed body used by `GET /events/`.
///
/// One line per event (`<TYPE> pubky://<user>/<path>`), followed by a trailing
/// `cursor: <id>` line pointing at the last event so the caller can resume.
/// Returns an empty string when there are no events (and therefore no cursor line).
fn format_events_feed(events: &[EventEntity]) -> String {
    let mut result = events
        .iter()
        .map(|event| format!("{} {}", event.event_type, event.pubky_uri()))
        .collect::<Vec<String>>();

    if let Some(next_cursor) = events.last().map(|event| event.id.to_string()) {
        result.push(format!("cursor: {}", next_cursor));
    }

    result.join("\n")
}

/// Legacy text-based endpoint for fetching historical events.
///
/// This feed is public and unauthenticated: it returns events under
/// `/pub/...` exclusively and never exposes private (`/priv/...`) paths, even to
/// an authenticated caller.
///
/// ## Query Parameters
/// - `cursor` (optional): Starting cursor position. Default: "0" (beginning)
/// - `limit` (optional): Maximum number of events to return
///
/// ## Response Format
/// Plain text response with one line per event, followed by the next cursor:
/// ```text
/// PUT pubky://user_pubkey/pub/example.txt
/// DEL pubky://user_pubkey/pub/old.txt
/// PUT pubky://user_pubkey/pub/another.txt
/// cursor: 12345
/// ```
pub async fn feed(
    State(state): State<AppState>,
    params: ListQueryParams,
) -> HttpResult<impl IntoResponse> {
    let cursor = match params.cursor {
        Some(cursor) => cursor,
        None => "0".to_string(),
    };

    let cursor = match state
        .context
        .events_service
        .parse_cursor(cursor.as_str(), &mut state.context.sql_db.pool().into())
        .await
    {
        Ok(cursor) => cursor,
        Err(_e) => return Err(HttpError::bad_request("Invalid cursor")),
    };

    let query_start = Instant::now();
    let events = state
        .context
        .events_service
        .get_public_by_cursor(
            Some(cursor),
            params.limit,
            &mut state.context.sql_db.pool().into(),
        )
        .await?;
    state
        .context
        .metrics
        .record_events_db_query(query_start.elapsed().as_millis());

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(format_events_feed(&events)))
        .unwrap())
}

/// Server-Sent Events (SSE) endpoint for real-time event streaming.
///
/// Supports two modes:
/// - **Batch Mode** (`live=false` or omitted): Fetches historical events then closes connection
/// - **Streaming Mode** (`live=true`): Fetches historical events then streams new events in real-time
///
/// ## Slow Client Behavior
/// If a client cannot consume events fast enough in live mode, the broadcast channel will lag and the connection will be closed.
/// It is recommended that low memory clients poll this endpoint: Ie `live=true` with a low `limit`
///
/// ## Revocation Behavior
/// A stream that includes a private path is bound to the cookie or grant that
/// authorized it. It closes promptly when that credential is revoked. A mixed
/// public/private subscription closes as a whole; public-only streams are not
/// tied to authentication and remain unaffected. Credential expiry and bearer
/// token rotation are enforced when opening a stream and do not terminate an
/// already-open stream.
///
/// ## Response Format
/// Each event is sent as an SSE message with the event type and multiline data:
/// ```text
/// event: PUT
/// data: pubky://user_pubkey/pub/example.txt
/// data: cursor: 42
/// data: content_hash: r0NJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI=
/// ```
pub async fn feed_stream(
    State(state): State<AppState>,
    session: Option<AuthSession>,
    headers: HeaderMap,
    cookies: Cookies,
    raw_query: RawQuery,
) -> HttpResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let params =
        parse_query_params(raw_query.0.as_deref().unwrap_or("")).map_err(HttpError::from)?;
    let tenant_scope = EventStreamTenantScope::from_query(&params.paths, &params.user_cursors);

    // A presented Bearer disables both middleware-resolved and
    // homeserver-addressed cookie authentication for this endpoint.
    let session = match session {
        Some(AuthSession::Cookie(_)) if has_bearer_auth(&headers) => None,
        Some(session) => Some(session),
        None if !has_bearer_auth(&headers) => {
            resolve_tenant_cookie_session(&state, &cookies, tenant_scope).await
        }
        None => None,
    };

    let allowed_paths = authorized_paths(&params.paths, tenant_scope, session.as_ref())?;

    // Subscribe after path authorization but before the final DB validation.
    // The validation catches revocations committed before this subscription;
    // the receiver catches anything committed after it.
    let pending_stream_auth = PendingStreamAuth::subscribe(
        matches!(tenant_scope, EventStreamTenantScope::PrivateSingleTenant(_)),
        &state.auth_state,
    )
    .await
    .map_err(|_| {
        HttpError::new_with_message(
            StatusCode::SERVICE_UNAVAILABLE,
            "Private event streams are temporarily unavailable",
        )
    })?;

    let mut stream_auth = pending_stream_auth
        .authorize(session, &state.auth_state)
        .await?;

    let mut user_cursor_map = resolve_user_cursors(
        &params.user_cursors,
        &state.context.events_service,
        &state.context.sql_db,
        &state.context.user_service,
    )
    .await
    .map_err(HttpError::from)?;

    let mut total_sent: usize = 0;
    let stream = async_stream::stream! {
         // Create guard to ensure cleanup on any exit path (increments on creation, decrements on drop)
        let _guard = ConnectionGuard::new(state.context.metrics.clone());

        // Subscribe to broadcast channel immediately to prevent race condition
        // Events that occur during Phase 1 will be buffered in the channel
        let mut rx = state.context.events_service.subscribe();

        // Phase 1: Batch Mode
        loop {
            if !stream_auth.is_valid(&state.auth_state).await {
                return;
            }

            // Drain any buffered events before querying as they'll be included in this or a future database query
            while rx.try_recv().is_ok() {}

            let current_user_cursors: Vec<(i32, Option<EventCursor>)> =
                user_cursor_map.iter().map(|(k, cursor)| (*k, *cursor)).collect();

            let query_start = Instant::now();
            let events = match state
                .context
                .events_service
                .get_by_user_cursors(
                    current_user_cursors,
                    params.reverse,
                    &allowed_paths,
                    &mut state.context.sql_db.pool().into(),
                )
                .await
            {
                Ok(events) => events,
                Err(e) => {
                    tracing::error!("Database error while fetching events: {}", e);
                    break;
                }
            };
            state.context.metrics.record_event_stream_db_query(query_start.elapsed().as_millis());

            let event_count = events.len();

            // Stream each historical event
            for event in events {
                if !stream_auth.is_valid(&state.auth_state).await {
                    return;
                }

                // Update the cursor for this specific user
                user_cursor_map.insert(event.user_id, Some(event.cursor()));

                yield Ok(Event::default()
                    .event(event.event_type.to_string())
                    .data(event.to_sse_data()));

                total_sent += 1;

                // Close if we've reached limit
                if let Some(max) = params.limit {
                    if total_sent >= max as usize {
                        return;
                    }
                }
            }

            // If we got zero events, all users are caught up with history
            if event_count == 0 {
                // If not in live mode, close connection (batch mode)
                if !params.live {
                    return;
                }
                // Otherwise, transition to live mode
                break;
            }

            // If we got a partial batch (> 0 but less than read_batch_size), continue querying
            // Some users might still have more events even though this batch was partial
        }

        // Phase 2: Live mode
        if params.live {
            let user_ids: Vec<i32> = user_cursor_map.keys().copied().collect();
            let half_capacity = state.context.events_service.channel_capacity() / 2;

            loop {
                tokio::select! {
                    biased;
                    check = stream_auth.next_check(&state.auth_state) => {
                        if !check.await {
                            return;
                        }
                    }
                    event = rx.recv() => match event {
                        Ok(event) => {
                        // Check if receiver queue is at half capacity (early warning of slow clients)
                        if rx.len() >= half_capacity {
                            state.context.metrics.record_broadcast_half_full();
                        }
                        // Filter events based on user_ids, cursors, and path
                        if !should_include_live_event(&event, &user_ids, &user_cursor_map, &allowed_paths) {
                            continue;
                        }

                        // Update this user's cursor
                        user_cursor_map.insert(event.user_id, Some(event.cursor()));

                        yield Ok(Event::default()
                            .event(event.event_type.to_string())
                            .data(event.to_sse_data()));

                        total_sent += 1;

                        // Close if we've reached limit
                        if let Some(max) = params.limit {
                            if total_sent >= max as usize {
                                return;
                            }
                        }
                    }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            state.context.metrics.record_broadcast_lagged();
                            tracing::warn!(
                                "Slow client detected: broadcast channel lagged by {} events. Closing connection.",
                                skipped
                            );
                            return;
                        }
                        Err(_) => break, // Channel closed
                    }
                }
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Resolve user public keys to user IDs and parse their cursors.
/// Returns a map of user_id → optional cursor position.
async fn resolve_user_cursors(
    user_cursors: &[(PublicKey, Option<String>)],
    events_service: &EventsService,
    sql_db: &SqlDb,
    user_service: &crate::services::user_service::UserService,
) -> Result<HashMap<i32, Option<EventCursor>>, EventStreamError> {
    let mut user_cursor_map: HashMap<i32, Option<EventCursor>> = HashMap::new();

    for (user_pubkey, cursor_str_opt) in user_cursors {
        let user_id = user_service
            .get_id(user_pubkey)
            .await
            .map_err(|e| match e {
                sqlx::Error::RowNotFound => EventStreamError::UserNotFound,
                e => EventStreamError::DatabaseError(e),
            })?;

        let cursor = if let Some(cursor_str) = cursor_str_opt {
            Some(
                events_service
                    .parse_cursor(cursor_str, &mut sql_db.pool().into())
                    .await
                    .map_err(|_| {
                        EventStreamError::InvalidParameter(format!(
                            "Invalid cursor: {}",
                            cursor_str
                        ))
                    })?,
            )
        } else {
            None
        };

        user_cursor_map.insert(user_id, cursor);
    }

    Ok(user_cursor_map)
}

fn has_bearer_auth(headers: &HeaderMap) -> bool {
    extract_bearer_token(headers).has_bearer_scheme()
}

async fn resolve_tenant_cookie_session(
    state: &AppState,
    cookies: &Cookies,
    scope: EventStreamTenantScope<'_>,
) -> Option<AuthSession> {
    let EventStreamTenantScope::PrivateSingleTenant(tenant) = scope else {
        return None;
    };
    let cookie_value = cookies.get(&tenant.z32()).map(|c| c.value().to_string());
    state
        .auth_state
        .cookie_auth_service
        .resolve_session_from_cookie(cookie_value, tenant)
        .await
}

fn authorized_paths(
    paths: &[StoragePath],
    scope: EventStreamTenantScope<'_>,
    session: Option<&AuthSession>,
) -> Result<Vec<PathFilter>, HttpError> {
    if paths.is_empty() {
        return Ok(vec![StoragePath::new(PUBLIC_ROOT)
            .expect("public root is canonical")
            .into()]);
    }

    let mut allowed = Vec::with_capacity(paths.len());
    for path in paths {
        has_read_permission(session, scope.tenant(), path)?;
        allowed.push(path.clone().into());
    }
    Ok(allowed)
}

/// Filter events in live mode based on user IDs, cursors, and the authorized
/// paths.
fn should_include_live_event(
    event: &EventEntity,
    user_ids: &[i32],
    user_cursor_map: &HashMap<i32, Option<EventCursor>>,
    allowed_paths: &[PathFilter],
) -> bool {
    if !user_ids.contains(&event.user_id) {
        return false;
    }

    // Filter out events we already sent in Phase 1
    if let Some(Some(cursor)) = user_cursor_map.get(&event.user_id) {
        if event.cursor() <= *cursor {
            return false;
        }
    }

    // Apply the authorized filter set.
    let path = event.path.path().as_str();
    allowed_paths.iter().any(|filter| filter.matches(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_server::auth::cookie::persistence::{SessionEntity, SessionSecret};
    use crate::client_server::auth::grant::session::GrantSession;
    use pubky_common::auth::jws::GrantId;
    use pubky_common::capabilities::{Capabilities, Capability};
    use pubky_common::crypto::Keypair;

    fn pk() -> PublicKey {
        Keypair::random().public_key()
    }

    fn wd(s: &str) -> StoragePath {
        StoragePath::new(s).expect("valid test path")
    }

    fn pf(s: &str) -> PathFilter {
        wd(s).into()
    }

    fn grant_session(user_key: PublicKey, capabilities: Capabilities) -> AuthSession {
        AuthSession::Grant(GrantSession::test(
            user_key,
            capabilities,
            GrantId::generate(),
            9999999999,
        ))
    }

    fn cookie_session(user_key: PublicKey, capabilities: Capabilities) -> AuthSession {
        AuthSession::Cookie(SessionEntity {
            id: 1,
            secret: SessionSecret::random(),
            user_id: 1,
            user_pubkey: user_key,
            capabilities,
            created_at: sqlx::types::chrono::DateTime::from_timestamp(0, 0)
                .expect("valid timestamp")
                .naive_utc(),
        })
    }

    fn cursors(keys: &[&PublicKey]) -> Vec<(PublicKey, Option<String>)> {
        keys.iter().map(|k| ((*k).clone(), None)).collect()
    }

    fn reject_status(result: Result<Vec<PathFilter>, HttpError>) -> StatusCode {
        result
            .expect_err("expected the subscription to be rejected")
            .into_response()
            .status()
    }

    fn authorize(
        paths: &[StoragePath],
        user_cursors: &[(PublicKey, Option<String>)],
        session: Option<&AuthSession>,
    ) -> Result<Vec<PathFilter>, HttpError> {
        authorized_paths(
            paths,
            EventStreamTenantScope::from_query(paths, user_cursors),
            session,
        )
    }

    fn authorization_headers(value: axum::http::HeaderValue) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, value);
        headers
    }

    #[test]
    fn has_bearer_auth_uses_bearer_scheme() {
        let cases = [
            (b"Bearer token".as_slice(), true),
            (b"Bearer \xff".as_slice(), true),
            (b"Basic \xff".as_slice(), false),
        ];

        for (value, expected) in cases {
            let headers = authorization_headers(
                axum::http::HeaderValue::from_bytes(value).expect("valid header bytes"),
            );
            assert_eq!(has_bearer_auth(&headers), expected, "{value:?}");
        }
    }

    #[test]
    fn parse_repeated_paths_preserves_order_and_trailing_slash() {
        let q = format!(
            "user={}&path=/pub/&path=/priv/app/&path=/priv/file",
            pk().z32()
        );
        let params = parse_query_params(&q).unwrap();
        let strs: Vec<&str> = params.paths.iter().map(|p| p.as_str()).collect();
        assert_eq!(strs, vec!["/pub/", "/priv/app/", "/priv/file"]);
    }

    #[test]
    fn parse_ignores_empty_path_values() {
        let params =
            parse_query_params(&format!("user={}&path=&path=/pub/&path=", pk().z32())).unwrap();
        assert_eq!(
            params.paths.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
            vec!["/pub/"]
        );
    }

    #[test]
    fn parse_requires_user() {
        let err = parse_query_params("path=/pub/").unwrap_err();
        assert_eq!(
            HttpError::from(err).into_response().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn parse_rejects_zero_limit() {
        let err = parse_query_params(&format!("user={}&limit=0", pk().z32())).unwrap_err();
        assert_eq!(err.to_string(), "limit must be at least 1");
    }

    #[test]
    fn authorized_paths_defaults_to_public_dir_filter() {
        let u = pk();
        let filters = authorize(&[], &cursors(&[&u]), None).unwrap();
        assert_eq!(filters, vec![pf("/pub/")]);
    }

    #[test]
    fn authorized_paths_rejects_anonymous_private_path() {
        let u = pk();
        let status = reject_status(authorize(&[wd("/priv/app/")], &cursors(&[&u]), None));
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn authorized_paths_allows_cookie_session_own_private_path() {
        let owner = pk();
        let session = cookie_session(owner.clone(), Capabilities::from(vec![Capability::root()]));
        let filters = authorize(&[wd("/priv/app/")], &cursors(&[&owner]), Some(&session)).unwrap();
        assert_eq!(filters, vec![pf("/priv/app/")]);
    }

    #[test]
    fn authorized_paths_rejects_wrong_tenant() {
        let (a, b) = (pk(), pk());
        let session = cookie_session(a, Capabilities::from(vec![Capability::root()]));
        let status = reject_status(authorize(
            &[wd("/priv/app/")],
            &cursors(&[&b]),
            Some(&session),
        ));
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn authorized_paths_rejects_private_path_with_multiple_users() {
        let (a, b) = (pk(), pk());
        let session = grant_session(a.clone(), Capabilities::from(vec![Capability::root()]));
        let status = reject_status(authorize(
            &[wd("/priv/app/")],
            &cursors(&[&a, &b]),
            Some(&session),
        ));
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn authorized_paths_rejects_under_scoped_private_path() {
        let owner = pk();
        let session = grant_session(
            owner.clone(),
            Capabilities::from(vec![Capability::read("/priv/app/").unwrap()]),
        );
        let status = reject_status(authorize(
            &[wd("/priv/other/")],
            &cursors(&[&owner]),
            Some(&session),
        ));
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn authorized_paths_allows_mixed_public_and_private_union() {
        let owner = pk();
        let session = grant_session(
            owner.clone(),
            Capabilities::from(vec![Capability::read("/priv/app/").unwrap()]),
        );
        let filters = authorize(
            &[wd("/pub/"), wd("/priv/app/")],
            &cursors(&[&owner]),
            Some(&session),
        )
        .unwrap();
        assert_eq!(filters, vec![pf("/pub/"), pf("/priv/app/")]);
    }

    #[test]
    fn authorized_paths_allows_public_paths_with_multiple_users() {
        let (a, b) = (pk(), pk());
        let filters = authorize(&[wd("/pub/")], &cursors(&[&a, &b]), None).unwrap();
        assert_eq!(filters, vec![pf("/pub/")]);
    }
}
