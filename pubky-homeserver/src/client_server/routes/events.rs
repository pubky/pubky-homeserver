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
use futures_util::{Stream, StreamExt};
use pubky_common::crypto::PublicKey;
use std::{convert::Infallible, time::Instant};
use tower_cookies::Cookies;

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
    persistence::sql::events::{EventCursor, EventEntity, PathFilter},
    services::{
        events_service::{ClientStreamQuery, EventStreamError, UserEventsFilter},
        user_service::UserService,
    },
    shared::{webdav::StoragePath, HttpError, HttpResult},
};

#[derive(Clone, Copy)]
enum EventStreamTenantScope<'a> {
    PublicOnly,
    PrivateSingleTenant(&'a PublicKey),
    PrivateUnsupported,
}

impl<'a> EventStreamTenantScope<'a> {
    fn from_query(
        paths: &[StoragePath],
        user_cursors: &'a [(PublicKey, Option<EventCursor>)],
    ) -> Self {
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
    let cursor = params.cursor.as_deref().unwrap_or("0");
    let cursor = cursor
        .parse::<EventCursor>()
        .map_err(|_| HttpError::bad_request(format!("Invalid cursor: {cursor}")))?;

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
    let query = ClientStreamQuery::parse(raw_query.0.as_deref().unwrap_or(""))?;
    let tenant_scope = EventStreamTenantScope::from_query(&query.paths, &query.user_cursors);

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

    let allowed_paths = authorized_paths(&query.paths, tenant_scope, session.as_ref())?;

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

    let stream_auth = pending_stream_auth
        .authorize(session, &state.auth_state)
        .await?;

    let user_cursors = resolve_user_ids(&query.user_cursors, &state.context.user_service).await?;

    let stream = state
        .context
        .events_service
        .user_events_stream(
            state.context.metrics.clone(),
            UserEventsFilter {
                user_cursors,
                allowed_paths,
                mode: query.mode,
                limit: query.limit,
            },
            stream_auth,
        )
        .map(|event| Ok::<_, Infallible>(event.to_sse_event()));

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Resolve user public keys to user IDs, keeping each user's cursor.
async fn resolve_user_ids(
    user_cursors: &[(PublicKey, Option<EventCursor>)],
    user_service: &UserService,
) -> Result<Vec<(i32, Option<EventCursor>)>, EventStreamError> {
    let pubkeys: Vec<PublicKey> = user_cursors.iter().map(|(pk, _)| pk.clone()).collect();
    let ids = user_service.get_ids(&pubkeys).await?;
    let cursors = user_cursors.iter().map(|(_, cursor)| *cursor);
    Ok(ids.into_iter().zip(cursors).collect())
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

    fn cursors(keys: &[&PublicKey]) -> Vec<(PublicKey, Option<EventCursor>)> {
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
        user_cursors: &[(PublicKey, Option<EventCursor>)],
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
