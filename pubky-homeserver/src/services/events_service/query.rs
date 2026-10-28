//! Query-string parsing shared by the client and admin event streams.
//!
//! Both streams take the same `limit`, `live`, `reverse`, repeatable `path`
//! and repeatable `user` parameters. They differ only in how a stream
//! resumes, which [`StreamKind`] selects.

use pubky_common::crypto::PublicKey;
use url::form_urlencoded;

use super::{Mode, MAX_EVENT_STREAM_USERS};
use crate::{persistence::sql::events::EventCursor, shared::webdav::StoragePath};

/// Which event stream a query belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamKind {
    /// `GET /events-stream` on the client server: at least one `user=` is
    /// required, and each user resumes from its own `user=<pk>:<cursor>` suffix.
    Client,
    /// `GET /events-stream` on the admin server: `user=` is optional (absent
    /// means every user) and a single global `cursor=` resumes the feed.
    Admin,
}

/// Why an event stream request was rejected.
///
/// The parse failures come from [`EventStreamQuery::parse`]; the two lookup
/// variants are raised when a route resolves `user=` public keys to ids.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EventStreamError {
    #[error("User not found")]
    UserNotFound,
    #[error("Database error: {0}")]
    DatabaseError(#[source] sqlx::Error),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid cursor: {0}")]
    InvalidCursor(String),
    #[error("Invalid limit: {0}")]
    InvalidLimit(String),
    #[error("limit must be at least 1")]
    ZeroLimit,
    #[error("Cannot use live mode with reverse ordering")]
    LiveWithReverse,
    #[error("Too many users. Maximum allowed: {}", MAX_EVENT_STREAM_USERS)]
    TooManyUsers,
    #[error("user parameter is required")]
    UserRequired,
    #[error("Invalid path: {0}")]
    InvalidPath(String),
}

/// The only database access behind an event stream request is the `user=`
/// lookup, so a missing row means the requested user does not exist.
impl From<sqlx::Error> for EventStreamError {
    fn from(error: sqlx::Error) -> Self {
        match error {
            sqlx::Error::RowNotFound => Self::UserNotFound,
            error => Self::DatabaseError(error),
        }
    }
}

/// A parsed event stream request.
///
/// For [`StreamKind::Client`] every cursor is per user and `cursor` is `None`;
/// for [`StreamKind::Admin`] the per-user cursors are all `None` and `cursor`
/// is the global one.
#[derive(Debug)]
pub(crate) struct EventStreamQuery {
    /// Users to stream, in query order, each with its optional resume cursor.
    pub user_cursors: Vec<(PublicKey, Option<EventCursor>)>,
    /// Global resume cursor. `None` = from the beginning.
    pub cursor: Option<EventCursor>,
    /// Maximum total events to send before closing.
    pub limit: Option<u16>,
    /// Ordering + live behavior.
    pub mode: Mode,
    /// Path filters (repeatable; union). Each value is a path without the
    /// `pubky://` scheme or user pubkey, e.g. `/pub/files/` or `/priv/app/`.
    pub paths: Vec<StoragePath>,
}

impl EventStreamQuery {
    /// Parse a raw query string such as
    /// `user=<pk>&user=<pk>:<cursor>&path=/pub/&limit=10&live=true`.
    ///
    /// Unknown parameters and empty `user=` and `path=` values are ignored.
    pub(crate) fn parse(query: &str, kind: StreamKind) -> Result<Self, EventStreamError> {
        let mut user_cursors: Vec<(PublicKey, Option<EventCursor>)> = Vec::new();
        let mut cursor = None;
        let mut limit = None;
        let mut live = false;
        let mut reverse = false;
        let mut paths = Vec::new();

        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "user" if !value.is_empty() => {
                    let (pubkey, user_cursor) = parse_user(&value, kind)?;
                    // The admin stream has no per-user cursor, so a repeated user adds nothing.
                    if kind == StreamKind::Admin
                        && user_cursors.iter().any(|(known, _)| *known == pubkey)
                    {
                        continue;
                    }
                    user_cursors.push((pubkey, user_cursor));
                }
                "cursor" if kind == StreamKind::Admin && !value.is_empty() => {
                    cursor = Some(parse_cursor(&value)?);
                }
                "limit" => {
                    let parsed = value
                        .parse::<u16>()
                        .map_err(|_| EventStreamError::InvalidLimit(value.to_string()))?;
                    if parsed == 0 {
                        return Err(EventStreamError::ZeroLimit);
                    }
                    limit = Some(parsed);
                }
                "live" => live = is_true(&value),
                "reverse" => reverse = is_true(&value),
                "path" if !value.is_empty() => paths.push(parse_path(&value)?),
                _ => {} // Ignore unknown parameters
            }
        }

        // Collapse the two flags into a mode; the incompatible combination is
        // rejected here so nothing downstream can represent it.
        let mode = match (live, reverse) {
            (false, false) => Mode::Forward,
            (true, false) => Mode::ForwardLive,
            (false, true) => Mode::Reverse,
            (true, true) => return Err(EventStreamError::LiveWithReverse),
        };
        if kind == StreamKind::Client && user_cursors.is_empty() {
            return Err(EventStreamError::UserRequired);
        }
        if user_cursors.len() > MAX_EVENT_STREAM_USERS {
            return Err(EventStreamError::TooManyUsers);
        }

        Ok(Self {
            user_cursors,
            cursor,
            limit,
            mode,
            paths,
        })
    }
}

/// Parse one `user=` value: `<pk>` or, for the client stream, `<pk>:<cursor>`.
fn parse_user(
    value: &str,
    kind: StreamKind,
) -> Result<(PublicKey, Option<EventCursor>), EventStreamError> {
    let (pubkey, cursor) = match kind {
        StreamKind::Client => match value.split_once(':') {
            Some((pubkey, cursor)) => (pubkey, Some(cursor)),
            None => (value, None),
        },
        StreamKind::Admin => (value, None),
    };

    if PublicKey::is_pubky_prefixed(pubkey) {
        return Err(EventStreamError::InvalidPublicKey(pubkey.to_string()));
    }
    let pubkey = PublicKey::try_from_z32(pubkey)
        .map_err(|_| EventStreamError::InvalidPublicKey(pubkey.to_string()))?;
    let cursor = cursor.map(parse_cursor).transpose()?;
    Ok((pubkey, cursor))
}

fn parse_cursor(value: &str) -> Result<EventCursor, EventStreamError> {
    value
        .parse()
        .map_err(|_| EventStreamError::InvalidCursor(value.to_string()))
}

fn parse_path(value: &str) -> Result<StoragePath, EventStreamError> {
    // Prepend "/" if missing, for caller convenience.
    let normalized = if value.starts_with('/') {
        value.to_string()
    } else {
        format!("/{value}")
    };
    StoragePath::normalize(&normalized).map_err(|_| EventStreamError::InvalidPath(normalized))
}

fn is_true(value: &str) -> bool {
    value == "true" || value == "1"
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Keypair;

    use super::*;

    fn pk() -> PublicKey {
        Keypair::random().public_key()
    }

    fn message(query: &str, kind: StreamKind) -> String {
        EventStreamQuery::parse(query, kind)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn client_splits_per_user_cursor() {
        let u = pk();
        let q = EventStreamQuery::parse(
            &format!("user={}:42&user={}", u.z32(), pk().z32()),
            StreamKind::Client,
        )
        .unwrap();
        assert_eq!(q.user_cursors[0], (u, Some(EventCursor::new(42))));
        assert_eq!(q.user_cursors[1].1, None);
        assert_eq!(q.cursor, None);
    }

    #[test]
    fn client_rejects_non_numeric_per_user_cursor() {
        // Legacy timestamp cursors and out-of-range ids are rejected alike.
        for cursor in ["yyyyyyyyyyyyy", "-1", "18446744073709551616", ""] {
            let msg = message(&format!("user={}:{cursor}", pk().z32()), StreamKind::Client);
            assert_eq!(msg, format!("Invalid cursor: {cursor}"));
        }
    }

    #[test]
    fn client_requires_user_and_ignores_global_cursor() {
        assert_eq!(
            message("path=/pub/", StreamKind::Client),
            "user parameter is required"
        );
        let q = EventStreamQuery::parse(
            &format!("user={}&cursor=42", pk().z32()),
            StreamKind::Client,
        )
        .unwrap();
        assert_eq!(q.cursor, None);
    }

    #[test]
    fn admin_parses_global_cursor() {
        let q = EventStreamQuery::parse("cursor=42", StreamKind::Admin).unwrap();
        assert_eq!(q.cursor, Some(EventCursor::new(42)));
        assert!(q.user_cursors.is_empty());
        assert_eq!(
            EventStreamQuery::parse("cursor=", StreamKind::Admin)
                .unwrap()
                .cursor,
            None
        );
    }

    #[test]
    fn admin_rejects_non_numeric_cursor() {
        for cursor in ["yyyyyyyyyyyyy", "-1", "18446744073709551616"] {
            let msg = message(&format!("cursor={cursor}"), StreamKind::Admin);
            assert_eq!(msg, format!("Invalid cursor: {cursor}"));
        }
    }

    #[test]
    fn admin_treats_per_user_cursor_as_invalid_public_key() {
        let value = format!("{}:42", pk().z32());
        assert_eq!(
            message(&format!("user={value}"), StreamKind::Admin),
            format!("Invalid public key: {value}")
        );
    }

    #[test]
    fn admin_dedups_repeated_users() {
        let u = pk();
        let q = EventStreamQuery::parse(
            &format!("user={}&user={}", u.z32(), u.z32()),
            StreamKind::Admin,
        )
        .unwrap();
        assert_eq!(q.user_cursors, vec![(u, None)]);
    }

    #[test]
    fn rejects_invalid_public_key() {
        for kind in [StreamKind::Client, StreamKind::Admin] {
            assert_eq!(
                message("user=not-a-key", kind),
                "Invalid public key: not-a-key"
            );
        }
    }

    #[test]
    fn rejects_zero_and_malformed_limit() {
        let user = format!("user={}", pk().z32());
        for kind in [StreamKind::Client, StreamKind::Admin] {
            assert_eq!(
                message(&format!("{user}&limit=0"), kind),
                "limit must be at least 1"
            );
            assert_eq!(
                message(&format!("{user}&limit=ten"), kind),
                "Invalid limit: ten"
            );
        }
    }

    #[test]
    fn flags_collapse_into_mode() {
        let user = format!("user={}", pk().z32());
        for kind in [StreamKind::Client, StreamKind::Admin] {
            assert_eq!(
                EventStreamQuery::parse(&user, kind).unwrap().mode,
                Mode::Forward
            );
            assert_eq!(
                EventStreamQuery::parse(&format!("{user}&live=1"), kind)
                    .unwrap()
                    .mode,
                Mode::ForwardLive
            );
            assert_eq!(
                EventStreamQuery::parse(&format!("{user}&reverse=true"), kind)
                    .unwrap()
                    .mode,
                Mode::Reverse
            );
            assert_eq!(
                message(&format!("{user}&live=true&reverse=true"), kind),
                "Cannot use live mode with reverse ordering"
            );
        }
    }

    #[test]
    fn rejects_too_many_users() {
        let query = (0..=MAX_EVENT_STREAM_USERS)
            .map(|_| format!("user={}", pk().z32()))
            .collect::<Vec<_>>()
            .join("&");
        for kind in [StreamKind::Client, StreamKind::Admin] {
            assert_eq!(
                message(&query, kind),
                format!("Too many users. Maximum allowed: {MAX_EVENT_STREAM_USERS}")
            );
        }
    }

    #[test]
    fn paths_keep_order_and_trailing_slash_and_skip_empty_values() {
        let q = EventStreamQuery::parse(
            &format!(
                "user={}&path=&path=/pub/&path=priv/app/&path=/priv/file&path=",
                pk().z32()
            ),
            StreamKind::Client,
        )
        .unwrap();
        let paths: Vec<&str> = q.paths.iter().map(|p| p.as_str()).collect();
        assert_eq!(paths, vec!["/pub/", "/priv/app/", "/priv/file"]);
    }

    #[test]
    fn rejects_invalid_path() {
        // Traversal above the storage root is one of the shapes `normalize` refuses.
        assert_eq!(
            message(
                &format!("user={}&path=/../x", pk().z32()),
                StreamKind::Client
            ),
            "Invalid path: /../x"
        );
    }
}
