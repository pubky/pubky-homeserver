//! Query-string parsing for the client and admin event streams.
//!
//! Both streams take the same `limit`, `live`, `reverse`, repeatable `path`
//! and repeatable `user` parameters. They differ only in how a stream
//! resumes: [`ClientStreamQuery`] carries one cursor per user,
//! [`AdminStreamQuery`] one global cursor.

use pubky_common::crypto::PublicKey;
use url::form_urlencoded;

use super::{Mode, MAX_EVENT_STREAM_USERS};
use crate::{persistence::sql::events::EventCursor, shared::webdav::StoragePath};

/// Why an event stream request was rejected.
///
/// The parse failures come from [`ClientStreamQuery::parse`] and
/// [`AdminStreamQuery::parse`]; the two lookup variants are raised when a
/// route resolves `user=` public keys to ids.
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

/// A parsed `GET /events-stream` request on the client server: at least one
/// `user=` is required, and each user resumes from its own
/// `user=<pk>:<cursor>` suffix.
#[derive(Debug)]
pub(crate) struct ClientStreamQuery {
    /// Users to stream, in query order, each with its optional resume cursor.
    pub user_cursors: Vec<(PublicKey, Option<EventCursor>)>,
    /// Maximum total events to send before closing.
    pub limit: Option<u16>,
    /// Ordering + live behavior.
    pub mode: Mode,
    /// Path filters (repeatable; union). Each value is a path without the
    /// `pubky://` scheme or user pubkey, e.g. `/pub/files/` or `/priv/app/`.
    pub paths: Vec<StoragePath>,
}

impl ClientStreamQuery {
    /// Parse a raw query string such as
    /// `user=<pk>&user=<pk>:<cursor>&path=/pub/&limit=10&live=true`.
    ///
    /// Unknown parameters (including a global `cursor`) and empty `user=`,
    /// `path=` and cursor-suffix values are ignored. A repeated user is one
    /// subscription that resumes from the last cursor given for it.
    pub(crate) fn parse(query: &str) -> Result<Self, EventStreamError> {
        let mut user_cursors: Vec<(PublicKey, Option<EventCursor>)> = Vec::new();
        let mut shared = SharedParams::default();

        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "user" if !value.is_empty() => {
                    let (pubkey, cursor) = match value.split_once(':') {
                        Some((pubkey, cursor)) => (pubkey, Some(cursor).filter(|c| !c.is_empty())),
                        None => (value.as_ref(), None),
                    };
                    let pubkey = parse_public_key(pubkey)?;
                    let cursor = cursor.map(parse_cursor).transpose()?;
                    match user_cursors.iter_mut().find(|(known, _)| *known == pubkey) {
                        Some(known) => known.1 = cursor,
                        None => user_cursors.push((pubkey, cursor)),
                    }
                }
                key => shared.parse(key, &value)?,
            }
        }

        let mode = shared.mode()?;
        if user_cursors.is_empty() {
            return Err(EventStreamError::UserRequired);
        }
        check_user_count(user_cursors.len())?;

        Ok(Self {
            user_cursors,
            limit: shared.limit,
            mode,
            paths: shared.paths,
        })
    }
}

/// A parsed `GET /events-stream` request on the admin server: `user=` is an
/// optional filter (absent means every user) and a single global `cursor=`
/// resumes the feed.
#[derive(Debug)]
pub(crate) struct AdminStreamQuery {
    /// Users to stream, in query order and without repeats. Empty = all users.
    pub users: Vec<PublicKey>,
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

impl AdminStreamQuery {
    /// Parse a raw query string such as
    /// `user=<pk>&cursor=42&path=/priv/&limit=10&live=true`.
    ///
    /// Unknown parameters and empty `user=`, `cursor=` and `path=` values are
    /// ignored. A per-user cursor suffix is not accepted.
    pub(crate) fn parse(query: &str) -> Result<Self, EventStreamError> {
        let mut users: Vec<PublicKey> = Vec::new();
        let mut cursor = None;
        let mut shared = SharedParams::default();

        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "user" if !value.is_empty() => {
                    let pubkey = parse_public_key(&value)?;
                    // Without per-user cursors a repeated user adds nothing.
                    if !users.contains(&pubkey) {
                        users.push(pubkey);
                    }
                }
                "cursor" if !value.is_empty() => cursor = Some(parse_cursor(&value)?),
                key => shared.parse(key, &value)?,
            }
        }

        let mode = shared.mode()?;
        check_user_count(users.len())?;

        Ok(Self {
            users,
            cursor,
            limit: shared.limit,
            mode,
            paths: shared.paths,
        })
    }
}

/// The parameters both streams accept, accumulated while walking the query.
#[derive(Default)]
struct SharedParams {
    limit: Option<u16>,
    live: bool,
    reverse: bool,
    paths: Vec<StoragePath>,
}

impl SharedParams {
    /// Consume one key/value pair. Unknown keys are ignored.
    fn parse(&mut self, key: &str, value: &str) -> Result<(), EventStreamError> {
        match key {
            "limit" => {
                let parsed = value
                    .parse::<u16>()
                    .map_err(|_| EventStreamError::InvalidLimit(value.to_string()))?;
                if parsed == 0 {
                    return Err(EventStreamError::ZeroLimit);
                }
                self.limit = Some(parsed);
            }
            "live" => self.live = is_true(value),
            "reverse" => self.reverse = is_true(value),
            "path" if !value.is_empty() => self.paths.push(parse_path(value)?),
            _ => {}
        }
        Ok(())
    }

    /// Collapse the two flags into a mode; the incompatible combination is
    /// rejected here so nothing downstream can represent it.
    fn mode(&self) -> Result<Mode, EventStreamError> {
        match (self.live, self.reverse) {
            (false, false) => Ok(Mode::Forward),
            (true, false) => Ok(Mode::ForwardLive),
            (false, true) => Ok(Mode::Reverse),
            (true, true) => Err(EventStreamError::LiveWithReverse),
        }
    }
}

fn check_user_count(count: usize) -> Result<(), EventStreamError> {
    if count > MAX_EVENT_STREAM_USERS {
        return Err(EventStreamError::TooManyUsers);
    }
    Ok(())
}

fn parse_public_key(value: &str) -> Result<PublicKey, EventStreamError> {
    if PublicKey::is_pubky_prefixed(value) {
        return Err(EventStreamError::InvalidPublicKey(value.to_string()));
    }
    PublicKey::try_from_z32(value)
        .map_err(|_| EventStreamError::InvalidPublicKey(value.to_string()))
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

    fn client_message(query: &str) -> String {
        ClientStreamQuery::parse(query).unwrap_err().to_string()
    }

    fn admin_message(query: &str) -> String {
        AdminStreamQuery::parse(query).unwrap_err().to_string()
    }

    /// The rejection both routes give the same query.
    fn messages(query: &str) -> [String; 2] {
        [client_message(query), admin_message(query)]
    }

    #[test]
    fn client_splits_per_user_cursor() {
        let u = pk();
        let q =
            ClientStreamQuery::parse(&format!("user={}:42&user={}", u.z32(), pk().z32())).unwrap();
        assert_eq!(q.user_cursors[0], (u, Some(EventCursor::new(42))));
        assert_eq!(q.user_cursors[1].1, None);
    }

    #[test]
    fn client_rejects_non_numeric_per_user_cursor() {
        // Legacy timestamp cursors and out-of-range ids are rejected alike.
        for cursor in ["yyyyyyyyyyyyy", "-1", "18446744073709551616"] {
            let msg = client_message(&format!("user={}:{cursor}", pk().z32()));
            assert_eq!(msg, format!("Invalid cursor: {cursor}"));
        }
    }

    #[test]
    fn client_treats_empty_cursor_suffix_as_absent() {
        let q = ClientStreamQuery::parse(&format!("user={}:", pk().z32())).unwrap();
        assert_eq!(q.user_cursors[0].1, None);
    }

    #[test]
    fn client_dedups_repeated_users_keeping_the_last_cursor() {
        let (a, b) = (pk(), pk());
        let q = ClientStreamQuery::parse(&format!(
            "user={}:10&user={}&user={}:20&user={}",
            a.z32(),
            b.z32(),
            a.z32(),
            b.z32()
        ))
        .unwrap();
        assert_eq!(
            q.user_cursors,
            vec![(a, Some(EventCursor::new(20))), (b, None)]
        );
    }

    #[test]
    fn client_requires_user_and_ignores_global_cursor() {
        assert_eq!(client_message("path=/pub/"), "user parameter is required");
        let q = ClientStreamQuery::parse(&format!("user={}&cursor=42", pk().z32())).unwrap();
        assert_eq!(q.user_cursors[0].1, None);
    }

    #[test]
    fn admin_parses_global_cursor() {
        let q = AdminStreamQuery::parse("cursor=42").unwrap();
        assert_eq!(q.cursor, Some(EventCursor::new(42)));
        assert!(q.users.is_empty());
        assert_eq!(AdminStreamQuery::parse("cursor=").unwrap().cursor, None);
    }

    #[test]
    fn admin_rejects_non_numeric_cursor() {
        for cursor in ["yyyyyyyyyyyyy", "-1", "18446744073709551616"] {
            let msg = admin_message(&format!("cursor={cursor}"));
            assert_eq!(msg, format!("Invalid cursor: {cursor}"));
        }
    }

    #[test]
    fn admin_treats_per_user_cursor_as_invalid_public_key() {
        let value = format!("{}:42", pk().z32());
        assert_eq!(
            admin_message(&format!("user={value}")),
            format!("Invalid public key: {value}")
        );
    }

    #[test]
    fn admin_dedups_repeated_users() {
        let u = pk();
        let q = AdminStreamQuery::parse(&format!("user={}&user={}", u.z32(), u.z32())).unwrap();
        assert_eq!(q.users, vec![u]);
    }

    #[test]
    fn rejects_invalid_public_key() {
        for msg in messages("user=not-a-key") {
            assert_eq!(msg, "Invalid public key: not-a-key");
        }
    }

    #[test]
    fn rejects_zero_and_malformed_limit() {
        let user = format!("user={}", pk().z32());
        for msg in messages(&format!("{user}&limit=0")) {
            assert_eq!(msg, "limit must be at least 1");
        }
        for msg in messages(&format!("{user}&limit=ten")) {
            assert_eq!(msg, "Invalid limit: ten");
        }
    }

    #[test]
    fn flags_collapse_into_mode() {
        let user = format!("user={}", pk().z32());
        let modes = |suffix: &str| {
            let query = format!("{user}{suffix}");
            [
                ClientStreamQuery::parse(&query).unwrap().mode,
                AdminStreamQuery::parse(&query).unwrap().mode,
            ]
        };
        assert_eq!(modes(""), [Mode::Forward; 2]);
        assert_eq!(modes("&live=1"), [Mode::ForwardLive; 2]);
        assert_eq!(modes("&reverse=true"), [Mode::Reverse; 2]);
        for msg in messages(&format!("{user}&live=true&reverse=true")) {
            assert_eq!(msg, "Cannot use live mode with reverse ordering");
        }
    }

    #[test]
    fn rejects_too_many_distinct_users() {
        let query = (0..=MAX_EVENT_STREAM_USERS)
            .map(|_| format!("user={}", pk().z32()))
            .collect::<Vec<_>>()
            .join("&");
        for msg in messages(&query) {
            assert_eq!(
                msg,
                format!("Too many users. Maximum allowed: {MAX_EVENT_STREAM_USERS}")
            );
        }

        // Repeats of one user count once.
        let repeated = vec![format!("user={}", pk().z32()); MAX_EVENT_STREAM_USERS + 1].join("&");
        assert!(ClientStreamQuery::parse(&repeated).is_ok());
        assert!(AdminStreamQuery::parse(&repeated).is_ok());
    }

    #[test]
    fn paths_keep_order_and_trailing_slash_and_skip_empty_values() {
        let query = format!(
            "user={}&path=&path=/pub/&path=priv/app/&path=/priv/file&path=",
            pk().z32()
        );
        let expected = ["/pub/", "/priv/app/", "/priv/file"];
        let client = ClientStreamQuery::parse(&query).unwrap();
        let admin = AdminStreamQuery::parse(&query).unwrap();
        for paths in [client.paths, admin.paths] {
            let paths: Vec<&str> = paths.iter().map(|p| p.as_str()).collect();
            assert_eq!(paths, expected);
        }
    }

    #[test]
    fn rejects_invalid_path() {
        // Traversal above the storage root is one of the shapes `normalize` refuses.
        for msg in messages(&format!("user={}&path=/../x", pk().z32())) {
            assert_eq!(msg, "Invalid path: /../x");
        }
    }
}
