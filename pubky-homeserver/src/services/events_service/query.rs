//! Query-string parsing shared by the client and admin event streams.
//!
//! Both streams take the same `cursor`, repeatable `user`, `limit`, `live`,
//! `reverse` and repeatable `path` parameters and resume in one of two ways
//! ([`Resume`]). The servers differ only in auth and visibility, which the
//! routes apply after parsing.

use pubky_common::crypto::PublicKey;
use url::form_urlencoded;

use super::{Mode, StreamCursor, MAX_EVENT_STREAM_USERS};
use crate::{
    constants::DEFAULT_LIST_LIMIT, persistence::sql::events::EventCursor,
    services::user_service::UserService, shared::webdav::StoragePath,
};

/// Why an event stream request was rejected.
///
/// The parse failures come from [`EventStreamQuery::parse`]; the two lookup
/// variants are raised when [`Resume::resolve`] maps `user=` public keys to
/// ids.
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
    #[error("Cannot combine cursor with per-user cursors")]
    MixedCursors,
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

/// Where a stream resumes from: one of the two forms a request may use.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Resume {
    /// One cursor over the combined feed (`None` = from the beginning),
    /// optionally restricted to `users` (empty = every user).
    Global {
        cursor: Option<EventCursor>,
        users: Vec<PublicKey>,
    },
    /// Only these users, each from its own cursor (`None` = from the beginning).
    PerUser(Vec<(PublicKey, Option<EventCursor>)>),
}

impl Resume {
    /// Users to stream, in query order; empty means every user.
    pub(crate) fn users(&self) -> Vec<&PublicKey> {
        match self {
            Self::Global { users, .. } => users.iter().collect(),
            Self::PerUser(user_cursors) => user_cursors.iter().map(|(pk, _)| pk).collect(),
        }
    }

    /// Map the public keys to user ids, keeping each cursor. An unknown user
    /// is [`EventStreamError::UserNotFound`].
    pub(crate) async fn resolve(
        self,
        user_service: &UserService,
    ) -> Result<StreamCursor, EventStreamError> {
        Ok(match self {
            Self::Global { cursor, users } => StreamCursor::Global {
                last: cursor,
                user_ids: if users.is_empty() {
                    None
                } else {
                    Some(user_service.get_ids(&users).await?)
                },
            },
            Self::PerUser(user_cursors) => {
                let pubkeys: Vec<PublicKey> =
                    user_cursors.iter().map(|(pk, _)| pk.clone()).collect();
                let ids = user_service.get_ids(&pubkeys).await?;
                let cursors = user_cursors.into_iter().map(|(_, cursor)| cursor);
                StreamCursor::PerUser(ids.into_iter().zip(cursors).collect())
            }
        })
    }
}

/// A parsed `GET /events-stream` request.
#[derive(Debug)]
pub(crate) struct EventStreamQuery {
    /// Which users to stream and where each resumes from; see [`Resume`].
    pub resume: Resume,
    /// Maximum total events to send before closing.
    pub limit: Option<u16>,
    /// Ordering + live behavior.
    pub mode: Mode,
    /// Path filters (repeatable; union). Each value is a path without the
    /// `pubky://` scheme or user pubkey, e.g. `/pub/files/` or `/priv/app/`.
    pub paths: Vec<StoragePath>,
}

impl EventStreamQuery {
    /// Parse a raw query string such as `cursor=42&user=<pk>&path=/pub/&live=true`
    /// or `user=<pk>:<cursor>&user=<pk>&limit=10`.
    ///
    /// A request resumes either from a global `cursor=` (optionally filtered
    /// by `user=`) or from per-user `user=<pk>:<cursor>` suffixes; giving both
    /// is rejected. Unknown parameters and empty `user=`, `cursor=`, `path=`
    /// and suffix values are ignored. A repeated user is one subscription that
    /// resumes from the last cursor given for it. A batch request over every
    /// user defaults `limit` to the legacy feed's page size.
    pub(crate) fn parse(query: &str) -> Result<Self, EventStreamError> {
        let mut user_cursors: Vec<(PublicKey, Option<EventCursor>)> = Vec::new();
        let mut cursor = None;
        let mut shared = SharedParams::default();

        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "user" if !value.is_empty() => {
                    let (pubkey, suffix) = match value.split_once(':') {
                        Some((pubkey, suffix)) => (pubkey, Some(suffix).filter(|c| !c.is_empty())),
                        None => (value.as_ref(), None),
                    };
                    let pubkey = parse_public_key(pubkey)?;
                    let suffix = suffix.map(parse_cursor).transpose()?;
                    match user_cursors.iter_mut().find(|(known, _)| *known == pubkey) {
                        // A bare repeat must not drop a suffix given earlier, or
                        // `user=<pk>:10&user=<pk>` would silently become the global form.
                        Some(known) => known.1 = suffix.or(known.1),
                        None => user_cursors.push((pubkey, suffix)),
                    }
                }
                "cursor" if !value.is_empty() => cursor = Some(parse_cursor(&value)?),
                key => shared.parse(key, &value)?,
            }
        }

        let mode = shared.mode()?;
        if user_cursors.len() > MAX_EVENT_STREAM_USERS {
            return Err(EventStreamError::TooManyUsers);
        }

        let has_suffix = user_cursors.iter().any(|(_, suffix)| suffix.is_some());
        let resume = match (cursor, has_suffix) {
            (Some(_), true) => return Err(EventStreamError::MixedCursors),
            (None, true) => Resume::PerUser(user_cursors),
            (cursor, false) => Resume::Global {
                cursor,
                users: user_cursors.into_iter().map(|(pk, _)| pk).collect(),
            },
        };

        let all_users = matches!(&resume, Resume::Global { users, .. } if users.is_empty());
        let limit = if all_users && !mode.live() {
            shared.limit.or(Some(DEFAULT_LIST_LIMIT))
        } else {
            shared.limit
        };

        Ok(Self {
            resume,
            limit,
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

    fn parse(query: &str) -> EventStreamQuery {
        EventStreamQuery::parse(query).unwrap()
    }

    fn message(query: &str) -> String {
        EventStreamQuery::parse(query).unwrap_err().to_string()
    }

    #[test]
    fn per_user_suffixes_resume_each_user() {
        let (a, b) = (pk(), pk());
        let q = parse(&format!("user={}:42&user={}", a.z32(), b.z32()));
        assert_eq!(
            q.resume,
            Resume::PerUser(vec![(a, Some(EventCursor::new(42))), (b, None)])
        );
        assert_eq!(q.limit, None);
    }

    #[test]
    fn global_cursor_with_optional_user_filter() {
        let u = pk();
        assert_eq!(
            parse("cursor=42").resume,
            Resume::Global {
                cursor: Some(EventCursor::new(42)),
                users: vec![],
            }
        );
        assert_eq!(
            parse(&format!("user={}&cursor=42", u.z32())).resume,
            Resume::Global {
                cursor: Some(EventCursor::new(42)),
                users: vec![u.clone()],
            }
        );
        // No cursor anywhere is the global form from the beginning.
        assert_eq!(
            parse(&format!("user={}", u.z32())).resume,
            Resume::Global {
                cursor: None,
                users: vec![u],
            }
        );
    }

    #[test]
    fn rejects_mixing_global_and_per_user_cursors() {
        assert_eq!(
            message(&format!("user={}:1&cursor=42", pk().z32())),
            "Cannot combine cursor with per-user cursors"
        );
    }

    #[test]
    fn rejects_non_numeric_cursors() {
        // Legacy timestamp cursors and out-of-range ids are rejected alike.
        for cursor in ["yyyyyyyyyyyyy", "-1", "18446744073709551616"] {
            assert_eq!(
                message(&format!("user={}:{cursor}", pk().z32())),
                format!("Invalid cursor: {cursor}")
            );
            assert_eq!(
                message(&format!("cursor={cursor}")),
                format!("Invalid cursor: {cursor}")
            );
        }
    }

    #[test]
    fn empty_cursor_values_are_ignored() {
        let u = pk();
        assert_eq!(
            parse(&format!("user={}:&cursor=", u.z32())).resume,
            Resume::Global {
                cursor: None,
                users: vec![u],
            }
        );
    }

    #[test]
    fn repeated_user_counts_once_keeping_the_last_cursor() {
        let (a, b) = (pk(), pk());
        let q = parse(&format!(
            "user={}:10&user={}&user={}:20&user={}",
            a.z32(),
            b.z32(),
            a.z32(),
            b.z32()
        ));
        assert_eq!(
            q.resume,
            Resume::PerUser(vec![
                (a.clone(), Some(EventCursor::new(20))),
                (b.clone(), None)
            ])
        );
        // A bare repeat after a suffix does not drop the cursor.
        assert_eq!(
            parse(&format!("user={}:10&user={}", a.z32(), a.z32())).resume,
            Resume::PerUser(vec![(a.clone(), Some(EventCursor::new(10)))])
        );
        assert_eq!(
            parse(&format!("user={}&user={}", a.z32(), a.z32())).resume,
            Resume::Global {
                cursor: None,
                users: vec![a],
            }
        );
    }

    #[test]
    fn all_users_batch_requests_default_the_limit() {
        assert_eq!(parse("").limit, Some(DEFAULT_LIST_LIMIT));
        assert_eq!(
            parse("cursor=42&reverse=true").limit,
            Some(DEFAULT_LIST_LIMIT)
        );
        assert_eq!(parse("limit=7").limit, Some(7));
        // A live stream and a filtered request keep today's no-default behaviour.
        assert_eq!(parse("live=true").limit, None);
        assert_eq!(parse(&format!("user={}", pk().z32())).limit, None);
        assert_eq!(parse(&format!("user={}:1", pk().z32())).limit, None);
    }

    #[test]
    fn rejects_invalid_public_key() {
        assert_eq!(message("user=not-a-key"), "Invalid public key: not-a-key");
        let prefixed = format!("pubky{}", pk().z32());
        assert_eq!(
            message(&format!("user={prefixed}")),
            format!("Invalid public key: {prefixed}")
        );
    }

    #[test]
    fn rejects_zero_and_malformed_limit() {
        assert_eq!(message("limit=0"), "limit must be at least 1");
        assert_eq!(message("limit=ten"), "Invalid limit: ten");
    }

    #[test]
    fn flags_collapse_into_mode() {
        assert_eq!(parse("").mode, Mode::Forward);
        assert_eq!(parse("live=1").mode, Mode::ForwardLive);
        assert_eq!(parse("reverse=true").mode, Mode::Reverse);
        assert_eq!(
            message("live=true&reverse=true"),
            "Cannot use live mode with reverse ordering"
        );
    }

    #[test]
    fn rejects_too_many_distinct_users() {
        let query = (0..=MAX_EVENT_STREAM_USERS)
            .map(|_| format!("user={}", pk().z32()))
            .collect::<Vec<_>>()
            .join("&");
        assert_eq!(
            message(&query),
            format!("Too many users. Maximum allowed: {MAX_EVENT_STREAM_USERS}")
        );

        // Repeats of one user count once.
        let repeated = vec![format!("user={}", pk().z32()); MAX_EVENT_STREAM_USERS + 1].join("&");
        assert!(EventStreamQuery::parse(&repeated).is_ok());
    }

    #[test]
    fn paths_keep_order_and_trailing_slash_and_skip_empty_values() {
        let q = parse("path=&path=/pub/&path=priv/app/&path=/priv/file&path=");
        let paths: Vec<&str> = q.paths.iter().map(|p| p.as_str()).collect();
        assert_eq!(paths, ["/pub/", "/priv/app/", "/priv/file"]);
    }

    #[test]
    fn rejects_invalid_path() {
        // Traversal above the storage root is one of the shapes `normalize` refuses.
        assert_eq!(message("path=/../x"), "Invalid path: /../x");
    }

    #[test]
    fn users_lists_both_forms_in_query_order() {
        let (a, b) = (pk(), pk());
        assert_eq!(
            parse(&format!("user={}&user={}", a.z32(), b.z32()))
                .resume
                .users(),
            vec![&a, &b]
        );
        assert_eq!(
            parse(&format!("user={}:1&user={}", a.z32(), b.z32()))
                .resume
                .users(),
            vec![&a, &b]
        );
        assert!(parse("").resume.users().is_empty());
    }
}
