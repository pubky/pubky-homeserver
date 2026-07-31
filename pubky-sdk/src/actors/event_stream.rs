//! Event stream actor for subscribing to multi-user event feeds.
//!
//! This module provides a builder-style API for subscribing to Server-Sent Events (SSE)
//! from a homeserver's `/events-stream` endpoint.
//!
//! # Example: Single user
//! ```no_run
//! use pubky::{Pubky, PublicKey};
//! use futures_util::StreamExt;
//!
//! # async fn example() -> pubky::Result<()> {
//! let pubky = Pubky::new()?;
//! let user = PublicKey::try_from("o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo").unwrap();
//!
//! let mut stream = pubky.event_stream_for_user(&user, None)
//!     .live()
//!     .subscribe()
//!     .await?;
//!
//! while let Some(result) = stream.next().await {
//!     let event = result?;
//!     println!("Event: {:?} at {}", event.event_type, event.resource);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Example: Multiple users on the same homeserver
//! ```no_run
//! use pubky::{Pubky, PublicKey, EventCursor};
//! use futures_util::StreamExt;
//!
//! # async fn example() -> pubky::Result<()> {
//! let pubky = Pubky::new()?;
//! let user1 = PublicKey::try_from("o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo").unwrap();
//! let user2 = PublicKey::try_from("pxnu33x7jtpx9ar1ytsi4yxbp6a5o36gwhffs8zoxmbuptici1jy").unwrap();
//!
//! // When subscribing to multiple users, specify the homeserver directly
//! let homeserver = pubky.get_homeserver_of(&user1).await?.unwrap();
//!
//! let mut stream = pubky.event_stream_for(&homeserver)
//!     .add_users([(&user1, None), (&user2, Some(EventCursor::new(100)))])?
//!     .live()
//!     .limit(100)
//!     .path("/pub/")
//!     .subscribe()
//!     .await?;
//!
//! while let Some(result) = stream.next().await {
//!     let event = result?;
//!     println!("Event: {:?} at {}", event.event_type, event.resource);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Example: Private events (authenticated)
//!
//! Attach a session with [`EventStreamBuilder::session`] and request a
//! `/priv/...` [`path`](EventStreamBuilder::path). The homeserver authorizes the
//! private scope against the session's read capabilities. The session may be
//! grant- or cookie-backed, but it must name the session's own user and be bound
//! to the target homeserver; public subscriptions need no session.
//! ```no_run
//! use pubky::{Pubky, PubkySession};
//! use futures_util::StreamExt;
//!
//! # async fn example(session: PubkySession) -> pubky::Result<()> {
//! let pubky = Pubky::new()?;
//! let user = session.public_key();
//!
//! let mut stream = pubky.event_stream_for_user(&user, None)
//!     .session(&session)
//!     .path("/priv/app/")
//!     .live()
//!     .subscribe()
//!     .await?;
//!
//! while let Some(result) = stream.next().await {
//!     let event = result?;
//!     println!("Private event: {:?} at {}", event.event_type, event.resource);
//! }
//! # Ok(())
//! # }
//! ```

use std::pin::Pin;
use std::sync::Arc;

use crate::PublicKey;
use base64::Engine;
use eventsource_stream::Eventsource;
use futures_util::{Stream, StreamExt};
use pubky_common::{StoragePath, constants::storage::PRIVATE_ROOT, crypto::Hash};
use reqwest::Method;
use url::Url;

pub use pubky_common::events::{EventCursor, EventType};

use crate::{
    Pkdns, PubkyHttpClient, PubkyResource, PubkySession,
    actors::session::credential::SessionCredential,
    cross_log,
    errors::{Error, RequestError, Result},
    util::check_http_status,
};

/// A single event from the event stream.
#[derive(Debug, Clone)]
pub struct Event {
    /// Type of event (PUT with content hash, or DELETE).
    pub event_type: EventType,
    /// The resource that was created, updated, or deleted.
    pub resource: PubkyResource,
    /// Cursor for pagination (event ID).
    pub cursor: EventCursor,
}

/// Builder for creating an event stream subscription.
///
/// Construct via [`crate::Pubky::event_stream_for_user`] or [`crate::Pubky::event_stream_for`].
#[derive(Clone, Debug)]
pub struct EventStreamBuilder {
    client: PubkyHttpClient,
    users: Vec<(PublicKey, Option<EventCursor>)>,
    homeserver: Option<PublicKey>,
    limit: Option<u16>,
    live: bool,
    reverse: bool,
    paths: Vec<String>,
    credential: Option<Arc<dyn SessionCredential>>,
}

enum EventStreamAuthScope<'a> {
    PublicOnly,
    PrivateSingleUser(&'a PublicKey),
    PrivateUnsupported,
}

fn is_private_path_filter(path: &str) -> bool {
    let absolute;
    let path = if path.starts_with('/') {
        path
    } else {
        absolute = format!("/{path}");
        &absolute
    };

    StoragePath::normalize(path).is_ok_and(|path| path.as_str().starts_with(PRIVATE_ROOT))
}

impl EventStreamBuilder {
    /// Create an event stream builder for a single user.
    ///
    /// This is the simplest way to subscribe to events for one user. The homeserver
    /// is automatically resolved from the user's Pkarr record.
    ///
    /// # Example
    /// ```no_run
    /// use pubky::{Pubky, PublicKey, EventCursor};
    /// use futures_util::StreamExt;
    ///
    /// # async fn example() -> pubky::Result<()> {
    /// let pubky = Pubky::new()?;
    /// let user = PublicKey::try_from("o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo").unwrap();
    ///
    /// let mut stream = pubky.event_stream_for_user(&user, None)
    ///     .live()
    ///     .subscribe()
    ///     .await?;
    ///
    /// while let Some(result) = stream.next().await {
    ///     let event = result?;
    ///     println!("Event: {:?}", event);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn for_user(
        client: PubkyHttpClient,
        user: &PublicKey,
        cursor: Option<EventCursor>,
    ) -> Self {
        Self {
            client,
            users: vec![(user.clone(), cursor)],
            homeserver: None,
            limit: None,
            live: false,
            reverse: false,
            paths: Vec::new(),
            credential: None,
        }
    }

    /// Create a new event stream builder for a specific homeserver.
    ///
    /// Use this when you already know the homeserver pubkey, avoiding Pkarr resolution.
    /// You can obtain a homeserver pubkey via [`crate::Pubky::get_homeserver_of`].
    ///
    /// # Example
    /// ```no_run
    /// use pubky::{Pubky, PublicKey};
    /// use futures_util::StreamExt;
    ///
    /// # async fn example() -> pubky::Result<()> {
    /// let pubky = Pubky::new()?;
    /// let user1 = PublicKey::try_from("o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo").unwrap();
    /// let user2 = PublicKey::try_from("pxnu33x7jtpx9ar1ytsi4yxbp6a5o36gwhffs8zoxmbuptici1jy").unwrap();
    ///
    /// // When subscribing to multiple users on the same homeserver,
    /// // specify the homeserver directly to avoid redundant Pkarr lookups
    /// let homeserver = pubky.get_homeserver_of(&user1).await?.unwrap();
    ///
    /// let mut stream = pubky.event_stream_for(&homeserver)
    ///     .add_users([(&user1, None), (&user2, None)])?
    ///     .live()
    ///     .subscribe()
    ///     .await?;
    ///
    /// while let Some(result) = stream.next().await {
    ///     let event = result?;
    ///     println!("Event: {:?}", event);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn for_homeserver(client: PubkyHttpClient, homeserver: &PublicKey) -> Self {
        Self {
            client,
            users: Vec::new(),
            homeserver: Some(homeserver.clone()),
            limit: None,
            live: false,
            reverse: false,
            paths: Vec::new(),
            credential: None,
        }
    }

    /// Add multiple users to the event stream subscription at once.
    ///
    /// # Errors
    /// - Returns an error if the total number of users would exceed 50
    ///
    /// # Example
    /// ```no_run
    /// use pubky::{Pubky, PublicKey, EventCursor};
    ///
    /// # async fn example() -> pubky::Result<()> {
    /// let pubky = Pubky::new()?;
    /// let homeserver = PublicKey::try_from("h9m4r...").unwrap();
    /// let user1 = PublicKey::try_from("o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo").unwrap();
    /// let user2 = PublicKey::try_from("pxnu33x7jtpx9ar1ytsi4yxbp6a5o36gwhffs8zoxmbuptici1jy").unwrap();
    ///
    /// let users = [
    ///     (&user1, None),
    ///     (&user2, Some(EventCursor::new(100))),
    /// ];
    ///
    /// let stream = pubky.event_stream_for(&homeserver)
    ///     .add_users(users)?
    ///     .live()
    ///     .subscribe()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_users<'a>(
        mut self,
        users: impl IntoIterator<Item = (&'a PublicKey, Option<EventCursor>)>,
    ) -> Result<Self> {
        for (user, cursor) in users {
            // Check if user already exists - update cursor if so
            if let Some(existing) = self.users.iter_mut().find(|(u, _)| u == user) {
                existing.1 = cursor;
                continue;
            }

            if self.users.len() >= 50 {
                return Err(Error::from(RequestError::Validation {
                    message: "Cannot subscribe to more than 50 users".into(),
                }));
            }

            self.users.push((user.clone(), cursor));
        }
        Ok(self)
    }

    /// Set maximum number of events to receive before closing the connection.
    ///
    /// If omitted:
    /// - With `live=false`: sends all historical events, then closes
    /// - With `live=true`: sends all historical events, then enters live mode (infinite stream)
    #[must_use]
    pub const fn limit(mut self, limit: u16) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Enable live streaming mode.
    ///
    /// When called, the stream will:
    /// 1. First deliver all historical events (oldest first)
    /// 2. Then remain open to stream new events as they occur in real-time
    ///
    /// Without this flag (default): Stream only delivers historical events and closes.
    ///
    /// **Note**: Cannot be combined with `reverse()`.
    ///
    /// # Cleanup
    /// To stop the stream, simply drop it. The underlying HTTP connection will be closed.
    /// ```ignore
    /// let stream = pubky.event_stream_for_user(&user, None).live().subscribe().await?;
    /// // Process some events...
    /// drop(stream); // Connection closed
    /// ```
    #[must_use]
    pub const fn live(mut self) -> Self {
        self.live = true;
        self
    }

    /// Return events in reverse chronological order (newest first).
    ///
    /// When called, events are delivered from newest to oldest, then the stream closes.
    /// This is useful for fetching recent history.
    ///
    /// Without this flag (default): Events are delivered oldest first.
    ///
    /// **Note**: Cannot be combined with `live()`.
    #[must_use]
    pub const fn reverse(mut self) -> Self {
        self.reverse = true;
        self
    }

    /// Filter events by path. Repeatable: call once per path to receive the
    /// union of several scopes (e.g. `/pub/` plus a private `/priv/app/`).
    ///
    /// Format: a path WITHOUT the `pubky://` scheme or user pubkey. A trailing
    /// slash matches a directory and all its descendants (`/pub/files/`); no
    /// trailing slash matches an exact file (`/pub/notes.txt`).
    ///
    /// Private (`/priv/...`) paths require a session attached via
    /// [`Self::session`]; without one the homeserver rejects the subscription
    /// with `401 Unauthorized`.
    #[must_use]
    pub fn path<S: Into<String>>(mut self, path: S) -> Self {
        self.paths.push(path.into());
        self
    }

    /// Authenticate the subscription with a user session.
    ///
    /// Required for private (`/priv/...`) events. Public streams stay anonymous.
    #[must_use]
    pub fn session(mut self, session: &PubkySession) -> Self {
        self.credential = Some(Arc::clone(session.credential()));
        self
    }

    /// Build the event stream request URL with all query parameters.
    ///
    /// Constructs a URL like:
    /// `https://{homeserver}/events-stream?user=pk1&user=pk2:cursor&limit=100&live=true&path=/pub/`
    fn build_request_url(&self, homeserver: &PublicKey) -> Result<Url> {
        let mut url = Url::parse(&format!("https://{}/events-stream", homeserver.z32()))?;

        {
            let mut query = url.query_pairs_mut();
            for (user, cursor) in &self.users {
                if let Some(c) = cursor {
                    query.append_pair("user", &format!("{}:{c}", user.z32()));
                } else {
                    query.append_pair("user", &user.z32());
                }
            }
            if let Some(limit) = self.limit {
                query.append_pair("limit", &limit.to_string());
            }
            if self.live {
                query.append_pair("live", "true");
            }
            if self.reverse {
                query.append_pair("reverse", "true");
            }
            for path in &self.paths {
                query.append_pair("path", path);
            }
        }
        cross_log!(debug, "Event stream URL: {}", url);
        Ok(url)
    }

    fn has_private_path_filter(&self) -> bool {
        self.paths.iter().any(|path| is_private_path_filter(path))
    }

    fn auth_scope(&self) -> EventStreamAuthScope<'_> {
        if !self.has_private_path_filter() {
            return EventStreamAuthScope::PublicOnly;
        }

        match self.users.as_slice() {
            [(user, _)] => EventStreamAuthScope::PrivateSingleUser(user),
            _ => EventStreamAuthScope::PrivateUnsupported,
        }
    }

    fn should_attach_credential(&self, credential: &dyn SessionCredential) -> bool {
        match self.auth_scope() {
            EventStreamAuthScope::PrivateSingleUser(user) => user == credential.info().public_key(),
            EventStreamAuthScope::PublicOnly | EventStreamAuthScope::PrivateUnsupported => false,
        }
    }

    /// Internal helper that contains the shared subscription logic.
    async fn subscribe_internal(self) -> Result<impl Stream<Item = Result<Event>>> {
        if self.live && self.reverse {
            return Err(Error::from(RequestError::Validation {
                message: "Cannot use live mode with reverse ordering".into(),
            }));
        }

        if self.users.is_empty() {
            return Err(Error::from(RequestError::Validation {
                message: "At least one user must be specified".into(),
            }));
        }
        if self.users.len() > 50 {
            return Err(Error::from(RequestError::Validation {
                message: "Cannot subscribe to more than 50 users".into(),
            }));
        }

        // Resolve the target homeserver from the subscription (explicit if given,
        // else the first user's). A session only decides WHETHER a credential is
        // attached, never WHERE the request goes.
        let homeserver = if let Some(hs) = &self.homeserver {
            hs.clone()
        } else {
            Pkdns::with_client(self.client.clone())
                .require_homeserver_of(&self.users[0].0)
                .await?
        };

        cross_log!(
            info,
            "Subscribing to event stream for {} user(s) on homeserver {}",
            self.users.len(),
            homeserver
        );

        let credential = self
            .credential
            .as_ref()
            .filter(|credential| self.should_attach_credential(credential.as_ref()));
        let can_attach_credential = match credential {
            Some(credential) => credential.can_attach_to(&homeserver).await,
            None => false,
        };
        if credential.is_some() && !can_attach_credential {
            return Err(Error::from(RequestError::Validation {
                message: "cannot attach session credential to target homeserver".into(),
            }));
        }

        let url = self.build_request_url(&homeserver)?;
        let mut request = self
            .client
            .cross_request_anonymous(Method::GET, url)
            .await?;
        if let Some(credential) = credential {
            request = credential.attach(request, &self.client).await?;
        }
        let response = request.send().await?;

        // Surface homeserver rejections (e.g. 401/403/400 for private-path
        // authorization) as a typed `RequestError::Server` carrying the status
        // and the server's message, rather than a hand-rolled string.
        let response = check_http_status(response).await?;

        let sse_stream = response.bytes_stream().eventsource();
        let event_stream = sse_stream.filter_map(|result| async move {
            match result {
                Ok(sse_event) => match parse_sse_event(&sse_event) {
                    Ok(event) => Some(Ok(event)),
                    Err(e) => {
                        // Skip unparseable events rather than failing the entire stream.
                        // We don't control what homeservers return, and we shouldn't panic
                        // on unexpected data.
                        // This also provides forward compatibility for new event types.
                        cross_log!(error, "Failed to parse SSE event, skipping: {}", e);
                        None
                    }
                },
                Err(e) => {
                    cross_log!(error, "SSE stream error: {}", e);
                    Some(Err(Error::from(RequestError::Validation {
                        message: format!("SSE stream error: {e}"),
                    })))
                }
            }
        });

        Ok(event_stream)
    }

    /// Subscribe to the event stream.
    ///
    /// This performs the following steps:
    /// 1. Resolves the user's homeserver via DHT/PKDNS
    /// 2. Constructs the `/events-stream` URL with query parameters
    /// 3. Makes the HTTP request
    /// 4. Returns a stream of parsed events
    ///
    /// The native version returns a `Send`-compatible stream for use in multi-threaded contexts.
    ///
    /// # Errors
    /// - Returns [`Error::Request`] if the homeserver cannot be resolved
    /// - Returns [`Error::Request`] if `live=true` and `reverse=true` (invalid combination)
    /// - Propagates HTTP request errors
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn subscribe(self) -> Result<Pin<Box<dyn Stream<Item = Result<Event>> + Send>>> {
        let stream = self.subscribe_internal().await?;
        Ok(Box::pin(stream))
    }

    /// Subscribe to the event stream (WASM version).
    ///
    /// This performs the following steps:
    /// 1. Resolves the user's homeserver via DHT/PKDNS
    /// 2. Constructs the `/events-stream` URL with query parameters
    /// 3. Makes the HTTP request
    /// 4. Returns a stream of parsed events
    ///
    /// The WASM version returns a stream without the `Send` bound, as WASM is single-threaded.
    ///
    /// # Errors
    /// - Returns [`Error::Request`] if the homeserver cannot be resolved
    /// - Returns [`Error::Request`] if `live=true` and `reverse=true` (invalid combination)
    /// - Propagates HTTP request errors
    #[cfg(target_arch = "wasm32")]
    pub async fn subscribe(self) -> Result<Pin<Box<dyn Stream<Item = Result<Event>>>>> {
        let stream = self.subscribe_internal().await?;
        Ok(Box::pin(stream))
    }
}

/// Parse a Server-Sent Event into our Event type.
///
/// SSE format:
/// ```text
/// event: PUT
/// data: pubky://user_pubkey/pub/example.txt
/// data: cursor: 42
/// data: content_hash: <base64 of raw 32-byte blake3 digest> (required for PUT events)
/// ```
fn parse_sse_event(sse: &eventsource_stream::Event) -> Result<Event> {
    // Parse SSE data by prefix
    let mut path: Option<String> = None;
    let mut cursor: Option<EventCursor> = None;
    let mut content_hash_base64: Option<String> = None;

    for (i, line) in sse.data.lines().enumerate() {
        if let Some(cursor_str) = line.strip_prefix("cursor: ") {
            cursor = Some(cursor_str.parse::<EventCursor>().map_err(|e| {
                Error::from(RequestError::Validation {
                    message: format!("Invalid cursor format '{cursor_str}': {e}"),
                })
            })?);
        } else if let Some(hash) = line.strip_prefix("content_hash: ") {
            content_hash_base64 = Some(hash.to_string());
        } else if i == 0 {
            // First line without a known prefix is the path
            path = Some(line.to_string());
        }
        // Unknown prefixed lines are ignored for forward compatibility
    }

    let path = path.ok_or_else(|| {
        Error::from(RequestError::Validation {
            message: "SSE event missing path (expected as first line)".into(),
        })
    })?;

    let resource: PubkyResource = path.parse().map_err(|e| {
        Error::from(RequestError::Validation {
            message: format!("Invalid resource path '{path}': {e}"),
        })
    })?;

    let cursor = cursor.ok_or_else(|| {
        Error::from(RequestError::Validation {
            message: "SSE event missing cursor line".into(),
        })
    })?;

    let event_type = match sse.event.as_str() {
        "PUT" => {
            let content_hash = decode_content_hash(content_hash_base64.as_deref())?;
            EventType::Put { content_hash }
        }
        "DEL" => EventType::Delete,
        other => {
            return Err(Error::from(RequestError::Validation {
                message: format!("Unknown event type: {other}"),
            }));
        }
    };

    Ok(Event {
        event_type,
        resource,
        cursor,
    })
}

/// Decode a base64-encoded content hash into a Hash.
fn decode_content_hash(content_hash_base64: Option<&str>) -> Result<Hash> {
    let b64 = content_hash_base64
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Error::from(RequestError::Validation {
                message: "PUT event missing required content_hash".into(),
            })
        })?;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| {
            Error::from(RequestError::Validation {
                message: format!("Invalid content_hash base64 encoding: {e}"),
            })
        })?;

    let hash_bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        Error::from(RequestError::Validation {
            message: format!(
                "content_hash must be exactly 32 bytes, got {} bytes",
                bytes.len()
            ),
        })
    })?;

    Ok(Hash::from_bytes(hash_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actors::auth::cookie::credential::CookieCredential;
    use pubky_common::{
        capabilities::{Capabilities, Capability},
        session::CookieSessionRecord,
    };

    /// Helper to create an SSE event for testing
    fn make_sse(event: &str, data: &str) -> eventsource_stream::Event {
        eventsource_stream::Event {
            event: event.to_string(),
            data: data.to_string(),
            id: String::new(),
            retry: None,
        }
    }

    /// Helper to create a base64-encoded hash from bytes
    fn encode_hash(bytes: [u8; 32]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn parse_put_event_with_content_hash() {
        let hash_bytes = [1u8; 32];
        let hash_b64 = encode_hash(hash_bytes);
        let sse = make_sse(
            "PUT",
            &format!(
                "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/example.txt\ncursor: 42\ncontent_hash: {hash_b64}"
            ),
        );

        let event = parse_sse_event(&sse).unwrap();

        assert!(matches!(event.event_type, EventType::Put { .. }));
        assert_eq!(event.resource.path.as_str(), "/pub/example.txt");
        assert_eq!(event.cursor.id(), 42);
        assert_eq!(
            event.event_type.content_hash(),
            Some(&Hash::from_bytes(hash_bytes))
        );
    }

    #[test]
    fn parse_del_event_without_content_hash() {
        let sse = make_sse(
            "DEL",
            "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/deleted.txt\ncursor: 100",
        );

        let event = parse_sse_event(&sse).unwrap();

        assert_eq!(event.event_type, EventType::Delete);
        assert_eq!(event.resource.path.as_str(), "/pub/deleted.txt");
        assert_eq!(event.cursor.id(), 100);
        assert_eq!(event.event_type.content_hash(), None);
    }

    #[test]
    fn parse_event_with_unknown_prefixed_lines_for_forward_compatibility() {
        let hash_bytes = [2u8; 32];
        let hash_b64 = encode_hash(hash_bytes);
        let sse = make_sse(
            "PUT",
            &format!(
                "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/file.txt\ncursor: 50\nfuture_field: some_value\nanother_future: 123\ncontent_hash: {hash_b64}"
            ),
        );

        let event = parse_sse_event(&sse).unwrap();

        assert!(matches!(event.event_type, EventType::Put { .. }));
        assert_eq!(event.cursor.id(), 50);
        assert_eq!(
            event.event_type.content_hash(),
            Some(&Hash::from_bytes(hash_bytes))
        );
    }

    #[test]
    fn parse_event_with_lines_in_different_order() {
        let hash_bytes = [3u8; 32];
        let hash_b64 = encode_hash(hash_bytes);
        // cursor before content_hash, both after path
        let sse = make_sse(
            "PUT",
            &format!(
                "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/test.txt\ncontent_hash: {hash_b64}\ncursor: 999"
            ),
        );

        let event = parse_sse_event(&sse).unwrap();

        assert_eq!(event.cursor.id(), 999);
        assert_eq!(
            event.event_type.content_hash(),
            Some(&Hash::from_bytes(hash_bytes))
        );
    }

    #[test]
    fn error_on_unknown_event_type() {
        let sse = make_sse(
            "PATCH",
            "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/file.txt\ncursor: 1",
        );

        let result = parse_sse_event(&sse);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unknown event type: PATCH"), "Got: {err}");
    }

    #[test]
    fn error_on_missing_path() {
        let hash_b64 = encode_hash([0u8; 32]);
        let sse = make_sse("PUT", &format!("cursor: 42\ncontent_hash: {hash_b64}"));

        let result = parse_sse_event(&sse);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("missing path") || err.contains("Invalid resource"),
            "Got: {err}"
        );
    }

    #[test]
    fn error_on_missing_cursor() {
        let hash_b64 = encode_hash([0u8; 32]);
        let sse = make_sse(
            "PUT",
            &format!(
                "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/file.txt\ncontent_hash: {hash_b64}"
            ),
        );

        let result = parse_sse_event(&sse);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing cursor"), "Got: {err}");
    }

    #[test]
    fn error_on_invalid_cursor_format() {
        let sse = make_sse(
            "PUT",
            "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/file.txt\ncursor: not_a_number",
        );

        let result = parse_sse_event(&sse);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid cursor format"), "Got: {err}");
    }

    #[test]
    fn error_on_negative_cursor() {
        let sse = make_sse(
            "PUT",
            "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/file.txt\ncursor: -100",
        );

        let result = parse_sse_event(&sse);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid cursor format"), "Got: {err}");
    }

    #[test]
    fn error_on_invalid_pubky_resource_path() {
        let sse = make_sse("PUT", "not-a-valid-pubky-url\ncursor: 42");

        let result = parse_sse_event(&sse);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid resource path"), "Got: {err}");
    }

    #[test]
    fn error_on_empty_content_hash() {
        let sse = make_sse(
            "PUT",
            "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/file.txt\ncursor: 1\ncontent_hash: ",
        );

        let result = parse_sse_event(&sse);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing required content_hash"), "Got: {err}");
    }

    #[test]
    fn error_on_missing_content_hash() {
        let sse = make_sse(
            "PUT",
            "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/file.txt\ncursor: 1",
        );

        let result = parse_sse_event(&sse);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing required content_hash"), "Got: {err}");
    }

    #[test]
    fn parse_event_with_large_cursor() {
        let hash_b64 = encode_hash([0u8; 32]);
        let sse = make_sse(
            "PUT",
            &format!(
                "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/file.txt\ncursor: 9223372036854775807\ncontent_hash: {hash_b64}"
            ),
        );

        let event = parse_sse_event(&sse).unwrap();

        assert_eq!(event.cursor.id(), 9_223_372_036_854_775_807_u64);
    }

    // Note: EventCursor and EventType trait tests are in pubky-common/src/events.rs
    // SDK tests focus on SSE parsing behavior specific to the SDK

    #[test]
    fn error_on_invalid_base64_content_hash() {
        let sse = make_sse(
            "PUT",
            "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/file.txt\ncursor: 1\ncontent_hash: not-valid-base64!!!",
        );

        let result = parse_sse_event(&sse);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid content_hash"), "Got: {err}");
    }

    #[test]
    fn error_on_wrong_length_content_hash() {
        // Base64-encode only 16 bytes instead of 32
        let short_hash = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        let sse = make_sse(
            "PUT",
            &format!(
                "pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/file.txt\ncursor: 1\ncontent_hash: {short_hash}"
            ),
        );

        let result = parse_sse_event(&sse);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("32 bytes"), "Got: {err}");
    }

    // === Builder tests ===

    fn test_pubkeys(count: usize) -> Vec<PublicKey> {
        // Generate random test public keys
        (0..count)
            .map(|_| crate::Keypair::random().public_key())
            .collect()
    }

    #[test]
    fn builder_constructors_and_add_users() {
        let client = crate::PubkyHttpClient::testnet().unwrap();
        let keys = test_pubkeys(4);

        // for_user initializes with single user and cursor
        let builder =
            EventStreamBuilder::for_user(client.clone(), &keys[0], Some(EventCursor::new(42)));
        assert_eq!(builder.users.len(), 1);
        assert_eq!(builder.users[0].0, keys[0]);
        assert_eq!(builder.users[0].1, Some(EventCursor::new(42)));
        assert!(builder.homeserver.is_none());

        // for_homeserver initializes with homeserver and no users
        let builder = EventStreamBuilder::for_homeserver(client.clone(), &keys[0]);
        assert!(builder.users.is_empty());
        assert_eq!(builder.homeserver.as_ref(), Some(&keys[0]));

        // add_users adds multiple users with cursors
        let builder = EventStreamBuilder::for_homeserver(client.clone(), &keys[0])
            .add_users([
                (&keys[1], None),
                (&keys[2], Some(EventCursor::new(100))),
                (&keys[3], Some(EventCursor::new(200))),
            ])
            .unwrap();
        assert_eq!(builder.users.len(), 3);
        assert_eq!(builder.users[0], (keys[1].clone(), None));
        assert_eq!(
            builder.users[1],
            (keys[2].clone(), Some(EventCursor::new(100)))
        );
        assert_eq!(
            builder.users[2],
            (keys[3].clone(), Some(EventCursor::new(200)))
        );

        // add_users updates existing user's cursor
        let builder = EventStreamBuilder::for_homeserver(client.clone(), &keys[0])
            .add_users([(&keys[1], Some(EventCursor::new(10))), (&keys[2], None)])
            .unwrap()
            .add_users([(&keys[1], Some(EventCursor::new(999)))])
            .unwrap();
        assert_eq!(builder.users.len(), 2);
        assert_eq!(builder.users[0].1, Some(EventCursor::new(999))); // Updated
        assert_eq!(builder.users[1].1, None); // Unchanged

        // Builder chaining with live mode
        let builder = EventStreamBuilder::for_user(client.clone(), &keys[0], None)
            .limit(100)
            .live()
            .path("/pub/posts/".to_string());
        assert_eq!(builder.limit, Some(100));
        assert!(builder.live);
        assert!(!builder.reverse);
        assert_eq!(builder.paths, vec!["/pub/posts/".to_string()]);
        assert!(builder.credential.is_none());

        // Builder chaining with reverse mode
        let builder = EventStreamBuilder::for_user(client, &keys[0], None)
            .limit(50)
            .reverse()
            .path("/pub/files/".to_string());
        assert_eq!(builder.limit, Some(50));
        assert!(!builder.live);
        assert!(builder.reverse);
        assert_eq!(builder.paths, vec!["/pub/files/".to_string()]);
    }

    #[test]
    fn path_is_repeatable_and_accumulates() {
        let client = crate::PubkyHttpClient::testnet().unwrap();
        let keys = test_pubkeys(1);

        // No path by default.
        let builder = EventStreamBuilder::for_user(client.clone(), &keys[0], None);
        assert!(builder.paths.is_empty());

        // Each `.path()` call appends, preserving order (union of scopes).
        let builder = builder.path("/pub/").path("/priv/app/").path("/priv/file");
        assert_eq!(
            builder.paths,
            vec![
                "/pub/".to_string(),
                "/priv/app/".to_string(),
                "/priv/file".to_string(),
            ]
        );
    }

    fn cookie_credential_for(user: &PublicKey) -> CookieCredential {
        let record =
            CookieSessionRecord::new(user, Capabilities::from(vec![Capability::root()]), None);
        CookieCredential::new(user.clone(), Some("test-cookie".to_string()), record, None)
    }

    #[test]
    fn has_private_path_filter_detects_priv_scopes() {
        let client = crate::PubkyHttpClient::testnet().unwrap();
        let keys = test_pubkeys(1);
        let user = &keys[0];

        let cases = [
            (vec![], false),
            (vec![""], false),
            (vec!["/pub/"], false),
            (vec!["/privstuff/x"], false),
            (vec!["/priv"], false),
            (vec!["/priv/app/"], true),
            (vec!["/priv/"], true),
            (vec!["priv/x"], true),
            (vec!["/pub/", "/priv/app/"], true),
            (vec!["/pub/../priv/secret/"], true),
            (vec!["/../../priv/secret/"], false),
        ];

        for (paths, expected) in cases {
            let builder = paths.iter().fold(
                EventStreamBuilder::for_user(client.clone(), user, None),
                |b, p| b.path(*p),
            );
            assert_eq!(builder.has_private_path_filter(), expected, "{paths:?}");
        }
    }

    #[test]
    fn should_attach_credential_only_for_own_single_user_private_stream() {
        let client = crate::PubkyHttpClient::testnet().unwrap();
        let keys = test_pubkeys(2);
        let alice = &keys[0];
        let bob = &keys[1];
        let alice_cred = cookie_credential_for(alice);

        let cases = [
            (
                "no path",
                EventStreamBuilder::for_user(client.clone(), alice, None),
                false,
            ),
            (
                "public path",
                EventStreamBuilder::for_user(client.clone(), alice, None).path("/pub/"),
                false,
            ),
            (
                "same-user private path",
                EventStreamBuilder::for_user(client.clone(), alice, None).path("/priv/app/"),
                true,
            ),
            (
                "normalized private path",
                EventStreamBuilder::for_user(client.clone(), alice, None)
                    .path("/pub/../priv/secret/"),
                true,
            ),
            (
                "wrong-user private path",
                EventStreamBuilder::for_user(client.clone(), bob, None).path("/priv/app/"),
                false,
            ),
            (
                "multi-user private path",
                EventStreamBuilder::for_homeserver(client, &keys[0])
                    .add_users([(alice, None), (bob, None)])
                    .unwrap()
                    .path("/priv/app/"),
                false,
            ),
        ];

        for (name, builder, expected) in cases {
            assert_eq!(
                builder.should_attach_credential(&alice_cred),
                expected,
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn private_stream_with_unbound_cookie_returns_validation_error() {
        let client = crate::PubkyHttpClient::testnet().unwrap();
        let keys = test_pubkeys(2);
        let user = &keys[0];
        let homeserver = &keys[1];
        let session =
            PubkySession::from_cookie_credential(client.clone(), cookie_credential_for(user));

        let result = EventStreamBuilder::for_homeserver(client, homeserver)
            .add_users([(user, None)])
            .unwrap()
            .path("/priv/app/")
            .session(&session)
            .subscribe_internal()
            .await;

        let Err(err) = result else {
            panic!("private stream should fail before request");
        };
        let Error::Request(RequestError::Validation { message }) = err else {
            panic!("expected validation error");
        };
        assert!(
            message.contains("cannot attach session credential"),
            "got: {message}"
        );
    }

    #[test]
    fn add_users_errors_on_exceeding_50_users() {
        let client = crate::PubkyHttpClient::testnet().unwrap();
        let keys = test_pubkeys(52);
        let homeserver = &keys[0];
        let users = &keys[1..]; // 51 users

        let user_refs: Vec<_> = users.iter().map(|u| (u, None)).collect();

        let result = EventStreamBuilder::for_homeserver(client, homeserver).add_users(user_refs);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("50 users"), "Got: {err}");
    }

    #[test]
    fn build_request_url_constructs_correct_query_params() {
        let client = crate::PubkyHttpClient::testnet().unwrap();
        let keys = test_pubkeys(3);
        let homeserver = &keys[0];
        let user1 = &keys[1];
        let user2 = &keys[2];

        // Test with all options: multiple users, cursors, limit, live, path
        let builder = EventStreamBuilder::for_homeserver(client.clone(), homeserver)
            .add_users([(user1, None), (user2, Some(EventCursor::new(42)))])
            .unwrap()
            .limit(100)
            .live()
            .path("/pub/posts/");

        let url = builder.build_request_url(homeserver).unwrap();

        // Verify base URL
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.path(), "/events-stream");

        // Verify query parameters
        let query: Vec<_> = url.query_pairs().collect();

        // Should have: user (x2), limit, live, path
        assert_eq!(query.len(), 5, "Should have 5 query params: {query:?}");

        // Check user params
        let user_params: Vec<_> = query
            .iter()
            .filter(|(k, _)| k == "user")
            .map(|(_, v)| v.to_string())
            .collect();
        assert_eq!(user_params.len(), 2);
        assert!(
            user_params.iter().any(|v| v == &user1.z32()),
            "Should have user1 without cursor"
        );
        assert!(
            user_params
                .iter()
                .any(|v| v == &format!("{}:42", user2.z32())),
            "Should have user2 with cursor"
        );

        // Check other params
        assert!(query.iter().any(|(k, v)| k == "limit" && v == "100"));
        assert!(query.iter().any(|(k, v)| k == "live" && v == "true"));
        assert!(query.iter().any(|(k, v)| k == "path" && v == "/pub/posts/"));

        // Test reverse mode (mutually exclusive with live)
        let builder_reverse = EventStreamBuilder::for_homeserver(client, homeserver)
            .add_users([(user1, None)])
            .unwrap()
            .reverse()
            .limit(50);

        let url_reverse = builder_reverse.build_request_url(homeserver).unwrap();
        let query_reverse: Vec<_> = url_reverse.query_pairs().collect();

        assert!(
            query_reverse
                .iter()
                .any(|(k, v)| k == "reverse" && v == "true")
        );
        assert!(
            !query_reverse.iter().any(|(k, _)| k == "live"),
            "Should not have live param when reverse is set"
        );
    }

    #[test]
    fn build_request_url_emits_repeated_path_params() {
        let client = crate::PubkyHttpClient::testnet().unwrap();
        let keys = test_pubkeys(2);
        let homeserver = &keys[0];
        let user = &keys[1];

        // A mixed public + private subscription emits one `path=` per filter,
        // matching the server's repeatable `path` query from #429.
        let builder = EventStreamBuilder::for_homeserver(client, homeserver)
            .add_users([(user, None)])
            .unwrap()
            .path("/pub/")
            .path("/priv/app/");

        let url = builder.build_request_url(homeserver).unwrap();
        let path_params: Vec<String> = url
            .query_pairs()
            .filter(|(k, _)| k == "path")
            .map(|(_, v)| v.to_string())
            .collect();

        assert_eq!(
            path_params,
            vec!["/pub/".to_string(), "/priv/app/".to_string()]
        );
    }

    #[tokio::test]
    async fn subscribe_fails_with_no_users() {
        let client = crate::PubkyHttpClient::testnet().unwrap();
        let keys = test_pubkeys(1);
        let homeserver = &keys[0];

        // Building with empty users list succeeds
        let empty: [(&PublicKey, Option<EventCursor>); 0] = [];
        let builder = EventStreamBuilder::for_homeserver(client, homeserver)
            .add_users(empty)
            .unwrap();

        assert!(builder.users.is_empty());
        assert_eq!(builder.homeserver.as_ref(), Some(homeserver));

        // But subscribe should fail
        let result = builder.subscribe().await;

        match result {
            Ok(_) => panic!("Expected error, but subscribe succeeded"),
            Err(e) => {
                let err = e.to_string();
                assert!(
                    err.contains("At least one user must be specified"),
                    "Got: {err}"
                );
            }
        }
    }
}
