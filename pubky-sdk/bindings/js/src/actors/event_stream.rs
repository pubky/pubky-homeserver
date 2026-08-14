use futures_util::StreamExt;
use wasm_bindgen::prelude::*;
use web_sys::ReadableStream;

use crate::actors::session::Session;
use crate::wrappers::event_stream::Event;

/// Builder for creating an event stream subscription.
///
/// Construct via `Pubky.eventStreamForUser()` or `Pubky.eventStreamFor()`.
///
/// @example
/// ```typescript
/// const stream = await pubky.eventStreamForUser(userPubkey, null)
///   .live()
///   .limit(100)
///   .path("/pub/")
///   .subscribe();
///
/// for await (const event of stream) {
///   console.log(event.eventType, event.resource.path);
/// }
/// ```
///
/// @example
/// ```typescript
/// // Private events: attach a session and request a `/priv/...` path.
/// const stream = await pubky.eventStreamForUser(userPubkey, null)
///   .session(session)
///   .path("/priv/app/")
///   .subscribe();
/// ```
#[wasm_bindgen]
pub struct EventStreamBuilder(pub(crate) pubky::EventStreamBuilder);

#[wasm_bindgen]
impl EventStreamBuilder {
    /// Add multiple users to the event stream subscription at once.
    ///
    /// Each user can have an independent cursor position. If a user already exists,
    /// their cursor value is overwritten.
    ///
    /// @param {Array<[string, string | null]>} users - Array of [z32PublicKey, cursor] tuples
    /// @returns {EventStreamBuilder} - Builder for chaining
    /// @throws {Error} - If total users would exceed 50 or if any cursor/pubkey is invalid
    ///
    /// @example
    /// ```typescript
    /// const users: [string, string | null][] = [
    ///   [user1.z32(), null],
    ///   [user2.z32(), "100"],
    /// ];
    /// const stream = await pubky.eventStreamFor(homeserver)
    ///   .addUsers(users)
    ///   .live()
    ///   .subscribe();
    /// ```
    #[wasm_bindgen(js_name = "addUsers")]
    pub fn add_users(self, users: js_sys::Array) -> Result<EventStreamBuilder, JsValue> {
        // Parse all users first
        let mut parsed_users: Vec<(pubky::PublicKey, Option<pubky::EventCursor>)> = Vec::new();

        for item in users.iter() {
            let tuple = js_sys::Array::from(&item);
            if tuple.length() != 2 {
                return Err(JsValue::from_str(
                    "Each user entry must be a [PublicKey, cursor] tuple",
                ));
            }

            // Parse the public key from z32 string
            let user_str = tuple.get(0).as_string().ok_or_else(|| {
                JsValue::from_str("First element must be a z32 public key string")
            })?;
            let user = pubky::PublicKey::try_from(user_str)
                .map_err(|e| JsValue::from_str(&format!("Invalid public key: {e}")))?;

            let cursor_val = tuple.get(1);
            let event_cursor = if cursor_val.is_null() || cursor_val.is_undefined() {
                None
            } else {
                let cursor_str = cursor_val
                    .as_string()
                    .ok_or_else(|| JsValue::from_str("Cursor must be a string or null"))?;
                Some(
                    cursor_str
                        .parse::<pubky::EventCursor>()
                        .map_err(|e| JsValue::from_str(&format!("Invalid cursor: {e}")))?,
                )
            };

            parsed_users.push((user, event_cursor));
        }

        // Use add_users with references
        let user_refs: Vec<_> = parsed_users.iter().map(|(u, c)| (u, *c)).collect();
        let builder = self
            .0
            .add_users(user_refs)
            .map_err(|e| JsValue::from_str(&format!("Failed to add users: {e}")))?;

        Ok(EventStreamBuilder(builder))
    }

    /// Set maximum number of events to receive before closing the connection.
    ///
    /// If omitted:
    /// - With `live=false`: sends all historical events, then closes
    /// - With `live=true`: sends all historical events, then enters live mode (infinite stream)
    ///
    /// @param {number} limit - Maximum number of events (1-65535)
    /// @returns {EventStreamBuilder} - Builder for chaining
    #[wasm_bindgen]
    pub fn limit(self, limit: u16) -> Self {
        EventStreamBuilder(self.0.limit(limit))
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
    /// ## Cleanup
    /// To stop a live stream, use the reader's `cancel()` method:
    /// ```typescript
    /// const stream = await pubky.eventStreamForUser(user, null).live().subscribe();
    /// const reader = stream.getReader();
    ///
    /// while (true) {
    ///   const { done, value } = await reader.read();
    ///   if (shouldStop) {
    ///     await reader.cancel(); // Closes the connection
    ///     break;
    ///   }
    /// }
    /// ```
    ///
    /// @returns {EventStreamBuilder} - Builder for chaining
    #[wasm_bindgen]
    pub fn live(self) -> Self {
        EventStreamBuilder(self.0.live())
    }

    /// Return events in reverse chronological order (newest first).
    ///
    /// When called, events are delivered from newest to oldest, then the stream closes.
    ///
    /// Without this flag (default): Events are delivered oldest first.
    ///
    /// **Note**: Cannot be combined with `live()`.
    ///
    /// @returns {EventStreamBuilder} - Builder for chaining
    #[wasm_bindgen]
    pub fn reverse(self) -> Self {
        EventStreamBuilder(self.0.reverse())
    }

    /// Filter events by path. Call once per path to receive the
    /// union of several scopes (e.g. `/pub/` plus a private `/priv/app/`).
    ///
    /// Format: a path WITHOUT the `pubky://` scheme or user pubkey. A trailing
    /// slash matches a directory and all its descendants (`/pub/files/`); no
    /// trailing slash matches an exact file (`/pub/notes.txt`).
    ///
    /// Private (`/priv/...`) paths require a session attached via `session()`;
    /// without one the homeserver rejects the subscription with 401.
    ///
    /// @param {string} path - Path filter (repeatable)
    /// @returns {EventStreamBuilder} - Builder for chaining
    #[wasm_bindgen]
    pub fn path(self, path: String) -> Self {
        EventStreamBuilder(self.0.path(path))
    }

    /// Authenticate the subscription with a user `Session`.
    ///
    /// Required to receive private (`/priv/...`) events: the session credential
    /// (grant or cookie) is attached so the homeserver can authorize each private
    /// `path()` against the session's read capabilities. Public subscriptions
    /// don't need this.
    ///
    ///
    /// @param {Session} session - The authenticated session
    /// @returns {EventStreamBuilder} - Builder for chaining
    #[wasm_bindgen]
    pub fn session(self, session: &Session) -> Self {
        EventStreamBuilder(self.0.session(&session.0))
    }

    /// Subscribe to the event stream.
    ///
    /// This performs the following steps:
    /// 1. Resolves the user's homeserver via DHT/PKDNS
    /// 2. Constructs the `/events-stream` URL with query parameters
    /// 3. Makes the HTTP request
    /// 4. Returns a Web ReadableStream of parsed events
    ///
    /// @returns {Promise<ReadableStream>} - A Web ReadableStream that yields Event objects
    ///
    /// @throws {PubkyError}
    /// - `{ name: "RequestError" }` if the homeserver cannot be resolved
    /// - `{ name: "ValidationError" }` if `live=true` and `reverse=true` (invalid combination)
    /// - Propagates HTTP request errors
    ///
    /// @example
    /// ```typescript
    /// const stream = await builder.subscribe();
    /// for await (const event of stream) {
    ///   console.log(`${event.eventType}: ${event.resource.path}`);
    /// }
    /// ```
    #[wasm_bindgen]
    pub async fn subscribe(self) -> Result<ReadableStream, JsValue> {
        // Call the underlying Rust implementation
        let rust_stream = self
            .0
            .subscribe()
            .await
            .map_err(|e| JsValue::from(crate::js_error::PubkyError::from(e)))?;

        let mapped_stream = rust_stream.map(|result| match result {
            Ok(event) => {
                let js_event = Event::from(event);
                Ok(JsValue::from(js_event))
            }
            Err(e) => {
                let pubky_err = crate::js_error::PubkyError::from(e);
                Err(JsValue::from(pubky_err))
            }
        });

        // Convert to Web ReadableStream using wasm_streams
        let wasm_stream = wasm_streams::ReadableStream::from_stream(mapped_stream);
        let web_sys_stream = wasm_stream.into_raw();
        Ok(web_sys_stream)
    }
}
