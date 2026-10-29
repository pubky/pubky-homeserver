use futures_util::Stream;
use tokio::sync::broadcast;

use super::stream::{stream_events, NoGuard, StreamCursor, StreamGuard, StreamOptions};
use crate::observability::Metrics;
use crate::persistence::sql::{
    events::{EventCursor, EventEntity, EventRepository, EventType, EventVisibility, PathFilter},
    SqlDb, UnifiedExecutor,
};
use crate::shared::webdav::EntryPath;

/// Maximum number of users allowed in a single event stream request.
/// Based on HTTP header size limits (~4KB) and typical URL encoding:
/// - Max users at 4KB: 3896 / 74 ≈ 52 users
/// - Set to 50 for clean limit with safety margin for longer cursors
pub const MAX_EVENT_STREAM_USERS: usize = 50;

/// Postgres channel name for event notifications.
pub(crate) const PG_NOTIFY_CHANNEL: &str = "events";

/// Service that handles all event-related business logic.
#[derive(Clone, Debug)]
pub struct EventsService {
    sql_db: SqlDb,
    event_tx: broadcast::Sender<EventEntity>,
    channel_capacity: usize,
}

/// Ordering + live behavior for an event stream. Encoding the mutually exclusive
/// options as one enum makes the invalid reverse-and-live combination unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Batch, oldest-first; close when caught up.
    Forward,
    /// Batch oldest-first, then stay open for live events.
    ForwardLive,
    /// Batch, newest-first; close when caught up.
    Reverse,
}

impl Mode {
    /// Newest-first batch ordering.
    pub(crate) fn reverse(self) -> bool {
        matches!(self, Self::Reverse)
    }
    /// Stay open for live events after replaying history.
    pub(crate) fn live(self) -> bool {
        matches!(self, Self::ForwardLive)
    }
}

/// Resolved filter for the admin all-events stream. The route builds this after authorizing the
/// request (pubkeys → user ids, cursor parsed); it drives [`EventsService::all_events_stream`].
pub(crate) struct AllEventsFilter {
    /// Starting cursor (global). `None` = from the beginning.
    pub start_cursor: Option<EventCursor>,
    /// User filter. `None` = all users (firehose).
    pub user_ids: Option<Vec<i32>>,
    /// Path filters
    pub paths: Vec<PathFilter>,
    /// Ordering + live behavior.
    pub mode: Mode,
    /// Maximum total events to send before closing.
    pub limit: Option<u16>,
}

/// Resolved filter for a client user-events stream. The route builds this after authorizing the
/// request (pubkeys → user ids, paths checked against the session); it drives
/// [`EventsService::user_events_stream`].
pub(crate) struct UserEventsFilter {
    /// Users to stream, each with its optional resume cursor.
    pub user_cursors: Vec<(i32, Option<EventCursor>)>,
    /// Authorized path filters; an event is sent only if it matches at least one.
    pub allowed_paths: Vec<PathFilter>,
    /// Ordering + live behavior.
    pub mode: Mode,
    /// Maximum total events to send before closing.
    pub limit: Option<u16>,
}

impl EventsService {
    /// Create a new EventsService with a broadcast channel.
    /// The channel_capacity determines how many events can be buffered before old ones are dropped.
    pub fn new(sql_db: SqlDb, channel_capacity: usize) -> Self {
        let (event_tx, _rx) = broadcast::channel(channel_capacity);
        Self {
            sql_db,
            event_tx,
            channel_capacity,
        }
    }

    /// Subscribe to the event broadcast channel.
    /// Returns a receiver that will receive all future events.
    pub fn subscribe(&self) -> broadcast::Receiver<EventEntity> {
        self.event_tx.subscribe()
    }

    /// Get the maximum capacity of the broadcast channel.
    pub fn channel_capacity(&self) -> usize {
        self.channel_capacity
    }

    /// Create a new event in the database.
    /// The event will be returned but NOT broadcast — call `notify_event` after transaction
    /// commit to wake up all PgEventListener instances, which will read and broadcast
    /// the event from the database.
    ///
    /// ## Usage Pattern
    /// ```rust,ignore
    /// let mut tx = db.pool().begin().await?;
    /// let event = events_service.create_event(..., &mut (&mut tx).into()).await?;
    /// tx.commit().await?;
    /// events_service.notify_event().await;
    /// ```
    pub async fn create_event<'a>(
        &self,
        user_id: i32,
        event_type: EventType,
        path: &EntryPath,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<EventEntity, sqlx::Error> {
        EventRepository::create(user_id, event_type, path, executor).await
    }

    /// Broadcast an event to all subscribers.
    /// This should be called AFTER the database transaction has been committed.
    ///
    /// ## Timing
    /// It's critical to broadcast only after commit to avoid race conditions where
    /// subscribers receive events that don't exist in the database yet.
    pub(crate) fn broadcast_event(&self, event: EventEntity) {
        match self.event_tx.send(event) {
            Ok(_) => {} // Successfully broadcast to receivers
            Err(broadcast::error::SendError(_)) => {
                // No active receivers - this is expected when no clients are listening
            }
        }
    }

    /// Send a Postgres NOTIFY to wake up all PgEventListener instances.
    /// Call this AFTER the transaction has been committed.
    ///
    /// This is a best-effort wake-up signal. The PgEventListener will poll the
    /// database for actual events, so a missed NOTIFY only adds latency (up to
    /// the fallback poll interval) — it never causes missed events.
    pub async fn notify_event(&self) {
        if let Err(e) = sqlx::query("SELECT pg_notify($1, '')")
            .bind(PG_NOTIFY_CHANNEL)
            .execute(self.sql_db.pool())
            .await
        {
            tracing::error!("Failed to send NOTIFY: {}", e);
        }
    }

    /// Get a list of public (`/pub/...`) events starting from a cursor position.
    /// Private events are served only through the authenticated event stream.
    ///
    /// ## Parameters
    /// - `cursor`: Starting position (None = from beginning)
    /// - `limit`: Maximum number of events to return (None = default limit)
    pub async fn get_public_by_cursor<'a>(
        &self,
        cursor: Option<EventCursor>,
        limit: Option<u16>,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<EventEntity>, sqlx::Error> {
        EventRepository::get_by_cursor(cursor, limit, EventVisibility::Public, executor).await
    }

    /// All events (public and private) by a single global cursor.
    /// Admin-only, exposes private paths.
    pub async fn get_all_events<'a>(
        &self,
        cursor: Option<EventCursor>,
        limit: Option<u16>,
        reverse: bool,
        path_filters: &[PathFilter],
        user_ids: Option<&[i32]>,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<EventEntity>, sqlx::Error> {
        EventRepository::get_all_filtered_by_cursor(
            cursor,
            limit,
            reverse,
            path_filters,
            user_ids,
            executor,
        )
        .await
    }

    /// Get events for multiple users with individual cursor positions.
    ///
    /// ## Parameters
    /// - `user_cursors`: Vec of (user_id, optional_cursor) pairs
    /// - `limit`: Maximum number of events to return (None = default limit)
    /// - `reverse`: If true, return newest events first
    /// - `allowed_paths`: Authorized paths, an event is returned only if
    ///   it matches at least one (see [`PathFilter`]). Expected non-empty, the
    ///   route defaults to `/pub/`.
    pub async fn get_by_user_cursors<'a>(
        &self,
        user_cursors: Vec<(i32, Option<EventCursor>)>,
        limit: Option<u16>,
        reverse: bool,
        allowed_paths: &[PathFilter],
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<EventEntity>, sqlx::Error> {
        EventRepository::get_by_user_cursors(user_cursors, limit, reverse, allowed_paths, executor)
            .await
    }

    /// Stream **all** events (the admin firehose): replay history over a single advancing global
    /// cursor, then — in `ForwardLive` mode — stay open on the broadcast channel. Yields domain
    /// [`EventEntity`]s for the caller to frame (e.g. SSE). Exposes private paths, so only
    /// admin-authenticated routes may call it.
    pub(crate) fn all_events_stream(
        &self,
        metrics: Metrics,
        filter: AllEventsFilter,
    ) -> impl Stream<Item = EventEntity> {
        stream_events(
            self.clone(),
            metrics,
            StreamCursor::Global {
                last: filter.start_cursor,
                user_ids: filter.user_ids,
            },
            StreamOptions {
                paths: filter.paths,
                mode: filter.mode,
                limit: filter.limit,
            },
            NoGuard,
        )
    }

    /// Stream the given users' events: replay history from each user's own cursor, then — in
    /// `ForwardLive` mode — stay open on the broadcast channel. The `guard` closes the stream once
    /// the credential behind it is revoked. Yields only events under the authorized paths.
    pub(crate) fn user_events_stream(
        &self,
        metrics: Metrics,
        filter: UserEventsFilter,
        guard: impl StreamGuard,
    ) -> impl Stream<Item = EventEntity> {
        stream_events(
            self.clone(),
            metrics,
            StreamCursor::PerUser(filter.user_cursors.into_iter().collect()),
            StreamOptions {
                paths: filter.allowed_paths,
                mode: filter.mode,
                limit: filter.limit,
            },
            guard,
        )
    }

    pub(super) fn sql_db(&self) -> &SqlDb {
        &self.sql_db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::SqlDb;
    use crate::services::user_service::UserService;
    use crate::shared::webdav::StoragePath;
    use pubky_common::crypto::Keypair;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_events_service_create_and_broadcast() {
        let db = SqlDb::test().await;
        let events_service = EventsService::new(db.clone(), 100);
        let user_service = UserService::new(db.clone());

        let user_pubkey = Keypair::random().public_key();
        let user = user_service.create(&user_pubkey).await.unwrap();

        let path = EntryPath::new(user_pubkey.clone(), StoragePath::new("/test.txt").unwrap());

        // Subscribe before creating event
        let mut rx = events_service.subscribe();

        // Create event within transaction
        let mut tx = db.pool().begin().await.unwrap();
        let event = events_service
            .create_event(
                user.id,
                EventType::Put {
                    content_hash: pubky_common::crypto::Hash::from_bytes([0; 32]),
                },
                &path,
                &mut (&mut tx).into(),
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();

        // Broadcast after commit
        events_service.broadcast_event(event.clone());

        // Verify broadcast received
        let received = rx.recv().await.unwrap();
        assert_eq!(received.id, event.id);
        assert_eq!(received.user_id, user.id);
        assert!(matches!(received.event_type, EventType::Put { .. }));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_events_service_get_public_by_cursor() {
        let db = SqlDb::test().await;
        let events_service = EventsService::new(db.clone(), 100);
        let user_service = UserService::new(db.clone());

        let user_pubkey = Keypair::random().public_key();
        let user = user_service.create(&user_pubkey).await.unwrap();

        // Interleave public and private events: ids 1=/pub/a, 2=/priv/x,
        // 3=/pub/b, 4=/priv/y, 5=/pub/c.
        let paths = ["/pub/a", "/priv/x", "/pub/b", "/priv/y", "/pub/c"];
        for p in paths {
            let path = EntryPath::new(user_pubkey.clone(), StoragePath::new(p).unwrap());
            events_service
                .create_event(
                    user.id,
                    EventType::Put {
                        content_hash: pubky_common::crypto::Hash::from_bytes([0; 32]),
                    },
                    &path,
                    &mut db.pool().into(),
                )
                .await
                .unwrap();
        }

        // From the beginning, only public events come back, in id order.
        let events = events_service
            .get_public_by_cursor(None, None, &mut db.pool().into())
            .await
            .unwrap();
        let returned: Vec<&str> = events.iter().map(|e| e.path.path().as_str()).collect();
        assert_eq!(returned, vec!["/pub/a", "/pub/b", "/pub/c"]);

        // A limited page returns a FULL page of public events despite the
        // interleaved private ones, and the next cursor resumes correctly.
        let page = events_service
            .get_public_by_cursor(None, Some(2), &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].id, 1); // /pub/a
        assert_eq!(page[1].id, 3); // /pub/b (skips /priv/x at id 2)

        let next_cursor = page.last().unwrap().cursor();
        let page = events_service
            .get_public_by_cursor(Some(next_cursor), Some(2), &mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, 5); // /pub/c (skips /priv/y at id 4)
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_events_service_get_all_events_includes_private() {
        let db = SqlDb::test().await;
        let events_service = EventsService::new(db.clone(), 100);
        let user_service = UserService::new(db.clone());

        let user_pubkey = Keypair::random().public_key();
        let user = user_service.create(&user_pubkey).await.unwrap();

        // Same interleaving as the public test: ids 1=/pub/a, 2=/priv/x,
        // 3=/pub/b, 4=/priv/y, 5=/pub/c.
        let paths = ["/pub/a", "/priv/x", "/pub/b", "/priv/y", "/pub/c"];
        for p in paths {
            let path = EntryPath::new(user_pubkey.clone(), StoragePath::new(p).unwrap());
            events_service
                .create_event(
                    user.id,
                    EventType::Put {
                        content_hash: pubky_common::crypto::Hash::from_bytes([0; 32]),
                    },
                    &path,
                    &mut db.pool().into(),
                )
                .await
                .unwrap();
        }

        // No filters: every event, private ones included, in id order.
        let events = events_service
            .get_all_events(None, None, false, &[], None, &mut db.pool().into())
            .await
            .unwrap();
        let returned: Vec<&str> = events.iter().map(|e| e.path.path().as_str()).collect();
        assert_eq!(
            returned,
            vec!["/pub/a", "/priv/x", "/pub/b", "/priv/y", "/pub/c"]
        );

        // reverse=true returns newest first.
        let events = events_service
            .get_all_events(None, None, true, &[], None, &mut db.pool().into())
            .await
            .unwrap();
        let returned: Vec<&str> = events.iter().map(|e| e.path.path().as_str()).collect();
        assert_eq!(
            returned,
            vec!["/pub/c", "/priv/y", "/pub/b", "/priv/x", "/pub/a"]
        );

        // A union of path filters scopes to those roots (here a single private directory).
        let path_filters = [PathFilter::from(StoragePath::new("/priv/").unwrap())];
        let events = events_service
            .get_all_events(
                None,
                None,
                false,
                &path_filters,
                None,
                &mut db.pool().into(),
            )
            .await
            .unwrap();
        let returned: Vec<&str> = events.iter().map(|e| e.path.path().as_str()).collect();
        assert_eq!(returned, vec!["/priv/x", "/priv/y"]);

        // Multiple path filters union (any-match): an exact file OR a directory subtree.
        let path_filters = [
            PathFilter::from(StoragePath::new("/pub/a").unwrap()),
            PathFilter::from(StoragePath::new("/priv/").unwrap()),
        ];
        let events = events_service
            .get_all_events(
                None,
                None,
                false,
                &path_filters,
                None,
                &mut db.pool().into(),
            )
            .await
            .unwrap();
        let returned: Vec<&str> = events.iter().map(|e| e.path.path().as_str()).collect();
        assert_eq!(returned, vec!["/pub/a", "/priv/x", "/priv/y"]);

        // user_ids filters to those users.
        let events = events_service
            .get_all_events(
                None,
                None,
                false,
                &[],
                Some(&[user.id]),
                &mut db.pool().into(),
            )
            .await
            .unwrap();
        assert_eq!(events.len(), 5);
    }
}
