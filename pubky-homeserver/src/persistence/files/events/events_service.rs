use std::time::Instant;

use futures_util::Stream;
use sqlx::PgPool;
use tokio::sync::broadcast;

use crate::observability::{ConnectionGuard, Metrics};
use crate::persistence::{
    files::events::{
        EventCursor, EventEntity, EventRepository, EventType, EventVisibility, PathFilter,
    },
    sql::{SqlDb, UnifiedExecutor},
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
    event_tx: broadcast::Sender<EventEntity>,
    channel_capacity: usize,
}

/// Ordering + live behavior for the admin all-events stream. Encoding the mutually exclusive
/// options as one enum makes the invalid reverse-and-live combination unrepresentable.
#[derive(Clone, Copy, PartialEq, Eq)]
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
    fn reverse(self) -> bool {
        matches!(self, Self::Reverse)
    }
    /// Stay open for live events after replaying history.
    fn live(self) -> bool {
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

impl EventsService {
    /// Create a new EventsService with a broadcast channel.
    /// The channel_capacity determines how many events can be buffered before old ones are dropped.
    pub fn new(channel_capacity: usize) -> Self {
        let (event_tx, _rx) = broadcast::channel(channel_capacity);
        Self {
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
    /// EventsService::notify_event(pool).await;
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
    pub async fn notify_event(pool: &PgPool) {
        if let Err(e) = sqlx::query("SELECT pg_notify($1, '')")
            .bind(PG_NOTIFY_CHANNEL)
            .execute(pool)
            .await
        {
            tracing::error!("Failed to send NOTIFY: {}", e);
        }
    }

    /// Parse a cursor string into a Cursor object.
    /// Supports both new cursor format (event ID) and legacy format (timestamp).
    pub async fn parse_cursor<'a>(
        &self,
        cursor: &str,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<EventCursor, sqlx::Error> {
        EventRepository::parse_cursor(cursor, executor).await
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
    /// - `reverse`: If true, return newest events first
    /// - `allowed_paths`: Authorized paths, an event is returned only if
    ///   it matches at least one (see [`PathFilter`]). Expected non-empty, the
    ///   route defaults to `/pub/`.
    pub async fn get_by_user_cursors<'a>(
        &self,
        user_cursors: Vec<(i32, Option<EventCursor>)>,
        reverse: bool,
        allowed_paths: &[PathFilter],
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Vec<EventEntity>, sqlx::Error> {
        EventRepository::get_by_user_cursors(user_cursors, reverse, allowed_paths, executor).await
    }

    /// Stream **all** events (the admin firehose): replay history over a single advancing global
    /// cursor, then — in `ForwardLive` mode — stay open on the broadcast channel. Yields domain
    /// [`EventEntity`]s for the caller to frame (e.g. SSE). Exposes private paths, so only
    /// admin-authenticated routes may call it.
    pub(crate) fn all_events_stream(
        &self,
        sql_db: SqlDb,
        metrics: Metrics,
        filter: AllEventsFilter,
    ) -> impl Stream<Item = EventEntity> {
        let service = self.clone();
        let mut rx = self.subscribe();
        let half_capacity = self.channel_capacity() / 2;

        async_stream::stream! {
            // Cleanup + connection metrics on any exit path.
            let _guard = ConnectionGuard::new(metrics.clone());

            let mut last_cursor = filter.start_cursor;
            let mut total_sent: usize = 0;
            let reverse = filter.mode.reverse();
            let live = filter.mode.live();

            // Historical replay over a single advancing global cursor.
            loop {
                // Drain buffered events; they'll be covered by this or a later DB query.
                while rx.try_recv().is_ok() {}

                // Only fetch the events still owed under `limit`
                let batch_limit = match filter.limit {
                    Some(max) => match (max as usize).saturating_sub(total_sent) {
                        0 => return,
                        remaining => Some(remaining as u16),
                    },
                    None => None,
                };

                let query_start = Instant::now();
                let events = match service
                    .get_all_events(
                        last_cursor,
                        batch_limit,
                        reverse,
                        &filter.paths,
                        filter.user_ids.as_deref(),
                        &mut sql_db.pool().into(),
                    )
                    .await
                {
                    Ok(events) => events,
                    Err(e) => {
                        tracing::error!("Database error while streaming admin events: {}", e);
                        break;
                    }
                };
                metrics.record_event_stream_db_query(query_start.elapsed().as_millis());

                // An empty batch means we've replayed everything up to `last_cursor`.
                let caught_up = events.is_empty();
                for event in events {
                    last_cursor = Some(event.cursor());
                    yield event;
                    total_sent += 1;
                }
                if caught_up {
                    if !live {
                        return;
                    }
                    break;
                }
            }

            // The live tail, runs only for a live stream.
            if live {
                loop {
                    match rx.recv().await {
                        Ok(event) => {
                            if rx.len() >= half_capacity {
                                metrics.record_broadcast_half_full();
                            }
                            if !accept_live_event(&event, last_cursor, &filter) {
                                continue;
                            }
                            if filter.limit.is_some_and(|max| total_sent >= max as usize) {
                                return;
                            }
                            last_cursor = Some(event.cursor());
                            yield event;
                            total_sent += 1;
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            metrics.record_broadcast_lagged();
                            tracing::warn!(
                                "Slow admin client detected: broadcast channel lagged by {} events. Closing connection.",
                                skipped
                            );
                            return;
                        }
                        Err(_) => break, // Channel closed
                    }
                }
            }
        }
    }
}

/// Whether a live broadcast event belongs in an all-events stream: not already sent (cursor dedup),
/// inside the optional user filter, and under the optional path filter.
fn accept_live_event(
    event: &EventEntity,
    last_cursor: Option<EventCursor>,
    filter: &AllEventsFilter,
) -> bool {
    if let Some(cursor) = last_cursor {
        if event.cursor() <= cursor {
            return false;
        }
    }
    if let Some(ids) = filter.user_ids.as_deref() {
        if !ids.contains(&event.user_id) {
            return false;
        }
    }
    if !filter.paths.is_empty() {
        let path = event.path.path();
        if !filter.paths.iter().any(|f| f.matches(path.as_str())) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::{user::UserRepository, SqlDb};
    use crate::shared::webdav::StoragePath;
    use pubky_common::crypto::Keypair;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_events_service_create_and_broadcast() {
        let db = SqlDb::test().await;
        let events_service = EventsService::new(100);

        let user_pubkey = Keypair::random().public_key();
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

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
        let events_service = EventsService::new(100);

        let user_pubkey = Keypair::random().public_key();
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

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
        let events_service = EventsService::new(100);

        let user_pubkey = Keypair::random().public_key();
        let user = UserRepository::create(&user_pubkey, &mut db.pool().into())
            .await
            .unwrap();

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
