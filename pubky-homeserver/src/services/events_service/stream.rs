//! The two-phase event stream shared by the client and admin routes: replay
//! history from the database in batches, then (in live mode) tail the
//! broadcast channel. The routes differ only in how a stream resumes
//! ([`StreamCursor`]) and in whether its credential is re-checked while the
//! stream is open ([`StreamGuard`]).

use std::{
    collections::HashMap,
    future::{self, Future},
    time::Instant,
};

use futures_util::Stream;
use tokio::sync::broadcast;

use super::{EventsService, Mode};
use crate::{
    observability::{ConnectionGuard, Metrics},
    persistence::sql::events::{EventCursor, EventEntity, PathFilter},
};

/// Re-checks a stream's credential while the stream is open. The client stream
/// binds private subscriptions to a session; the admin stream has nothing to
/// re-check.
pub(crate) trait StreamGuard: Send + 'static {
    /// Whether the stream may continue. Called before each batch and each event.
    fn is_valid(&mut self) -> impl Future<Output = bool> + Send;

    /// Waits for the next credential signal, then returns the check that must
    /// complete once this future has won a `select!`. Keeping the slow part in
    /// the returned future stops a ready event from cancelling it.
    fn next_check(&mut self) -> impl Future<Output = impl Future<Output = bool> + Send> + Send;
}

/// A guard for streams with nothing to re-check.
pub(super) struct NoGuard;

impl StreamGuard for NoGuard {
    fn is_valid(&mut self) -> impl Future<Output = bool> + Send {
        future::ready(true)
    }

    fn next_check(&mut self) -> impl Future<Output = impl Future<Output = bool> + Send> + Send {
        future::pending::<future::Ready<bool>>()
    }
}

/// Where a stream has got to, in the two shapes the routes resume from.
pub(super) enum StreamCursor {
    /// Client stream: only these users, each resuming from its own cursor.
    PerUser(HashMap<i32, Option<EventCursor>>),
    /// Admin stream: one cursor over the whole feed, optionally restricted to
    /// some users (`None` = every user).
    Global {
        last: Option<EventCursor>,
        user_ids: Option<Vec<i32>>,
    },
}

impl StreamCursor {
    /// The next batch of history after this cursor.
    async fn fetch(
        &self,
        service: &EventsService,
        limit: Option<u16>,
        reverse: bool,
        paths: &[PathFilter],
    ) -> Result<Vec<EventEntity>, sqlx::Error> {
        let mut executor = service.sql_db().pool().into();
        match self {
            Self::PerUser(cursors) => {
                let user_cursors = cursors.iter().map(|(id, cursor)| (*id, *cursor)).collect();
                service
                    .get_by_user_cursors(user_cursors, limit, reverse, paths, &mut executor)
                    .await
            }
            Self::Global { last, user_ids } => {
                service
                    .get_all_events(
                        *last,
                        limit,
                        reverse,
                        paths,
                        user_ids.as_deref(),
                        &mut executor,
                    )
                    .await
            }
        }
    }

    /// Record an event as sent so the live tail does not repeat it.
    fn advance(&mut self, event: &EventEntity) {
        match self {
            Self::PerUser(cursors) => {
                cursors.insert(event.user_id, Some(event.cursor()));
            }
            Self::Global { last, .. } => *last = Some(event.cursor()),
        }
    }

    /// Whether a live broadcast event belongs in this stream: from a streamed
    /// user, not already sent, and under `paths` (empty = every path).
    fn accepts_live(&self, event: &EventEntity, paths: &[PathFilter]) -> bool {
        let last = match self {
            Self::PerUser(cursors) => match cursors.get(&event.user_id) {
                Some(last) => *last,
                None => return false,
            },
            Self::Global { last, user_ids } => {
                if user_ids
                    .as_ref()
                    .is_some_and(|ids| !ids.contains(&event.user_id))
                {
                    return false;
                }
                *last
            }
        };
        if last.is_some_and(|last| event.cursor() <= last) {
            return false;
        }
        let path = event.path.path();
        paths.is_empty() || paths.iter().any(|filter| filter.matches(path.as_str()))
    }
}

/// What a stream sends, beyond where it resumes from.
pub(super) struct StreamOptions {
    /// Path filters (union). Empty = every path.
    pub paths: Vec<PathFilter>,
    pub mode: Mode,
    /// Maximum total events to send before closing.
    pub limit: Option<u16>,
}

/// Replay history after `cursor` in batches, then tail the broadcast channel in
/// live mode. Closes after `limit` events, when caught up in batch mode, when
/// the guard fails, or when the client falls behind the channel.
pub(super) fn stream_events(
    service: EventsService,
    metrics: Metrics,
    mut cursor: StreamCursor,
    options: StreamOptions,
    mut guard: impl StreamGuard,
) -> impl Stream<Item = EventEntity> {
    let half_capacity = service.channel_capacity() / 2;
    let reverse = options.mode.reverse();
    let live = options.mode.live();

    async_stream::stream! {
        // Connection metrics on any exit path.
        let _connection = ConnectionGuard::new(metrics.clone());
        // Subscribe before the first query so events committed during replay are buffered.
        let mut rx = service.subscribe();
        let mut total_sent: usize = 0;

        // Phase 1: replay history.
        loop {
            if !guard.is_valid().await {
                return;
            }
            // Drain buffered events; this or a later query covers them.
            while rx.try_recv().is_ok() {}

            // Only fetch the events still owed under `limit`; the per-event
            // check below returns before `total_sent` can reach it.
            let batch_limit = options.limit.map(|max| max - total_sent as u16);

            let query_start = Instant::now();
            let events = match cursor.fetch(&service, batch_limit, reverse, &options.paths).await {
                Ok(events) => events,
                Err(e) => {
                    tracing::error!("Database error while fetching events: {}", e);
                    break;
                }
            };
            metrics.record_event_stream_db_query(query_start.elapsed().as_millis());

            // An empty batch means everything up to the cursor has been replayed.
            let caught_up = events.is_empty();
            for event in events {
                if !guard.is_valid().await {
                    return;
                }
                cursor.advance(&event);
                yield event;
                total_sent += 1;
                if options.limit.is_some_and(|max| total_sent >= max as usize) {
                    return;
                }
            }
            if caught_up {
                if !live {
                    return;
                }
                break;
            }
        }

        // Phase 2: live tail.
        if live {
            loop {
                tokio::select! {
                    biased;
                    check = guard.next_check() => {
                        if !check.await {
                            return;
                        }
                    }
                    received = rx.recv() => match received {
                        Ok(event) => {
                            // Early warning of a slow client.
                            if rx.len() >= half_capacity {
                                metrics.record_broadcast_half_full();
                            }
                            if !cursor.accepts_live(&event, &options.paths) {
                                continue;
                            }
                            cursor.advance(&event);
                            yield event;
                            total_sent += 1;
                            if options.limit.is_some_and(|max| total_sent >= max as usize) {
                                return;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            metrics.record_broadcast_lagged();
                            tracing::warn!(
                                "Slow client detected: broadcast channel lagged by {} events. Closing connection.",
                                skipped
                            );
                            return;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Keypair;
    use sqlx::types::chrono::NaiveDateTime;

    use super::*;
    use crate::{
        persistence::sql::events::EventType,
        shared::webdav::{EntryPath, StoragePath},
    };

    fn event(user_id: i32, id: u64, path: &str) -> EventEntity {
        let user_pubkey = Keypair::random().public_key();
        EventEntity {
            id,
            user_id,
            user_pubkey: user_pubkey.clone(),
            event_type: EventType::Delete,
            path: EntryPath::new(user_pubkey, StoragePath::new(path).unwrap()),
            created_at: NaiveDateTime::default(),
        }
    }

    fn public() -> Vec<PathFilter> {
        vec![StoragePath::new("/pub/").unwrap().into()]
    }

    #[test]
    fn per_user_accepts_streamed_users_after_their_cursor_under_paths() {
        let cursor =
            StreamCursor::PerUser(HashMap::from([(1, Some(EventCursor::new(10))), (2, None)]));
        assert!(!cursor.accepts_live(&event(1, 10, "/pub/a"), &public()));
        assert!(cursor.accepts_live(&event(1, 11, "/pub/a"), &public()));
        assert!(cursor.accepts_live(&event(2, 1, "/pub/a"), &public()));
        assert!(!cursor.accepts_live(&event(3, 99, "/pub/a"), &public()));
        assert!(!cursor.accepts_live(&event(2, 1, "/priv/a"), &public()));
    }

    #[test]
    fn global_accepts_after_last_cursor_within_user_filter() {
        let filtered = StreamCursor::Global {
            last: Some(EventCursor::new(5)),
            user_ids: Some(vec![1]),
        };
        assert!(!filtered.accepts_live(&event(1, 5, "/priv/a"), &[]));
        assert!(filtered.accepts_live(&event(1, 6, "/priv/a"), &[]));
        assert!(!filtered.accepts_live(&event(2, 6, "/priv/a"), &[]));

        let firehose = StreamCursor::Global {
            last: None,
            user_ids: None,
        };
        assert!(firehose.accepts_live(&event(2, 1, "/priv/a"), &[]));
        assert!(!firehose.accepts_live(&event(2, 1, "/priv/a"), &public()));
    }

    #[test]
    fn advance_records_the_sent_event() {
        let mut per_user = StreamCursor::PerUser(HashMap::from([(1, None)]));
        per_user.advance(&event(1, 7, "/pub/a"));
        assert!(!per_user.accepts_live(&event(1, 7, "/pub/a"), &public()));
        assert!(per_user.accepts_live(&event(1, 8, "/pub/a"), &public()));

        let mut global = StreamCursor::Global {
            last: None,
            user_ids: None,
        };
        global.advance(&event(1, 7, "/pub/a"));
        assert!(!global.accepts_live(&event(2, 7, "/pub/a"), &[]));
        assert!(global.accepts_live(&event(2, 8, "/pub/a"), &[]));
    }
}
