//! Postgres LISTEN/NOTIFY event broadcaster for cross-instance event propagation.
//!
//! This module implements a background service that polls the events table for new
//! events and broadcasts them to local SSE subscribers. Postgres NOTIFY is used as
//! a wake-up hint to minimize latency, but the database is always the source of truth.
//!
//! This design guarantees sequential delivery with no gaps: events are always read
//! from the database in order, so a missed NOTIFY or listener reconnection cannot
//! cause events to be skipped.
//!
//! **Latency trade-off:** Even the instance that writes an event does not broadcast
//! it directly in-process. Instead it round-trips through Postgres (NOTIFY → DB read
//! → broadcast). This adds a small amount of latency compared to direct broadcasting,
//! but is the correct trade-off for horizontal scalability - every instance sees every
//! event without needing its own broadcast path.

use std::sync::Arc;
use std::time::Duration;

use sqlx::{postgres::PgListener, PgPool};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::constants::DEFAULT_MAX_LIST_LIMIT;
use crate::persistence::files::events::{
    EventCursor, EventRepository, EventVisibility, EventsService, PG_NOTIFY_CHANNEL,
};
use crate::persistence::sql::UnifiedExecutor;

/// Default fallback poll interval when no NOTIFY is received.
/// This is a safety net for rare failures (missed NOTIFYs, listener downtime).
/// In the happy path, NOTIFY wakes the poll loop immediately.
const DEFAULT_FALLBACK_POLL_INTERVAL: Duration = Duration::from_secs(30);

const _: () = assert!(
    PgEventListener::BATCH_SIZE <= DEFAULT_MAX_LIST_LIMIT,
    "BATCH_SIZE must not exceed DEFAULT_MAX_LIST_LIMIT",
);

/// Background service that polls the events table and broadcasts new events locally.
///
/// Uses Postgres NOTIFY as a wake-up hint to minimize latency. The database is
/// always the source of truth - events are read sequentially by ID, guaranteeing
/// no gaps even if NOTIFYs are lost.
pub struct PgEventListener {
    poll_handle: Option<JoinHandle<()>>,
    listen_handle: Option<JoinHandle<()>>,
    cancel: CancellationToken,
}

impl PgEventListener {
    /// Start the event broadcaster.
    ///
    /// Spawns two tasks:
    /// 1. A LISTEN task that receives Postgres NOTIFY and wakes the poll loop
    /// 2. A poll loop that reads new events from the DB and broadcasts them
    ///
    /// On startup, initializes `last_broadcast_id` to the current max event ID,
    /// so only new events created after startup are broadcast.
    #[must_use = "the listener stops receiving events when dropped"]
    pub async fn start(pool: &PgPool, events_service: EventsService) -> Result<Self, sqlx::Error> {
        Self::start_with_poll_interval(pool, events_service, DEFAULT_FALLBACK_POLL_INTERVAL).await
    }

    /// Start the event broadcaster with a custom fallback poll interval.
    /// Useful for tests that need shorter timeouts.
    async fn start_with_poll_interval(
        pool: &PgPool,
        events_service: EventsService,
        fallback_poll_interval: Duration,
    ) -> Result<Self, sqlx::Error> {
        let pool = pool.clone();
        let wake = Arc::new(Notify::new());
        let cancel = CancellationToken::new();

        // Initialize last_broadcast_id to current max event ID before spawning tasks,
        // so only events created after this point are broadcast.
        // Retry a few times before giving up — starting from 0 would replay the entire
        // event history, so we treat this as a hard failure after retries are exhausted.
        let mut last_err = None;
        let mut initial_id = None;
        for attempt in 1..=3 {
            match EventRepository::get_max_id(&mut UnifiedExecutor::from(&pool)).await {
                Ok(max_id) => {
                    tracing::info!("PgEventListener starting, last_broadcast_id = {}", max_id);
                    initial_id = Some(max_id);
                    break;
                }
                Err(e) => {
                    tracing::error!("Failed to get max event ID (attempt {}/3): {}", attempt, e);
                    last_err = Some(e);
                    if attempt < 3 {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
        let initial_id = match initial_id {
            Some(id) => id,
            None => return Err(last_err.expect("last_err must be set when initial_id is None")),
        };
        let listen_handle = {
            let pool = pool.clone();
            let wake = wake.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                Self::listen_loop(pool, wake, cancel).await;
            })
        };

        let poll_handle = {
            let wake = wake.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                Self::poll_loop(
                    pool,
                    events_service,
                    wake,
                    initial_id,
                    fallback_poll_interval,
                    cancel,
                )
                .await;
            })
        };

        Ok(Self {
            poll_handle: Some(poll_handle),
            listen_handle: Some(listen_handle),
            cancel,
        })
    }

    /// Main poll loop: reads new events from DB and broadcasts them.
    /// Woken by NOTIFY hints or falls back to periodic polling.
    async fn poll_loop(
        pool: PgPool,
        events_service: EventsService,
        wake: Arc<Notify>,
        mut last_broadcast_id: u64,
        fallback_poll_interval: Duration,
        cancel: CancellationToken,
    ) {
        loop {
            // Wait for NOTIFY hint, timeout, or cancellation
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("Poll loop cancelled, shutting down");
                    return;
                }
                _ = tokio::time::timeout(fallback_poll_interval, wake.notified()) => {}
            }

            // Poll DB for new events
            if let Err(e) =
                Self::broadcast_new_events(&pool, &events_service, &mut last_broadcast_id, &wake)
                    .await
            {
                tracing::error!("Error polling events from DB: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    /// Query DB for events after last_broadcast_id and broadcast them in order.
    /// Processes up to `MAX_BATCHES_PER_WAKE` batches per wake cycle to bound latency
    /// under sustained write pressure. Remaining events will be picked up on the next cycle.
    const MAX_BATCHES_PER_WAKE: usize = 10;
    /// Must not exceed `DEFAULT_MAX_LIST_LIMIT` (1000), which caps the limit in
    /// `EventRepository::get_by_cursor`. If it did, `is_full_batch` would never
    /// trigger and the multi-batch continuation logic would silently break.
    const BATCH_SIZE: u16 = 100;

    async fn broadcast_new_events(
        pool: &PgPool,
        events_service: &EventsService,
        last_broadcast_id: &mut u64,
        wake: &Notify,
    ) -> Result<(), sqlx::Error> {
        for _ in 0..Self::MAX_BATCHES_PER_WAKE {
            let cursor = EventCursor::new(*last_broadcast_id);

            let events = EventRepository::get_by_cursor(
                Some(cursor),
                Some(Self::BATCH_SIZE),
                EventVisibility::All,
                &mut UnifiedExecutor::from(pool),
            )
            .await?;

            if events.is_empty() {
                return Ok(());
            }

            let is_full_batch = events.len() == Self::BATCH_SIZE as usize;

            for event in &events {
                events_service.broadcast_event(event.clone());
                *last_broadcast_id = event.id;
            }

            if !is_full_batch {
                return Ok(());
            }

            // Yield to let other tasks run between batches.
            tokio::task::yield_now().await;
        }

        // Hit the batch cap — wake ourselves immediately to continue without
        // waiting for the fallback poll interval.
        tracing::debug!(
            "Hit max batch cap ({}), scheduling immediate continuation",
            Self::MAX_BATCHES_PER_WAKE
        );
        wake.notify_one();
        Ok(())
    }

    /// LISTEN loop: receives Postgres NOTIFY and wakes the poll loop.
    /// Handles reconnection on errors. Exits when the cancellation token is triggered.
    async fn listen_loop(pool: PgPool, wake: Arc<Notify>, cancel: CancellationToken) {
        loop {
            if cancel.is_cancelled() {
                tracing::info!("Listen loop cancelled, shutting down");
                return;
            }
            match Self::run_listener(&pool, &wake, &cancel).await {
                Err(e) => {
                    tracing::error!("PgListener error: {}. Reconnecting in 1s...", e);
                    // Wake the poll loop so it can catch up on any events missed
                    // during the listener downtime
                    wake.notify_one();
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Ok(()) => return, // Cancelled
            }
        }
    }

    /// Run the NOTIFY listener until an error occurs or cancellation is requested.
    /// Ignores the payload - just wakes the poll loop.
    async fn run_listener(
        pool: &PgPool,
        wake: &Notify,
        cancel: &CancellationToken,
    ) -> Result<(), sqlx::Error> {
        let mut listener = PgListener::connect_with(pool).await?;
        listener.listen(PG_NOTIFY_CHANNEL).await?;

        tracing::info!("PgEventListener NOTIFY listener started");

        // Wake poll loop to catch any events created during connection setup.
        // This is critical after reconnection to fill gaps from the downtime window.
        wake.notify_one();

        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                result = listener.recv() => {
                    result?;
                    wake.notify_one();
                }
            }
        }
    }
}

impl Drop for PgEventListener {
    fn drop(&mut self) {
        tracing::info!("PgEventListener shutting down");
        // Signal both tasks to exit their loops gracefully.
        self.cancel.cancel();
        // Abort as a fallback in case a task is blocked on a non-cancellation-aware future.
        if let Some(handle) = self.poll_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.listen_handle.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::files::events::{EventRepository, EventType, EventsService};
    use crate::persistence::sql::SqlDb;
    use crate::services::user_service::UserService;
    use crate::shared::webdav::{EntryPath, StoragePath};
    use pubky_common::crypto::{Hash, Keypair};
    use std::time::Duration;
    use tokio::sync::broadcast;

    /// Helper: create a real event in the DB and send a NOTIFY to wake the listener.
    async fn create_event_and_notify(
        db: &SqlDb,
        user_id: i32,
        path: &str,
        pubkey: &pubky_common::crypto::PublicKey,
    ) -> u64 {
        let entry_path = EntryPath::new(pubkey.clone(), StoragePath::new(path).unwrap());
        let mut tx = db.pool().begin().await.unwrap();
        let event = EventRepository::create(
            user_id,
            EventType::Put {
                content_hash: Hash::from_bytes([1; 32]),
            },
            &entry_path,
            &mut UnifiedExecutor::from(&mut tx),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // Send NOTIFY to wake the listener (empty payload, just a hint)
        EventsService::notify_event(db.pool()).await;

        event.id
    }

    /// Test that two instances sharing the same DB both receive all events.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_cross_instance_propagation() {
        let db = SqlDb::test().await;

        let events_service_a = EventsService::new(100);
        let _listener_a = PgEventListener::start(db.pool(), events_service_a.clone())
            .await
            .unwrap();

        let events_service_b = EventsService::new(100);
        let _listener_b = PgEventListener::start(db.pool(), events_service_b.clone())
            .await
            .unwrap();

        let keypair = Keypair::random();
        let pubkey = keypair.public_key();
        let user = UserService::new(db.clone()).create(&pubkey).await.unwrap();

        let mut rx_a = events_service_a.subscribe();
        let mut rx_b = events_service_b.subscribe();

        // Instance A writes an event
        let event_id = create_event_and_notify(&db, user.id, "/pub/from-a.txt", &pubkey).await;

        // Both instances should receive it
        let recv_a = tokio::time::timeout(Duration::from_secs(5), rx_a.recv())
            .await
            .expect("Timeout")
            .expect("Channel closed");
        let recv_b = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("Timeout")
            .expect("Channel closed");

        assert_eq!(recv_a.id, event_id, "Instance A should receive the event");
        assert_eq!(recv_b.id, event_id, "Instance B should receive the event");
    }

    /// Helper: create an event in the DB without sending NOTIFY.
    async fn create_event_silent(
        db: &SqlDb,
        user_id: i32,
        path: &str,
        pubkey: &pubky_common::crypto::PublicKey,
    ) -> u64 {
        let entry_path = EntryPath::new(pubkey.clone(), StoragePath::new(path).unwrap());
        let mut tx = db.pool().begin().await.unwrap();
        let event = EventRepository::create(
            user_id,
            EventType::Put {
                content_hash: Hash::from_bytes([1; 32]),
            },
            &entry_path,
            &mut UnifiedExecutor::from(&mut tx),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        event.id
    }

    /// Test that fallback polling delivers events when NOTIFY is unavailable.
    /// Covers: normal event delivery, then silent events (simulating lost NOTIFYs
    /// during a listener reconnect), verifying all arrive in order with no gaps.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_fallback_polling_delivers_gap_events() {
        let db = SqlDb::test().await;
        let events_service = EventsService::new(100);

        let _listener = PgEventListener::start_with_poll_interval(
            db.pool(),
            events_service.clone(),
            Duration::from_millis(500),
        )
        .await
        .unwrap();

        let keypair = Keypair::random();
        let pubkey = keypair.public_key();
        let user = UserService::new(db.clone()).create(&pubkey).await.unwrap();

        let mut rx = events_service.subscribe();

        // Phase 1: Deliver an event normally via NOTIFY to advance last_broadcast_id
        let first_id = create_event_and_notify(&db, user.id, "/pub/normal.txt", &pubkey).await;
        let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("Timeout")
            .expect("Channel closed");
        assert_eq!(received.id, first_id);

        // Phase 2: Create events WITHOUT NOTIFY (simulating lost notifications)
        let mut gap_ids = Vec::new();
        for i in 1..=5 {
            let id =
                create_event_silent(&db, user.id, &format!("/pub/gap{}.txt", i), &pubkey).await;
            gap_ids.push(id);
        }

        // Phase 3: All gap events should arrive via fallback polling, in order
        for (idx, expected_id) in gap_ids.iter().enumerate() {
            let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "Timeout waiting for gap event {}/{} — fallback polling failed",
                        idx + 1,
                        gap_ids.len()
                    )
                })
                .expect("Channel closed");
            assert_eq!(
                received.id,
                *expected_id,
                "Gap event {} should be delivered in order",
                idx + 1
            );
        }
    }

    /// Test that get_max_id returns 0 on an empty table and the correct ID after inserts.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_max_id() {
        let db = SqlDb::test().await;

        // Empty table should return 0
        let max_id = EventRepository::get_max_id(&mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(max_id, 0);

        // Insert some events
        let keypair = Keypair::random();
        let pubkey = keypair.public_key();
        let user = UserService::new(db.clone()).create(&pubkey).await.unwrap();

        let mut last_id = 0;
        for i in 1..=3 {
            last_id =
                create_event_silent(&db, user.id, &format!("/pub/file{}.txt", i), &pubkey).await;
        }

        let max_id = EventRepository::get_max_id(&mut db.pool().into())
            .await
            .unwrap();
        assert_eq!(max_id, last_id);
    }

    /// Test that dropping a listener and starting a new one correctly catches up.
    /// Simulates: instance crash → events produced during downtime → instance restart.
    /// The new listener should skip gap events (they're already in the DB for cursor-based
    /// SSE catch-up) and only broadcast events created after restart.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_listener_restart_skips_gap_and_resumes() {
        let db = SqlDb::test().await;
        let events_service = EventsService::new(100);

        let keypair = Keypair::random();
        let pubkey = keypair.public_key();
        let user = UserService::new(db.clone()).create(&pubkey).await.unwrap();

        // Phase 1: Start listener, verify it works
        let listener = PgEventListener::start(db.pool(), events_service.clone())
            .await
            .unwrap();
        let mut rx = events_service.subscribe();

        let initial_id =
            create_event_and_notify(&db, user.id, "/pub/before-crash.txt", &pubkey).await;

        let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("Timeout")
            .expect("Channel closed");
        assert_eq!(received.id, initial_id);

        // Phase 2: Drop listener (simulates crash)
        drop(listener);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Phase 3: Create events during the gap (no listener running)
        let mut gap_ids = Vec::new();
        for i in 1..=3 {
            let id =
                create_event_silent(&db, user.id, &format!("/pub/during-gap{}.txt", i), &pubkey)
                    .await;
            gap_ids.push(id);
        }

        // Phase 4: Start a NEW listener (simulates instance restart)
        let _listener2 = PgEventListener::start(db.pool(), events_service.clone())
            .await
            .unwrap();

        // Phase 5: Create a new event after restart
        let post_restart_id =
            create_event_and_notify(&db, user.id, "/pub/after-restart.txt", &pubkey).await;

        // Phase 6: The subscriber should receive ONLY the post-restart event.
        // Gap events are skipped because the new listener initialized last_broadcast_id
        // to the DB max (which includes the gap events).
        let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("Timeout waiting for post-restart event")
            .expect("Channel closed");
        assert_eq!(
            received.id, post_restart_id,
            "Should receive the post-restart event, not a gap event"
        );
    }

    /// Test that the batch loop handles more than 100 events correctly.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_batch_boundary_over_100_events() {
        let db = SqlDb::test().await;
        let events_service = EventsService::new(250);

        let _listener = PgEventListener::start(db.pool(), events_service.clone())
            .await
            .unwrap();

        let keypair = Keypair::random();
        let pubkey = keypair.public_key();
        let user = UserService::new(db.clone()).create(&pubkey).await.unwrap();

        let mut rx = events_service.subscribe();

        // Create 150 events (exceeds the batch size of 100)
        let total = 150;
        let mut expected_ids = Vec::new();
        for i in 1..=total {
            let id =
                create_event_silent(&db, user.id, &format!("/pub/batch{}.txt", i), &pubkey).await;
            expected_ids.push(id);
        }

        // Send a single NOTIFY to wake the poll loop
        EventsService::notify_event(db.pool()).await;

        // All 150 events should be delivered in order
        for (idx, expected_id) in expected_ids.iter().enumerate() {
            let received = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("Timeout waiting for event {}/{}", idx + 1, total))
                .expect("Channel closed");
            assert_eq!(
                received.id,
                *expected_id,
                "Event {} out of order: expected {}, got {}",
                idx + 1,
                expected_id,
                received.id
            );
        }
    }

    /// Test that concurrent writers produce events that are all delivered in order.
    /// Multiple tasks write events simultaneously while the listener is running.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_concurrent_writers() {
        let db = SqlDb::test().await;
        let events_service = EventsService::new(500);

        let _listener = PgEventListener::start(db.pool(), events_service.clone())
            .await
            .unwrap();

        let keypair = Keypair::random();
        let pubkey = keypair.public_key();
        let user = UserService::new(db.clone()).create(&pubkey).await.unwrap();

        let mut rx = events_service.subscribe();

        // Spawn 10 tasks that each create 5 events concurrently
        let num_tasks = 10;
        let events_per_task = 5;
        let mut handles = Vec::new();
        for task_idx in 0..num_tasks {
            let db = db.clone();
            let pubkey = pubkey.clone();
            let user_id = user.id;
            handles.push(tokio::spawn(async move {
                let mut ids = Vec::new();
                for event_idx in 0..events_per_task {
                    let id = create_event_and_notify(
                        &db,
                        user_id,
                        &format!("/pub/t{}-e{}.txt", task_idx, event_idx),
                        &pubkey,
                    )
                    .await;
                    ids.push(id);
                }
                ids
            }));
        }

        // Collect all created event IDs
        let mut all_ids = Vec::new();
        for handle in handles {
            all_ids.extend(handle.await.unwrap());
        }
        all_ids.sort();

        let total = all_ids.len();
        assert_eq!(total, num_tasks * events_per_task);

        // Receive all events — they must arrive in strictly ascending ID order
        let mut received_ids = Vec::new();
        for i in 0..total {
            let received = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("Timeout waiting for event {}/{}", i + 1, total))
                .expect("Channel closed");
            received_ids.push(received.id);
        }

        // Verify monotonically increasing (the poll loop reads by ID order)
        for window in received_ids.windows(2) {
            assert!(
                window[0] < window[1],
                "Events not in order: {} should be before {}",
                window[0],
                window[1]
            );
        }
        // Verify we got every event
        assert_eq!(received_ids, all_ids);
    }

    /// Regression test for MVCC visibility gaps under concurrent writes.
    ///
    /// Uses a barrier to force all tasks to insert events simultaneously,
    /// maximising the chance of out-of-order commits. The advisory lock
    /// serialises inserts so that IDs are always committed in ascending order.
    /// Without the lock, the poll loop could advance its cursor past an
    /// uncommitted lower ID and permanently skip it.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_concurrent_barrier_inserts_no_skipped_events() {
        let db = SqlDb::test().await;
        let events_service = EventsService::new(500);

        let _listener = PgEventListener::start_with_poll_interval(
            db.pool(),
            events_service.clone(),
            Duration::from_millis(200),
        )
        .await
        .unwrap();

        let keypair = Keypair::random();
        let pubkey = keypair.public_key();
        let user = UserService::new(db.clone()).create(&pubkey).await.unwrap();

        let mut rx = events_service.subscribe();

        // All tasks wait on the barrier before inserting, forcing true concurrency.
        let num_tasks: usize = 20;
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(num_tasks));

        let mut handles = Vec::new();
        for i in 0..num_tasks {
            let db = db.clone();
            let pubkey = pubkey.clone();
            let user_id = user.id;
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let entry_path = EntryPath::new(
                    pubkey,
                    StoragePath::new(&format!("/pub/race{}.txt", i)).unwrap(),
                );
                let mut tx = db.pool().begin().await.unwrap();
                let event = EventRepository::create(
                    user_id,
                    EventType::Put {
                        content_hash: Hash::from_bytes([1; 32]),
                    },
                    &entry_path,
                    &mut UnifiedExecutor::from(&mut tx),
                )
                .await
                .unwrap();
                tx.commit().await.unwrap();
                EventsService::notify_event(db.pool()).await;
                event.id
            }));
        }

        let mut all_ids: Vec<u64> = Vec::new();
        for h in handles {
            all_ids.push(h.await.unwrap());
        }
        all_ids.sort();
        assert_eq!(all_ids.len(), num_tasks);

        // Receive all events from the poll loop
        let mut received_ids = Vec::new();
        for i in 0..num_tasks {
            let received = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("Timeout at event {}/{}", i + 1, num_tasks))
                .expect("Channel closed");
            received_ids.push(received.id);
        }

        // Every event must be delivered, in strictly ascending order
        for window in received_ids.windows(2) {
            assert!(
                window[0] < window[1],
                "Events out of order: {} before {}",
                window[0],
                window[1],
            );
        }
        assert_eq!(
            received_ids, all_ids,
            "All events must be delivered with no gaps"
        );
    }

    /// Test that a slow subscriber that falls behind the broadcast channel capacity
    /// experiences a Lagged error but can recover by re-subscribing.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_broadcast_channel_overflow_lagged_receiver() {
        let db = SqlDb::test().await;
        // Use a very small channel capacity to force overflow
        let channel_capacity = 4;
        let events_service = EventsService::new(channel_capacity);

        let _listener = PgEventListener::start_with_poll_interval(
            db.pool(),
            events_service.clone(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        let keypair = Keypair::random();
        let pubkey = keypair.public_key();
        let user = UserService::new(db.clone()).create(&pubkey).await.unwrap();

        // Subscribe but do NOT read — simulate a slow consumer
        let mut rx = events_service.subscribe();

        // Create more events than the channel can hold
        let overflow_count = channel_capacity + 10;
        let mut all_ids = Vec::new();
        for i in 0..overflow_count {
            let id =
                create_event_and_notify(&db, user.id, &format!("/pub/overflow{}.txt", i), &pubkey)
                    .await;
            all_ids.push(id);
        }

        // Poll until we see a Lagged error (with timeout instead of fixed sleep).
        // The poll loop will broadcast all events, overflowing the small channel.
        let mut saw_lagged = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Ok(_)) => continue, // Consume buffered events
                Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                    saw_lagged = true;
                    assert!(
                        n > 0,
                        "Lagged count should be positive when channel overflows"
                    );
                    break;
                }
                Ok(Err(broadcast::error::RecvError::Closed)) => {
                    panic!("Channel should not be closed")
                }
                Err(_) => break, // Timeout
            }
        }
        assert!(
            saw_lagged,
            "Slow receiver should have been lagged by channel overflow"
        );

        // After lagging, re-subscribe to get a fresh receiver, then verify
        // new events are still delivered.
        let mut rx = events_service.subscribe();
        let new_id =
            create_event_and_notify(&db, user.id, "/pub/after-overflow.txt", &pubkey).await;

        // Drain until we see the specific new event (older events may still be in-flight)
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut found = false;
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Ok(event)) if event.id == new_id => {
                    found = true;
                    break;
                }
                Ok(Ok(_)) => continue, // Older event, skip
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(broadcast::error::RecvError::Closed)) => {
                    panic!("Channel closed unexpectedly")
                }
                Err(_) => break, // Timeout
            }
        }
        assert!(
            found,
            "Should receive new event after re-subscribing post-overflow"
        );
    }
}
