use std::{sync::Arc, time::Duration};

use sqlx::{postgres::PgListener, PgPool};
use tokio::{
    sync::{broadcast, oneshot, Mutex},
    time::Instant,
};

use super::{AuthRevocation, PG_AUTH_REVOCATION_CHANNEL};

/// Sized to absorb short revocation bursts without forcing unrelated streams
/// through a database revalidation round-trip.
const AUTH_REVOCATION_CHANNEL_CAPACITY: usize = 1024;
/// This keeps a Postgres outage from turning request rate into connection-attempt rate:
/// one attempt per window, and everyone else is told the listener is unavailable.
const REPLACEMENT_COOLDOWN: Duration = Duration::from_secs(1);

/// The local listener is unavailable, so accepting a private long-lived stream
/// could miss an already-committed revocation.
#[derive(Debug)]
pub(crate) struct RevocationUnavailable;

type RevocationReceiver = broadcast::Receiver<AuthRevocation>;
type SubscriptionResult = Result<RevocationReceiver, RevocationUnavailable>;

/// Local fan-out for committed authentication revocations.
#[derive(Clone, Debug)]
pub(crate) struct RevocationListener {
    supervisor: Arc<Mutex<Supervisor>>,
}

impl RevocationListener {
    /// Start the supervisor with a listener already receiving, so the app never
    /// starts serving private streams without its revocation feed.
    pub(crate) async fn start(pool: &PgPool) -> Result<Self, sqlx::Error> {
        let supervisor = Supervisor {
            pool: pool.clone(),
            actor: Some(ListenerActor::spawn(pool).await?),
            replacement_cooldown: ReplacementCooldown::default(),
        };
        Ok(Self {
            supervisor: Arc::new(Mutex::new(supervisor)),
        })
    }

    pub(crate) async fn subscribe(&self) -> SubscriptionResult {
        self.supervisor.lock().await.subscribe().await
    }
}

/// Serves subscriptions from one listener actor at a time.
#[derive(Debug)]
struct Supervisor {
    pool: PgPool,
    actor: Option<ListenerActorHandle>,
    replacement_cooldown: ReplacementCooldown,
}

#[derive(Debug, Default)]
struct ReplacementCooldown {
    last_attempt: Option<Instant>,
}

impl ReplacementCooldown {
    /// Return whether a replacement may start now. Refused attempts do not
    /// extend the current cooldown window.
    fn try_start(&mut self, now: Instant) -> bool {
        if self
            .last_attempt
            .is_some_and(|started| now.duration_since(started) < REPLACEMENT_COOLDOWN)
        {
            return false;
        }

        self.last_attempt = Some(now);
        true
    }
}

impl Supervisor {
    async fn subscribe(&mut self) -> SubscriptionResult {
        loop {
            if let Some(receiver) = self.actor.as_ref().and_then(ListenerActorHandle::subscribe) {
                return Ok(receiver);
            }

            self.actor = None;
            self.replace().await?;
        }
    }

    async fn replace(&mut self) -> Result<(), RevocationUnavailable> {
        if !self.replacement_cooldown.try_start(Instant::now()) {
            return Err(RevocationUnavailable);
        }

        let replacement = ListenerActor::spawn(&self.pool).await.map_err(|error| {
            tracing::error!(%error, "failed to start the auth revocation listener");
            RevocationUnavailable
        })?;
        tracing::info!("started a replacement auth revocation listener");
        self.actor = Some(replacement);
        Ok(())
    }
}

struct ListenerActor {
    listener: PgListener,
    notifications_tx: broadcast::Sender<AuthRevocation>,
    lifetime_rx: oneshot::Receiver<()>,
}

impl ListenerActor {
    /// Connect and `LISTEN` before spawning, so a failure surfaces to the
    /// caller instead of to a stream that already believes it is protected.
    async fn spawn(pool: &PgPool) -> Result<ListenerActorHandle, sqlx::Error> {
        let mut listener = PgListener::connect_with(pool).await?;
        // `try_recv` must report a lost connection before sqlx reconnects, so
        // existing private streams can be closed before a notification gap is
        // silently accepted.
        listener.eager_reconnect(false);
        listener.listen(PG_AUTH_REVOCATION_CHANNEL).await?;

        let (notifications_tx, _) = broadcast::channel(AUTH_REVOCATION_CHANNEL_CAPACITY);
        let (lifetime_tx, lifetime_rx) = oneshot::channel();
        let handle = ListenerActorHandle {
            notifications_tx: notifications_tx.downgrade(),
            _lifetime_tx: lifetime_tx,
        };
        let actor = Self {
            listener,
            notifications_tx,
            lifetime_rx,
        };
        drop(tokio::spawn(actor.run()));

        Ok(handle)
    }

    /// Forward notifications to this actor's subscribers until any gap makes
    /// the feed unsafe. Dropping the actor closes all of its receivers.
    async fn run(mut self) {
        loop {
            tokio::select! {
                _ = &mut self.lifetime_rx => return,
                notification = self.listener.try_recv() => match notification {
                    Ok(Some(notification)) => {
                        match serde_json::from_str::<AuthRevocation>(notification.payload()) {
                            Ok(revocation) => {
                                // No receivers is normal when no private streams are connected.
                                let _ = self.notifications_tx.send(revocation);
                            }
                            // The payload could be a revocation this instance would
                            // otherwise ignore, so it is not safe to skip.
                            Err(error) => {
                                tracing::error!(%error, "invalid auth revocation notification; closing private streams");
                                return;
                            }
                        }
                    }
                    Ok(None) => {
                        tracing::error!("auth revocation listener connection was lost; closing private streams");
                        return;
                    }
                    Err(error) => {
                        tracing::error!(%error, "auth revocation listener failed; closing private streams");
                        return;
                    }
                },
            }
        }
    }
}

#[derive(Debug)]
struct ListenerActorHandle {
    notifications_tx: broadcast::WeakSender<AuthRevocation>,
    _lifetime_tx: oneshot::Sender<()>,
}

impl ListenerActorHandle {
    fn subscribe(&self) -> Option<RevocationReceiver> {
        self.notifications_tx
            .upgrade()
            .map(|notifications_tx| notifications_tx.subscribe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::SqlDb;
    use tokio::time::{sleep, timeout};

    async fn receive_revocation(receiver: &mut RevocationReceiver) -> AuthRevocation {
        timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("timed out waiting for auth revocation")
            .expect("auth revocation channel unexpectedly closed")
    }

    async fn expect_closed(receiver: &mut RevocationReceiver) {
        let result = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("timed out waiting for the revocation channel to close");
        assert!(
            matches!(result, Err(broadcast::error::RecvError::Closed)),
            "expected a closed revocation channel, got {result:?}"
        );
    }

    async fn notify(pool: &PgPool, payload: &str) {
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(PG_AUTH_REVOCATION_CHANNEL)
            .bind(payload)
            .execute(pool)
            .await
            .expect("send notification");
    }

    async fn notify_cookie_revocation(pool: &PgPool, id: i32) {
        let payload = serde_json::to_string(&AuthRevocation::CookieSession(id))
            .expect("serialize revocation");
        notify(pool, &payload).await;
    }

    async fn listener_backend_pids(pool: &PgPool) -> Vec<i32> {
        sqlx::query_scalar::<_, i32>(
            "SELECT pid FROM pg_stat_activity \
             WHERE datname = current_database() \
               AND pid <> pg_backend_pid() \
               AND query = $1",
        )
        .bind(format!("LISTEN \"{PG_AUTH_REVOCATION_CHANNEL}\""))
        .fetch_all(pool)
        .await
        .expect("query listener backends")
    }

    async fn listener_backend_pid(pool: &PgPool) -> i32 {
        timeout(Duration::from_secs(5), async {
            loop {
                if let Some(pid) = listener_backend_pids(pool).await.first() {
                    return *pid;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timed out waiting for listener backend")
    }

    #[test]
    fn replacement_cooldown_throttles_without_extending_the_window() {
        let mut cooldown = ReplacementCooldown::default();
        let first_attempt = Instant::now();

        assert!(cooldown.try_start(first_attempt));
        assert!(!cooldown.try_start(first_attempt + REPLACEMENT_COOLDOWN - Duration::from_nanos(1)));
        assert!(cooldown.try_start(first_attempt + REPLACEMENT_COOLDOWN));
        assert!(!cooldown.try_start(first_attempt + REPLACEMENT_COOLDOWN));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn listeners_on_two_instances_receive_the_same_revocation() {
        let db = SqlDb::test().await;
        let listener_a = RevocationListener::start(db.pool()).await.unwrap();
        let listener_b = RevocationListener::start(db.pool()).await.unwrap();
        let mut receiver_a = listener_a.subscribe().await.unwrap();
        let mut receiver_b = listener_b.subscribe().await.unwrap();

        notify_cookie_revocation(db.pool(), 42).await;

        assert_eq!(
            receive_revocation(&mut receiver_a).await,
            AuthRevocation::CookieSession(42)
        );
        assert_eq!(
            receive_revocation(&mut receiver_b).await,
            AuthRevocation::CookieSession(42)
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_lost_connection_closes_private_streams_until_a_replacement_listener_takes_over() {
        let db = SqlDb::test().await;
        let listener = RevocationListener::start(db.pool()).await.unwrap();
        let mut orphaned = listener.subscribe().await.unwrap();

        let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
            .bind(listener_backend_pid(db.pool()).await)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert!(
            terminated,
            "Postgres should terminate the listener connection"
        );

        expect_closed(&mut orphaned).await;

        let mut receiver = listener
            .subscribe()
            .await
            .expect("a later subscription should start a replacement listener");

        notify_cookie_revocation(db.pool(), 42).await;
        assert_eq!(
            receive_revocation(&mut receiver).await,
            AuthRevocation::CookieSession(42)
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn an_invalid_notification_payload_closes_private_streams() {
        let db = SqlDb::test().await;
        let listener = RevocationListener::start(db.pool()).await.unwrap();
        let mut receiver = listener.subscribe().await.unwrap();

        notify(db.pool(), "not-an-auth-revocation").await;

        expect_closed(&mut receiver).await;
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn dropping_the_last_service_clone_releases_the_postgres_listener() {
        let db = SqlDb::test().await;
        let listener = RevocationListener::start(db.pool()).await.unwrap();
        let spare = listener.clone();
        let pid = listener_backend_pid(db.pool()).await;

        drop(listener);
        let mut receiver = spare
            .subscribe()
            .await
            .expect("a remaining clone keeps the listener alive");

        drop(spare);
        expect_closed(&mut receiver).await;

        timeout(Duration::from_secs(5), async {
            while listener_backend_pids(db.pool()).await.contains(&pid) {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timed out waiting for the listener connection to be released");
    }
}
