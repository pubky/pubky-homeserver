//! The lock a write or delete runs under, from the request that presents its
//! token to the change that reaches the storage backend.
//!
//! A request's lock is checked before it starts, but the file changes later,
//! on a finalization task that outlives the request, and the backend request
//! that publishes the change can outlive even that. The lock must not change
//! hands while any of it can still land. So a finalization reserves the lock
//! for a window long enough to cover the whole change, and until the window
//! has passed the lock cannot be released, replaced, shortened or reserved
//! again (see [`EntryLockRepository::reserve_publish`]). Four steps, all of
//! them here:
//!
//! 1. [`run_under`]: the HTTP layer runs the write under the token it checked.
//! 2. [`carry`]: the token follows the write onto its finalization task.
//! 3. [`reserve`]: before the finalization transaction begins, the lock is
//!    reserved for [`PUBLISH_WINDOW_SECS`], or the change is refused.
//! 4. [`check_window`]: inside the transaction, before the backend is told to
//!    publish, enough of the window must remain to cover the request however
//!    it ends: abandoned after [`BACKEND_IO_TIMEOUT`], aborted by the kernel
//!    after [`BACKEND_TCP_USER_TIMEOUT`], or executed late by the backend.
//! 5. [`keep_reserved`]: while the backend request is being waited for, the
//!    reservation is pushed out again every [`HEARTBEAT_INTERVAL`], so a
//!    request that is never abandoned, a local rename that the kernel takes
//!    its time over, keeps its lock however long it takes. Only a remote
//!    backend's calls are abandoned at the timeout; a local backend's are
//!    waited for to the end, and a process that dies takes them with it.
//!
//! The reservation ends with [`settle`]: at once when the backend confirmed
//! the change or nothing was ever sent to it, otherwise it is left to run
//! out, since the request may still reach the backend. A reservation is
//! extended and ended by when it ends, which a later change's always does
//! later, so a change that outran its window cannot touch the reservation a
//! later change has taken since.
//!
//! The reservation is taken outside the finalization transaction. That
//! transaction can die at any moment, a dropped connection or a failover, and
//! a reservation inside it would die with it while the backend request lives
//! on. The window is measured on the database clock, like every lock
//! lifetime, so it holds across instances.
//!
//! The token travels as a task-local because OpenDAL's write and delete calls
//! sit between the request and the finalization and have no slot for it. The
//! task-local is private to this module: nothing else can set or read it.
//!
//! A write that does not go through [`run_under`] runs under no lock and is
//! never refused.

use std::{future::Future, pin::pin, time::Duration};

use opendal::Result;

use crate::persistence::files::layer_domain_error::LayerDomainError;
use crate::persistence::sql::{entry_lock::EntryLockRepository, SqlDb, UnifiedExecutor};
use crate::shared::webdav::EntryPath;

use super::layer::unexpected;

/// Longest one remote backend I/O call may take before it is abandoned: a
/// chunk write, the close that publishes an upload, or a blob delete. Applied
/// to a remote backend's operator by the storage setup. A local backend's
/// calls are never abandoned: dropping a filesystem rename would not stop it,
/// only lose track of it.
pub(crate) const BACKEND_IO_TIMEOUT: Duration = Duration::from_secs(60);

/// Longest data sent to the backend may stay unacknowledged before the kernel
/// aborts the connection. Abandoning a request does not stop it: the kernel
/// keeps retransmitting what it has buffered, after the future is dropped and
/// even after the process is gone, until this runs out. Applied to the
/// backend's HTTP client by the storage setup, on Linux.
pub(crate) const BACKEND_TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);

/// Time the backend may take to act on a request it has received in full.
const BACKEND_EXECUTION_MARGIN_SECS: i64 = 30;

/// Window a publish must still have when it starts. By the time it has
/// passed, the backend has acted on the request or can never receive it.
const MIN_PUBLISH_WINDOW_SECS: i64 = BACKEND_IO_TIMEOUT.as_secs() as i64
    + BACKEND_TCP_USER_TIMEOUT.as_secs() as i64
    + BACKEND_EXECUTION_MARGIN_SECS;

/// How long a finalization may wait for its turn on the user row before its
/// window is too short to publish.
const USER_ROW_WAIT_BUDGET_SECS: i64 = 60;

/// The window a finalization reserves its lock for. Also how long a crashed
/// instance leaves a path with a change in flight locked.
pub(crate) const PUBLISH_WINDOW_SECS: i64 = MIN_PUBLISH_WINDOW_SECS + USER_ROW_WAIT_BUDGET_SECS;

/// How often a change waiting on its backend request pushes its reservation
/// out to a full window again, see [`keep_reserved`]. Well inside the
/// window, so a few failed heartbeats cost nothing.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

tokio::task_local! {
    static LOCK_TOKEN: Option<String>;
}

fn current_token() -> Option<String> {
    LOCK_TOKEN.try_with(Clone::clone).ok().flatten()
}

/// Run `write` under the lock held with `token`, or under no lock for `None`.
pub(crate) async fn run_under<T>(token: Option<String>, write: impl Future<Output = T>) -> T {
    LOCK_TOKEN.scope(token, write).await
}

/// Wrap a future that is about to be spawned, so it runs under the same lock
/// as the task spawning it. A new task starts with no task-locals.
pub(super) fn carry<F: Future>(task: F) -> impl Future<Output = F::Output> {
    LOCK_TOKEN.scope(current_token(), task)
}

/// Seconds after which a refused change can be retried. A change refused
/// before anything was sent ends its reservation with it, and one refused
/// behind an earlier change usually has only that change's publish to wait
/// for. Only an earlier change the backend never confirmed keeps refusing,
/// until its window has passed; a hint of the whole window would make
/// every client wait that long for the common case.
const RETRY_AT_ONCE_SECS: i64 = 1;

/// A lock reserved for one change, until [`settle`].
pub(super) struct PublishReservation {
    sql_db: SqlDb,
    entry_path: EntryPath,
    token: String,
    /// When the reservation ends, as last set here. Tells it from a later
    /// change's reservation, which ends later.
    publishing_until: i64,
}

/// How a change's backend request ended, for [`settle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BackendOutcome {
    /// The backend confirmed the change, or was never sent it.
    Done,
    /// Sent, and not confirmed: the backend may still act on it.
    Unconfirmed,
}

/// A failed change that knows how its backend request ended.
pub(super) trait FailedChange {
    fn backend_outcome(&self) -> BackendOutcome;
}

/// Reserve the lock the current task runs under for the change about to be
/// made to `entry_path`. Fails if the lock is gone, or still reserved for an
/// earlier change. `None` under no lock.
pub(super) async fn reserve(
    entry_path: &EntryPath,
    sql_db: &SqlDb,
) -> Result<Option<PublishReservation>> {
    let Some(token) = current_token() else {
        return Ok(None);
    };
    let mut executor: UnifiedExecutor = sql_db.pool().into();
    let reserved = EntryLockRepository::reserve_publish(
        entry_path,
        &token,
        PUBLISH_WINDOW_SECS,
        &mut executor,
    )
    .await
    .map_err(|error| unexpected(format!("Failed to reserve lock on {entry_path}"), error))?;
    let Some(reserved) = reserved else {
        let remaining =
            EntryLockRepository::publish_window_remaining(entry_path, &token, &mut executor)
                .await
                .map_err(|error| {
                    unexpected(format!("Failed to read lock on {entry_path}"), error)
                })?;
        return Err(match remaining {
            None => {
                tracing::warn!(path = %entry_path, "Refusing a change whose lock was lost");
                lock_lost_error(entry_path)
            }
            Some(remaining) => {
                tracing::warn!(
                    path = %entry_path,
                    remaining,
                    "Refusing a change whose lock is reserved for an earlier one"
                );
                lock_busy_error(entry_path, RETRY_AT_ONCE_SECS)
            }
        });
    };
    Ok(Some(PublishReservation {
        sql_db: sql_db.clone(),
        entry_path: entry_path.clone(),
        token,
        publishing_until: reserved.publishing_until,
    }))
}

/// Wait for `request`, the backend request of the change `reservation` is
/// for, pushing the reservation out to a full window every
/// [`HEARTBEAT_INTERVAL`] meanwhile. A request that is never abandoned is
/// covered for as long as it takes; one abandoned at the timeout has at
/// least the window [`check_window`] saw, less one interval, left to land in.
pub(super) async fn keep_reserved<T>(
    reservation: Option<&mut PublishReservation>,
    request: impl Future<Output = T>,
) -> T {
    keep_reserved_every(HEARTBEAT_INTERVAL, reservation, request).await
}

async fn keep_reserved_every<T>(
    interval: Duration,
    reservation: Option<&mut PublishReservation>,
    request: impl Future<Output = T>,
) -> T {
    let Some(reservation) = reservation else {
        return request.await;
    };
    let mut request = pin!(request);
    loop {
        tokio::select! {
            output = &mut request => return output,
            () = tokio::time::sleep(interval) => reservation.extend().await,
        }
    }
}

/// End `reservation`, if there is one, once the change is over, unless the
/// backend may still act on it: then the reservation runs out on its own, and
/// the lock stays put until it has.
pub(super) async fn settle<T, E: FailedChange>(
    reservation: Option<PublishReservation>,
    result: &std::result::Result<T, E>,
) {
    let Some(reservation) = reservation else {
        return;
    };
    let outcome = result
        .as_ref()
        .map_or_else(FailedChange::backend_outcome, |_| BackendOutcome::Done);
    reservation.end_unless(outcome).await;
}

impl PublishReservation {
    /// Push the reservation out to a full window from now. A failure is only
    /// logged: the window [`check_window`] saw still stands, and the next
    /// heartbeat tries again.
    async fn extend(&mut self) {
        let mut executor: UnifiedExecutor = self.sql_db.pool().into();
        let extended = EntryLockRepository::extend_publish(
            &self.entry_path,
            &self.token,
            self.publishing_until,
            PUBLISH_WINDOW_SECS,
            &mut executor,
        )
        .await;
        match extended {
            Ok(Some(lock)) => self.publishing_until = lock.publishing_until,
            // Cannot happen while the reservation is live: nothing else ends
            // or replaces it. Left to run out, like a failed heartbeat.
            Ok(None) => tracing::error!(
                path = %self.entry_path,
                "Lock reservation is no longer this change's to extend"
            ),
            Err(error) => {
                tracing::warn!(path = %self.entry_path, %error, "Failed to extend a lock reservation")
            }
        }
    }

    async fn end_unless(self, outcome: BackendOutcome) {
        if outcome == BackendOutcome::Unconfirmed {
            tracing::warn!(
                path = %self.entry_path,
                "Leaving the lock reserved: the backend may still act on the change"
            );
            return;
        }
        let mut executor: UnifiedExecutor = self.sql_db.pool().into();
        if let Err(error) = EntryLockRepository::end_publish(
            &self.entry_path,
            &self.token,
            self.publishing_until,
            &mut executor,
        )
        .await
        {
            // The reservation runs out on its own; only the holder waits.
            tracing::warn!(path = %self.entry_path, %error, "Failed to end a lock reservation");
        }
    }
}

/// Check, right before the backend is told to publish, that the reservation
/// of the current task's lock still covers the request whatever happens to
/// it. Fails otherwise; nothing has been sent, so the caller's reservation
/// settles as [`BackendOutcome::Done`].
pub(super) async fn check_window(
    entry_path: &EntryPath,
    executor: &mut UnifiedExecutor<'_>,
) -> Result<()> {
    let Some(token) = current_token() else {
        return Ok(());
    };
    let remaining = EntryLockRepository::publish_window_remaining(entry_path, &token, executor)
        .await
        .map_err(|error| unexpected(format!("Failed to read lock on {entry_path}"), error))?;
    match remaining {
        None => {
            tracing::warn!(path = %entry_path, "Refusing a change whose lock was lost");
            Err(lock_lost_error(entry_path))
        }
        Some(remaining) if remaining < MIN_PUBLISH_WINDOW_SECS => {
            tracing::warn!(
                path = %entry_path,
                remaining,
                "Refusing a change with too little of its publish window left"
            );
            Err(lock_busy_error(entry_path, RETRY_AT_ONCE_SECS))
        }
        Some(_) => Ok(()),
    }
}

fn lock_lost_error(entry_path: &EntryPath) -> opendal::Error {
    opendal::Error::new(
        opendal::ErrorKind::ConditionNotMatch,
        format!("Lock lost before {entry_path} was changed"),
    )
    .set_source(LayerDomainError::LockLost)
}

fn lock_busy_error(entry_path: &EntryPath, retry_after_secs: i64) -> opendal::Error {
    opendal::Error::new(
        opendal::ErrorKind::ConditionNotMatch,
        format!("Lock on {entry_path} is reserved for an earlier change"),
    )
    .set_source(LayerDomainError::LockBusy {
        retry_after_secs: retry_after_secs as u64,
    })
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Keypair;

    use super::*;
    use crate::{persistence::sql::entry_lock::ReleaseOutcome, shared::webdav::StoragePath};

    /// A change waiting on a backend request that is never abandoned keeps
    /// its reservation however long the request takes, and settling ends the
    /// reservation as last extended.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn heartbeat_keeps_a_long_request_reserved_until_it_settles() {
        let db = SqlDb::test().await;
        let entry_path = EntryPath::new(
            Keypair::random().public_key(),
            StoragePath::new("/pub/a.txt").unwrap(),
        );
        let mut executor: UnifiedExecutor = db.pool().into();
        EntryLockRepository::acquire(&entry_path, "t", 60, &mut executor)
            .await
            .unwrap()
            .unwrap();
        let reservation = run_under(Some("t".to_string()), reserve(&entry_path, &db))
            .await
            .unwrap();
        let mut reservation = reservation.expect("the write runs under a lock");
        // The window is almost gone when the request starts.
        EntryLockRepository::set_publish_window(&entry_path, 2, &mut executor)
            .await
            .unwrap();

        let long_request = tokio::time::sleep(Duration::from_millis(300));
        keep_reserved_every(
            Duration::from_millis(50),
            Some(&mut reservation),
            long_request,
        )
        .await;

        let remaining =
            EntryLockRepository::publish_window_remaining(&entry_path, "t", &mut executor)
                .await
                .unwrap()
                .unwrap();
        assert!(
            remaining > PUBLISH_WINDOW_SECS - 5,
            "the heartbeat pushed the window out, {remaining}s remain"
        );

        let done: Result<(), WriteNeverFails> = Ok(());
        settle(Some(reservation), &done).await;
        assert_eq!(
            EntryLockRepository::release(&entry_path, "t", &mut executor)
                .await
                .unwrap(),
            ReleaseOutcome::Released
        );
    }

    struct WriteNeverFails;

    impl FailedChange for WriteNeverFails {
        fn backend_outcome(&self) -> BackendOutcome {
            BackendOutcome::Done
        }
    }

    /// The window is the correctness boundary: a request abandoned at the I/O
    /// timeout can still be delivered until the kernel gives up on it, and
    /// acted on for a while after that. Raising a timeout without the window
    /// following it would let a lock change hands under a change in flight.
    #[test]
    fn publish_window_covers_a_request_however_it_ends() {
        assert_eq!(BACKEND_IO_TIMEOUT.as_secs(), 60);
        assert_eq!(BACKEND_TCP_USER_TIMEOUT.as_secs(), 30);
        assert_eq!(MIN_PUBLISH_WINDOW_SECS, 60 + 30 + 30);
        assert_eq!(PUBLISH_WINDOW_SECS, MIN_PUBLISH_WINDOW_SECS + 60);
        const { assert!(PUBLISH_WINDOW_SECS >= MIN_PUBLISH_WINDOW_SECS + USER_ROW_WAIT_BUDGET_SECS) };
        // An abandoned request keeps most of the window it was checked for.
        const { assert!((HEARTBEAT_INTERVAL.as_secs() as i64) * 4 <= MIN_PUBLISH_WINDOW_SECS) };
    }
}
