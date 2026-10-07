//! The lock a write or delete runs under, from the request that presents its
//! token to the transaction that changes the file.
//!
//! A request's lock is checked before it starts, but the file changes later,
//! on a finalization task that outlives the request. By then the lock may have
//! expired and been taken by someone else, so the change is refused unless the
//! lock is still held at that moment. Three steps, all of them here:
//!
//! 1. [`run_under`]: the HTTP layer runs the write under the token it checked.
//! 2. [`carry`]: the token follows the write onto its finalization task.
//! 3. [`hold`]: inside the finalization transaction, the lock is held until
//!    commit, or the finalization is refused because the lock is gone.
//!
//! The token travels as a task-local because OpenDAL's write and delete calls
//! sit between the request and the finalization and have no slot for it. The
//! task-local is private to this module: nothing else can set or read it.
//!
//! A write that does not go through [`run_under`] runs under no lock and is
//! never refused.

use std::future::Future;

use opendal::Result;

use crate::persistence::files::layer_domain_error::LayerDomainError;
use crate::persistence::sql::{entry_lock::EntryLockRepository, UnifiedExecutor};
use crate::shared::webdav::EntryPath;

use super::layer::unexpected;

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

/// Hold the lock the current task runs under until the executor's transaction
/// ends, or fail if the lock is gone.
///
/// Call it holding the user row, so no other change to the file can slip in
/// between the check and this one. Holding the lock from then on keeps it from
/// changing hands before the change is committed.
pub(super) async fn hold(entry_path: &EntryPath, executor: &mut UnifiedExecutor<'_>) -> Result<()> {
    let Some(token) = current_token() else {
        return Ok(());
    };
    let held = EntryLockRepository::hold(entry_path, &token, executor)
        .await
        .map_err(|error| unexpected(format!("Failed to hold lock on {entry_path}"), error))?;
    if !held {
        tracing::warn!(path = %entry_path, "Refusing a write whose lock was lost");
        return Err(lock_lost_error(entry_path));
    }
    Ok(())
}

fn lock_lost_error(entry_path: &EntryPath) -> opendal::Error {
    opendal::Error::new(
        opendal::ErrorKind::ConditionNotMatch,
        format!("Lock lost before {entry_path} was changed"),
    )
    .set_source(LayerDomainError::LockLost)
}
