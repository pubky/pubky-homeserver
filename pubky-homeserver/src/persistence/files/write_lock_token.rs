//! The lock token a write in flight runs under.
//!
//! Set by the HTTP layer around a write or delete that presented a lock token,
//! carried onto the finalization task when it is spawned, and checked against
//! the live lock inside the finalization transaction. Defined here rather than
//! in the HTTP layer so the persistence layer does not depend on it.

tokio::task_local! {
    /// `Some(token)` for a write that runs under a lock, `None` or unset for an
    /// unlocked write.
    pub(crate) static WRITE_LOCK_TOKEN: Option<String>;
}

/// The token of the lock the current task's write runs under, if any.
pub(crate) fn current_write_lock_token() -> Option<String> {
    WRITE_LOCK_TOKEN.try_with(Clone::clone).ok().flatten()
}
