//! Lock service — owns the lifecycle of the write locks on storage paths.

mod service;

pub(crate) use service::{
    LockError, LockService, DEFAULT_LOCK_TIMEOUT_SECS, MAX_LOCK_TIMEOUT_SECS,
};
