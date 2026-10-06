//! Atomic replay consumption and the state shared by built-in stores.

use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// Digest of the verified issuer, grant ID, audience, and nonce.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplayKey(pub(crate) [u8; 32]);

impl ReplayKey {
    /// Stable 32-byte key suitable for a database unique constraint.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ReplayKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayKey").finish_non_exhaustive()
    }
}

/// Verified consumption request. Only the verifier constructs these requests.
///
/// A store must check the time bounds under its consumption lock, reject clock
/// rollback, and bind its state to the policy fingerprint before returning success.
#[derive(Clone, Debug)]
pub struct ReplayRequest {
    pub(crate) key: ReplayKey,
    pub(crate) not_before: u64,
    pub(crate) expires_at: u64,
    pub(crate) policy: [u8; 32],
}

impl ReplayRequest {
    /// Key that must be inserted atomically, at most once.
    #[must_use]
    pub const fn key(&self) -> ReplayKey {
        self.key
    }
    /// Earliest accepted Unix second, inclusive.
    #[must_use]
    pub const fn not_before(&self) -> u64 {
        self.not_before
    }
    /// Retention deadline and latest accepted Unix second, exclusive.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    /// Fingerprint of audience and verification policy; changing it requires a new store.
    #[must_use]
    pub const fn policy_fingerprint(&self) -> &[u8; 32] {
        &self.policy
    }
}

/// Result of an atomic replay-store operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// The proof was consumed and may be accepted.
    Consumed,
    /// This proof was already consumed.
    AlreadyConsumed,
}

/// Storage failures reject authentication. Never discard live records to recover capacity.
#[derive(Debug, thiserror::Error)]
pub enum ReplayStoreError {
    /// Capacity or journal configuration is invalid.
    #[error("Invalid replay store configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// Live entries or journal bytes reached the configured limit.
    #[error("Replay store capacity exhausted")]
    Capacity,
    /// Another process or handle owns the file store.
    #[error("Replay store is already open")]
    AlreadyOpen,
    /// Audience or verification policy differs from the store's existing binding.
    #[error("Replay store belongs to a different audience or verification policy")]
    PolicyMismatch,
    /// Time has moved behind the last observed or persisted cleanup time.
    #[error("Clock moved backwards; replay protection cannot proceed")]
    ClockRollback,
    /// The proof expired or became too far in the future while waiting for storage.
    #[error("Proof is outside its acceptance window")]
    OutsideTimeWindow,
    /// Persistent bytes are truncated, corrupt, or use an unsupported format.
    #[error("Invalid replay journal: {0}")]
    Corrupt(&'static str),
    /// A previous uncertain write or poisoned lock requires reopening the store.
    #[error("Replay store is unavailable; reopen it before retrying")]
    Unavailable,
    /// Filesystem operation failed.
    #[error("Replay store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Blocking storage task could not complete.
    #[error("Replay store task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

/// Atomic consumption boundary used by a service verifier.
///
/// Implementations must recheck request time bounds after acquiring their lock,
/// reject incompatible policy fingerprints, and retain consumed keys until
/// `expires_at`. Reject allocations when full, not evicting live keys. A canceled
/// call may consume a key; clients must generate fresh proofs when retrying.
/// Multi-instance deployments must share the same authoritative storage.
/// Persistent implementations must make consumption durable before returning
/// success; the memory store explicitly provides only process-local protection.
#[async_trait::async_trait]
pub trait ReplayStore: fmt::Debug + Send + Sync {
    /// Consume a verified proof once, or report a prior consumption.
    ///
    /// # Errors
    /// Returns storage, capacity, clock, or policy errors without accepting the proof.
    async fn consume_once(
        &self,
        request: ReplayRequest,
    ) -> Result<ConsumeOutcome, ReplayStoreError>;
}

#[async_trait::async_trait]
impl<S: ReplayStore + ?Sized> ReplayStore for Arc<S> {
    async fn consume_once(
        &self,
        request: ReplayRequest,
    ) -> Result<ConsumeOutcome, ReplayStoreError> {
        self.as_ref().consume_once(request).await
    }
}

pub(super) fn now_unix() -> Result<u64, ReplayStoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_error| ReplayStoreError::ClockRollback)
}

/// Live replay records and the policy/clock floor that make expiry cleanup safe.
#[derive(Debug, Default)]
pub(super) struct ReplayIndex {
    pub entries: HashMap<ReplayKey, u64>,
    pub policy: Option<[u8; 32]>,
    pub last_seen: u64,
}

/// Preflight decision, before a new consumption has been recorded durably.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReplayCheck {
    Fresh,
    AlreadyConsumed,
}

impl ReplayIndex {
    pub fn prepare(
        &mut self,
        request: &ReplayRequest,
        now: u64,
        capacity: usize,
    ) -> Result<ReplayCheck, ReplayStoreError> {
        if self.policy.is_some_and(|policy| policy != request.policy) {
            return Err(ReplayStoreError::PolicyMismatch);
        }
        if now < self.last_seen {
            return Err(ReplayStoreError::ClockRollback);
        }
        if now < request.not_before || now >= request.expires_at {
            return Err(ReplayStoreError::OutsideTimeWindow);
        }
        self.last_seen = now;
        self.entries.retain(|_, deadline| *deadline > now);
        if self.entries.contains_key(&request.key) {
            return Ok(ReplayCheck::AlreadyConsumed);
        }
        if self.entries.len() >= capacity {
            return Err(ReplayStoreError::Capacity);
        }
        Ok(ReplayCheck::Fresh)
    }

    pub fn record(&mut self, request: &ReplayRequest) {
        self.policy = Some(request.policy);
        self.entries.insert(request.key, request.expires_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiration_capacity_clock_and_policy_checks_preserve_live_entries() {
        let first = ReplayRequest {
            key: ReplayKey([1; 32]),
            not_before: 90,
            expires_at: 110,
            policy: [3; 32],
        };
        let second = ReplayRequest {
            key: ReplayKey([2; 32]),
            not_before: 90,
            expires_at: 120,
            policy: [3; 32],
        };
        let mut index = ReplayIndex::default();
        assert_eq!(index.prepare(&first, 100, 1).unwrap(), ReplayCheck::Fresh);
        index.record(&first);
        assert!(matches!(
            index.prepare(&second, 109, 1),
            Err(ReplayStoreError::Capacity)
        ));
        assert_eq!(
            index.prepare(&first, 109, 1).unwrap(),
            ReplayCheck::AlreadyConsumed
        );
        assert!(matches!(
            index.prepare(&second, 108, 1),
            Err(ReplayStoreError::ClockRollback)
        ));
        assert_eq!(index.prepare(&second, 110, 1).unwrap(), ReplayCheck::Fresh);
        index.record(&second);
        assert!(matches!(
            index.prepare(&first, 110, 1),
            Err(ReplayStoreError::OutsideTimeWindow)
        ));
        let changed = ReplayRequest {
            policy: [4; 32],
            ..second
        };
        assert!(matches!(
            index.prepare(&changed, 110, 1),
            Err(ReplayStoreError::PolicyMismatch)
        ));
    }
}
