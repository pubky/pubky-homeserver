//! Bounded process-local replay tracking.

use super::replay_store::{
    ConsumeOutcome, ReplayCheck, ReplayIndex, ReplayRequest, ReplayStore, ReplayStoreError,
    now_unix,
};
use std::sync::{Arc, Mutex};

/// Process-local replay protection. Clones share state; restarting loses replay history.
#[derive(Clone, Debug)]
pub struct MemoryReplayStore {
    state: Arc<Mutex<ReplayIndex>>,
    capacity: usize,
}

impl MemoryReplayStore {
    /// Create a replay store with an explicit maximum number of live entries.
    ///
    /// # Errors
    /// Rejects a zero capacity.
    pub fn new(capacity: usize) -> Result<Self, ReplayStoreError> {
        if capacity == 0 {
            return Err(ReplayStoreError::InvalidConfiguration(
                "capacity must be positive",
            ));
        }
        Ok(Self {
            state: Arc::new(Mutex::new(ReplayIndex::default())),
            capacity,
        })
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl ReplayStore for MemoryReplayStore {
    async fn consume_once(
        &self,
        request: ReplayRequest,
    ) -> Result<ConsumeOutcome, ReplayStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_error| ReplayStoreError::Unavailable)?;
        if state.prepare(&request, now_unix()?, self.capacity)? == ReplayCheck::AlreadyConsumed {
            return Ok(ConsumeOutcome::AlreadyConsumed);
        }
        state.record(&request);
        Ok(ConsumeOutcome::Consumed)
    }
}
