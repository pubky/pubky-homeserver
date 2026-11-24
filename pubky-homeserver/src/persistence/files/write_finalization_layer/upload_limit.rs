//! Counts open upload writers on one homeserver replica.

use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use pubky_common::crypto::PublicKey;

use crate::persistence::files::layer_domain_error::LayerDomainError;

#[derive(Debug)]
pub(super) struct UploadLimit {
    per_user: NonZeroUsize,
    active: Mutex<HashMap<PublicKey, usize>>,
}

impl UploadLimit {
    pub(super) fn new(per_user: NonZeroUsize) -> Self {
        Self {
            per_user,
            active: Mutex::default(),
        }
    }

    pub(super) fn try_acquire(self: &Arc<Self>, user: &PublicKey) -> opendal::Result<UploadSlot> {
        let mut active = self.active.lock().expect("upload counts poisoned");
        let count = active.entry(user.clone()).or_default();
        if *count >= self.per_user.get() {
            return Err(opendal::Error::new(
                opendal::ErrorKind::RateLimited,
                "Too many concurrent uploads",
            )
            .set_source(LayerDomainError::TooManyUploads));
        }
        *count += 1;
        Ok(UploadSlot {
            limit: self.clone(),
            user: user.clone(),
        })
    }
}

/// Stays with the writer through finalization or disconnect cleanup.
pub(super) struct UploadSlot {
    limit: Arc<UploadLimit>,
    user: PublicKey,
}

impl Drop for UploadSlot {
    fn drop(&mut self) {
        let mut active = self.limit.active.lock().expect("upload counts poisoned");
        let count = active
            .get_mut(&self.user)
            .expect("active upload has a slot");
        *count -= 1;
        if *count == 0 {
            active.remove(&self.user);
        }
    }
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Keypair;

    use super::*;

    #[test]
    fn concurrent_upload_limit_releases_only_the_finished_slot() {
        let limit = Arc::new(UploadLimit::new(NonZeroUsize::new(2).unwrap()));
        let owner = Keypair::random().public_key();
        let first = limit.try_acquire(&owner).unwrap();
        let second = limit.try_acquire(&owner).unwrap();
        assert!(limit.try_acquire(&owner).is_err());

        drop(first);
        let replacement = limit.try_acquire(&owner).unwrap();
        assert!(limit.try_acquire(&owner).is_err());
        drop(second);
        drop(replacement);
        assert!(limit.active.lock().unwrap().is_empty());
    }
}
