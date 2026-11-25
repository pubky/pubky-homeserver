//! Counts upload reservations on one homeserver replica.

use std::{
    cell::RefCell,
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use opendal::{Operator, Writer};
use pubky_common::crypto::PublicKey;

use crate::persistence::files::layer_domain_error::LayerDomainError;
use crate::shared::webdav::EntryPath;

tokio::task_local! {
    // OpenDAL has no argument for a reserved slot. Only writer construction
    // runs in this scope. The finalization layer takes ownership of the slot.
    static RESERVED_SLOT: RefCell<Option<UploadSlot>>;
}

#[derive(Debug)]
pub(in crate::persistence::files) struct UploadLimit {
    per_user: NonZeroUsize,
    active: Mutex<HashMap<PublicKey, usize>>,
}

impl UploadLimit {
    pub(in crate::persistence::files) fn new(per_user: NonZeroUsize) -> Self {
        Self {
            per_user,
            active: Mutex::default(),
        }
    }

    /// Direct operator writers acquire a slot here. HTTP uploads bring the
    /// slot they reserved before checking the WebDAV lock.
    pub(super) fn slot_for_writer(
        self: &Arc<Self>,
        user: &PublicKey,
    ) -> opendal::Result<UploadSlot> {
        let reserved = RESERVED_SLOT.try_with(|slot| {
            slot.borrow_mut()
                .take_if(|slot| Arc::ptr_eq(self, &slot.limit) && &slot.user == user)
        });
        match reserved {
            Ok(Some(slot)) => Ok(slot),
            _ => self.try_acquire(user),
        }
    }

    pub(in crate::persistence::files) fn try_acquire(
        self: &Arc<Self>,
        user: &PublicKey,
    ) -> opendal::Result<UploadSlot> {
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
pub(in crate::persistence::files) struct UploadSlot {
    limit: Arc<UploadLimit>,
    user: PublicKey,
}

impl UploadSlot {
    pub(in crate::persistence::files) async fn open_writer(
        self,
        operator: &Operator,
        path: &EntryPath,
    ) -> opendal::Result<Writer> {
        RESERVED_SLOT
            .scope(RefCell::new(Some(self)), operator.writer(path.as_str()))
            .await
    }
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
