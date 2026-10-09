// js/src/actors/storage/lock.rs
use std::{cell::RefCell, time::Duration};

use wasm_bindgen::prelude::*;

use super::session::SessionStorage;
use crate::js_error::{JsResult, PubkyError, PubkyErrorName};

/// An exclusive write lock on one file path, granted by the homeserver.
///
/// While the lock lives, only writes that present it are accepted on the path;
/// every other write, and every other {@link SessionStorage.lock}, rejects with
/// `423 Locked`. The lock ends when it is {@link SessionStorage.unlock | unlocked}
/// or when its {@link StorageLock.timeoutSeconds} runs out without a
/// {@link SessionStorage.refreshLock | refresh}, so a client that disappears never
/// blocks a path for long.
///
/// The lock is a bearer token: whoever holds this value, and may write the path,
/// can use and release the lock.
///
/// Calls that take the lock may overlap: a {@link SessionStorage.refreshLock | refresh}
/// can run while a locked write is in flight.
///
/// @example
/// const lock = await session.storage.lock("/pub/my.app/state.json", 30);
/// const state = await session.storage.getText(lock.path);
/// await session.storage.putTextLocked(lock, state);
/// await session.storage.unlock(lock);
#[wasm_bindgen]
// A `RefCell` rather than `&mut` methods: a wasm-bindgen export that takes `&mut`
// holds the JS object's exclusive borrow across its whole `await`, so any overlapping
// use of the lock from JS would throw an aliasing error instead of rejecting.
pub struct StorageLock(RefCell<pubky::StorageLock>);

impl StorageLock {
    fn inner(&self) -> pubky::StorageLock {
        self.0.borrow().clone()
    }
}

#[wasm_bindgen]
impl StorageLock {
    /// The locked path.
    #[wasm_bindgen(getter, unchecked_return_type = "Path")]
    pub fn path(&self) -> String {
        self.0.borrow().path().as_str().to_owned()
    }

    /// The lock token URL, `opaquelocktoken:<uuid>`.
    #[wasm_bindgen(getter)]
    pub fn token(&self) -> String {
        self.0.borrow().token().to_owned()
    }

    /// Lifetime the homeserver granted at the last `lock` or `refreshLock`, in seconds,
    /// counted from when that call resolved. It may be shorter than what was asked for.
    /// It is not the time remaining: note when the call resolved to know when to refresh.
    #[wasm_bindgen(getter, js_name = "timeoutSeconds")]
    pub fn timeout_seconds(&self) -> f64 {
        self.0.borrow().timeout().as_secs_f64()
    }

    /// Value of the `If` header that presents this lock on a write.
    #[wasm_bindgen(js_name = "ifHeader")]
    pub fn if_header(&self) -> String {
        self.0.borrow().if_header()
    }
}

#[wasm_bindgen]
impl SessionStorage {
    /// Take an exclusive write lock on a file at an **absolute session path**.
    ///
    /// The file need not exist; locking a free path reserves it. `timeoutSeconds` is
    /// the lifetime asked for; the homeserver caps it, and
    /// {@link StorageLock.timeoutSeconds} tells what was granted. The lifetime is the
    /// caller's to manage: a write made under the lock must fit inside it, so
    /// {@link SessionStorage.refreshLock | refresh} the lock during a long upload. Once a
    /// write comes to change the file the homeserver keeps the lock until the change has
    /// landed, whatever the lifetime says.
    ///
    /// Nothing refreshes the lock on its own: an upload that outlives it is refused with
    /// 412 when it ends. To cover one longer than the lifetime, call
    /// {@link SessionStorage.refreshLock | refreshLock} from a timer while the write is
    /// in flight; the two calls may overlap.
    ///
    /// @param {Path} path File path; must not end with `/`.
    /// @param {number} timeoutSeconds Lifetime to ask for, in seconds; rounded down to
    /// whole seconds, and at least 1.
    /// @returns {Promise<StorageLock>} The granted lock.
    /// @throws {PubkyError} `InvalidInput` for a negative, NaN or out-of-range timeout;
    /// a path that is already locked rejects with `RequestError` and status `423`;
    /// directory targets with `400`; a homeserver without lock support with `405`.
    /// See {@link SessionStorage} for shared errors.
    #[wasm_bindgen]
    pub async fn lock(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
        timeout_seconds: f64,
    ) -> JsResult<StorageLock> {
        let timeout = seconds(timeout_seconds)?;
        let lock = self.0.lock(path, timeout).await?;
        Ok(StorageLock(RefCell::new(lock)))
    }

    /// Restart the lifetime of a lock this client holds.
    ///
    /// On success the lock carries the newly granted
    /// {@link StorageLock.timeoutSeconds}.
    ///
    /// @param {StorageLock} lock A lock this client holds.
    /// @param {number} timeoutSeconds Lifetime to ask for, in seconds; rounded down to
    /// whole seconds, and at least 1.
    /// @returns {Promise<void>}
    /// @throws {PubkyError} A lock that has expired or was unlocked rejects with
    /// `RequestError` and status `412`; take a new one and read the file again.
    /// `InvalidInput` for a negative, NaN or out-of-range timeout.
    /// See {@link SessionStorage} for shared errors.
    #[wasm_bindgen(js_name = "refreshLock")]
    pub async fn refresh_lock(&self, lock: &StorageLock, timeout_seconds: f64) -> JsResult<()> {
        let timeout = seconds(timeout_seconds)?;
        // Refresh a copy: the borrow must not be held across the await.
        let mut refreshed = lock.inner();
        self.0.refresh_lock(&mut refreshed, timeout).await?;
        *lock.0.borrow_mut() = refreshed;
        Ok(())
    }

    /// Release a lock this client holds.
    ///
    /// @param {StorageLock} lock A lock this client holds.
    /// @returns {Promise<void>}
    /// @throws {PubkyError} A lock that no longer exists rejects with `RequestError`
    /// and status `409`; a lock under which a write is still being published rejects with
    /// status `423` and a `Retry-After`, and the lock is still this client's, so unlock
    /// again once the write has landed. See {@link SessionStorage} for shared errors.
    #[wasm_bindgen]
    pub async fn unlock(&self, lock: &StorageLock) -> JsResult<()> {
        self.0.unlock(&lock.inner()).await?;
        Ok(())
    }

    /// `PUT` binary data to the path of a lock this client holds.
    ///
    /// @param {StorageLock} lock A lock this client holds.
    /// @param {Uint8Array} body
    /// @returns {Promise<void>}
    /// @throws {PubkyError} A lock that has expired or was unlocked rejects with
    /// `RequestError` and status `412`; take a new one and read the file again.
    /// Otherwise as {@link SessionStorage.putBytes}.
    #[wasm_bindgen(js_name = "putBytesLocked")]
    pub async fn put_bytes_locked(&self, lock: &StorageLock, body: &[u8]) -> JsResult<()> {
        self.0.put_locked(&lock.inner(), body.to_vec()).await?;
        Ok(())
    }

    /// `PUT` text to the path of a lock this client holds.
    ///
    /// @param {StorageLock} lock A lock this client holds.
    /// @param {string} body
    /// @returns {Promise<void>}
    /// @throws {PubkyError} A lock that has expired or was unlocked rejects with
    /// `RequestError` and status `412`; take a new one and read the file again.
    /// Otherwise as {@link SessionStorage.putText}.
    #[wasm_bindgen(js_name = "putTextLocked")]
    pub async fn put_text_locked(&self, lock: &StorageLock, body: &str) -> JsResult<()> {
        self.0
            .put_locked(&lock.inner(), body.as_bytes().to_vec())
            .await?;
        Ok(())
    }

    /// `DELETE` the path of a lock this client holds. The lock stays in place.
    ///
    /// @param {StorageLock} lock A lock this client holds.
    /// @returns {Promise<void>}
    /// @throws {PubkyError} A lock that has expired or was unlocked rejects with
    /// `RequestError` and status `412`; take a new one.
    /// Otherwise as {@link SessionStorage.delete}.
    #[wasm_bindgen(js_name = "deleteLocked")]
    pub async fn delete_locked(&self, lock: &StorageLock) -> JsResult<()> {
        self.0.delete_locked(&lock.inner()).await?;
        Ok(())
    }
}

/// Seconds as a `Duration`, rejecting what `Duration` cannot hold.
fn seconds(value: f64) -> JsResult<Duration> {
    Duration::try_from_secs_f64(value).map_err(|error| {
        PubkyError::new(
            PubkyErrorName::InvalidInput,
            format!("invalid timeoutSeconds: {error}"),
        )
    })
}
