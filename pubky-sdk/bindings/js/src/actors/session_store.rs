use super::browser_session::BrowserSessionCoordinator;
use pubky::GrantSessionCoordinator;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::{
    browser_grant_key_store::BrowserGrantKeyStore,
    grant_session::{decode_delegated_grant_state, encode_delegated_grant_state},
    session::Session,
};
use crate::js_error::{JsResult, PubkyError, PubkyErrorName, js_error_message};

const STORE_VERSION: &str = "pubky-session-v1";
const MODE_DELEGATED: &str = "delegated";
const MODE_LOCAL_SECRET: &str = "localSecret";

#[wasm_bindgen(inline_js = r#"
const PUBKY_SESSIONS_DB_NAME = "pubky-auth";
const PUBKY_SESSIONS_DB_VERSION = 1;
const PUBKY_SESSIONS_STORE_NAME = "storedSessions";
const PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME = "delegatedGrantKeys";

/** Assert that IndexedDB is available for browser session persistence. */
function requireIndexedDb() {
  if (!globalThis.indexedDB) {
    throw new Error("Pubky session persistence requires IndexedDB.");
  }
}

/** Create an operation-specific error while preserving the IndexedDB cause. 
 * Used for backwards compatability because old browsers don't support the cause property.
 */
function contextualSessionStoreError(message, cause) {
  const error = new Error(message, { cause });
  if (cause !== undefined && error.cause === undefined) {
    error.cause = cause;
  }
  return error;
}

/**
 * Open the IndexedDB database used for browser auth persistence.
 *
 * The database contains session records and delegated WebCrypto key handles so
 * both stores are created here even though single-store helpers use only one.
 */
function openSessionStoreDb() {
  requireIndexedDb();
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(PUBKY_SESSIONS_DB_NAME, PUBKY_SESSIONS_DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(PUBKY_SESSIONS_STORE_NAME)) {
        db.createObjectStore(PUBKY_SESSIONS_STORE_NAME, { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains(PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME)) {
        db.createObjectStore(PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME, { keyPath: "keyId" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Opening Pubky session store failed."));
  });
}

/**
 * Run an IndexedDB operation against the stored-session object store.
 *
 * The callback receives the object store and returns a request. This wrapper
 * resolves only after the transaction commits, not when the request succeeds.
 */
async function withSessionStore(mode, operation) {
  const db = await openSessionStoreDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(PUBKY_SESSIONS_STORE_NAME, mode);
      const store = tx.objectStore(PUBKY_SESSIONS_STORE_NAME);
      let result;
      try {
        const request = operation(store);
        request.onsuccess = () => {
          result = request.result;
        };
        request.onerror = () => reject(request.error ?? new Error("Pubky session store request failed."));
      } catch (error) {
        reject(error);
      }
      tx.onerror = () => reject(tx.error ?? new Error("Pubky session store transaction failed."));
      tx.onabort = () => reject(tx.error ?? new Error("Pubky session store transaction aborted."));
      tx.oncomplete = () => resolve(result);
    });
  } finally {
    db.close();
  }
}

/** Return whether browser session persistence can open its IndexedDB database. */
export async function __pubkySessionStoreIsAvailable() {
  if (!globalThis.indexedDB) return false;
  try {
    if (!globalThis.navigator?.locks) return false;
    const db = await openSessionStoreDb();
    db.close();
    return true;
  } catch (_error) {
    return false;
  }
}

/** Persist or replace a browser session record. */
export async function __pubkySessionStorePut(record, lease) {
  requireIndexedDb();
  try {
    const previous = await __pubkySessionStoreGet(record.id);
    if (previous?.sharedSession) record.sharedSession = previous.sharedSession;
    await withSessionStore("readwrite", (store) => {
      requireSessionLease(lease, true);
      return store.put(record);
    });
  } catch (error) {
    throw contextualSessionStoreError("Saving Pubky session failed.", error);
  }
}

/** Load a browser session record by id. */
export async function __pubkySessionStoreGet(id) {
  requireIndexedDb();
  try {
    return await withSessionStore("readonly", (store) => store.get(id));
  } catch (error) {
    throw contextualSessionStoreError("Reading Pubky session failed.", error);
  }
}

/** List all browser session records, returning an empty list if storage is unavailable. */
export async function __pubkySessionStoreList() {
  if (!globalThis.indexedDB) return [];
  try {
    return (await withSessionStore("readonly", (store) => store.getAll())) ?? [];
  } catch (_error) {
    return [];
  }
}

/** Clear saved sessions and their keys, or every key when clearing all auth state. */
async function clearSessionStore(allKeys = false) {
  requireIndexedDb();
  const db = await openSessionStoreDb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(
        [PUBKY_SESSIONS_STORE_NAME, PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME], "readwrite",
      );
      const sessions = tx.objectStore(PUBKY_SESSIONS_STORE_NAME);
      const keys = tx.objectStore(PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME);
      const records = sessions.getAll();
      records.onsuccess = () => {
        try {
          if (allKeys) keys.clear();
          else for (const record of records.result) {
            if (record.storageMode === "delegated") keys.delete(JSON.parse(record.credential).keyId);
          }
          sessions.clear();
        } catch (error) { tx.abort(); reject(error); }
      };
      tx.oncomplete = resolve;
      tx.onerror = tx.onabort = () => reject(tx.error ?? new Error("Clearing browser sessions failed."));
    });
  } finally { db.close(); }
}

const SESSION_STORE_LOCK = "pubky-session-store";
const sessionLeases = new Map();
let nextSessionLease = 0;
const sessionChannel = typeof indexedDB !== "undefined" && typeof BroadcastChannel === "function"
  ? new BroadcastChannel("pubky-session-store") : null;
function notifySessionChange(detail) {
  if (typeof globalThis.dispatchEvent === "function") {
    globalThis.dispatchEvent(new CustomEvent("pubky-session-changed", { detail }));
  }
}
if (sessionChannel) sessionChannel.onmessage = event => notifySessionChange(event.data);
function sessionChanged(id, action) {
  const detail = { id, action };
  notifySessionChange(detail);
  sessionChannel?.postMessage(detail);
}

export function __pubkySessionAcquire(id, homeserver, exclusive) {
  if (!globalThis.navigator?.locks) throw new Error("Browser sessions require Web Locks in a secure context.");
  const token = ++nextSessionLease;
  const abort = new AbortController();
  let release, ready, failed;
  const held = new Promise(resolve => { release = resolve; });
  const waiting = new Promise((resolve, reject) => { ready = resolve; failed = reject; });
  // Cancellation can drop the Rust future before it starts awaiting this promise.
  waiting.catch(() => {});
  const lease = { id, homeserver, exclusive, abort, release, waiting, active: false };
  sessionLeases.set(token, lease);
  navigator.locks.request(SESSION_STORE_LOCK, { mode: "shared", signal: abort.signal }, () =>
    navigator.locks.request(`pubky-shared-session:${homeserver}:${id}`, {
      mode: exclusive ? "exclusive" : "shared", signal: abort.signal,
    }, async () => {
      lease.active = true;
      ready();
      await held;
    })
  ).catch(failed);
  return token;
}
export function __pubkySessionWait(token) {
  return sessionLeases.get(token).waiting;
}
export function __pubkySessionRelease(token) {
  const lease = sessionLeases.get(token);
  if (!lease) return;
  lease.active = false;
  lease.abort.abort();
  lease.release();
  sessionLeases.delete(token);
}
function requireSessionLease(token, write = false) {
  const lease = sessionLeases.get(token);
  if (!lease?.active || (write && !lease.exclusive)) throw new Error("Browser session lock was released.");
  return lease;
}
export async function __pubkySharedSessionLoad(token) {
  const lease = requireSessionLease(token);
  const record = await __pubkySessionStoreGet(lease.id);
  if (record && record.homeserver !== lease.homeserver) throw new Error("Stored session homeserver changed.");
  return record?.sharedSession;
}
export async function __pubkySharedSessionStore(token, sharedSession) {
  const lease = requireSessionLease(token, true);
  const record = await __pubkySessionStoreGet(lease.id);
  if (!record || record.homeserver !== lease.homeserver) throw new Error("Browser session was removed or changed.");
  await withSessionStore("readwrite", store => {
    requireSessionLease(token, true);
    return store.put({ ...record, sharedSession });
  });
}
export async function __pubkySharedSessionRemove(token) {
  const lease = requireSessionLease(token, true);
  const record = await __pubkySessionStoreGet(lease.id);
  if (!record) return;
  const db = await openSessionStoreDb();
  try {
    requireSessionLease(token, true);
    await new Promise((resolve, reject) => {
      const tx = db.transaction([PUBKY_SESSIONS_STORE_NAME, PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME], "readwrite");
      tx.objectStore(PUBKY_SESSIONS_STORE_NAME).delete(lease.id);
      if (record.storageMode === "delegated") {
        const { keyId } = JSON.parse(record.credential);
        tx.objectStore(PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME).delete(keyId);
      }
      tx.oncomplete = resolve;
      tx.onerror = tx.onabort = () => reject(tx.error ?? new Error("Removing browser session failed."));
    });
  } finally { db.close(); }
  sessionChanged(lease.id, "removed");
}
export async function __pubkySessionStoreClear() {
  await navigator.locks.request(SESSION_STORE_LOCK, () => clearSessionStore());
  sessionChanged(null, "cleared");
}
export async function __pubkySessionStoreClearAll() {
  await navigator.locks.request(SESSION_STORE_LOCK, () => clearSessionStore(true));
  sessionChanged(null, "cleared");
}
"#)]
extern "C" {
    #[wasm_bindgen(catch, js_name = __pubkySessionAcquire)]
    pub(crate) fn js_session_acquire(
        id: &str,
        homeserver: &str,
        exclusive: bool,
    ) -> Result<u32, JsValue>;
    #[wasm_bindgen(js_name = __pubkySessionWait)]
    pub(crate) fn js_session_wait(token: u32) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkySessionRelease)]
    pub(crate) fn js_session_release(token: u32);
    #[wasm_bindgen(js_name = __pubkySharedSessionLoad)]
    pub(crate) fn js_shared_load(token: u32) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkySharedSessionStore)]
    pub(crate) fn js_shared_store(token: u32, state: JsValue) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkySharedSessionRemove)]
    pub(crate) fn js_shared_remove(token: u32) -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreIsAvailable)]
    fn js_store_is_available() -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStorePut)]
    fn js_store_put(record: JsValue, lease: u32) -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreGet)]
    fn js_store_get(id: String) -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreList)]
    fn js_store_list() -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreClear)]
    fn js_store_clear() -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreClearAll)]
    fn js_store_clear_all() -> js_sys::Promise;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredSessionRecord {
    version: String,
    id: String,
    storage_mode: String,
    credential: String,
    public_key: String,
    homeserver: String,
    grant_id: String,
    client_id: String,
    capabilities: Vec<String>,
    grant_expires_at: f64,
    created_at: f64,
}

/// Metadata for a session saved in the browser session store.
#[wasm_bindgen]
pub struct StoredSessionInfo(StoredSessionRecord);

#[wasm_bindgen]
impl StoredSessionInfo {
    /// Stable local identifier for this stored session.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.0.id.clone()
    }

    /// `delegated` for origin-bound WebCrypto sessions, `localSecret` for raw local PoP secret storage.
    #[wasm_bindgen(js_name = "storageMode", getter)]
    pub fn storage_mode(&self) -> String {
        self.0.storage_mode.clone()
    }

    /// User public key as z32.
    #[wasm_bindgen(js_name = "publicKey", getter)]
    pub fn public_key(&self) -> String {
        self.0.public_key.clone()
    }

    /// Homeserver public key as z32.
    #[wasm_bindgen(getter)]
    pub fn homeserver(&self) -> String {
        self.0.homeserver.clone()
    }

    /// Grant identifier backing this stored session.
    #[wasm_bindgen(js_name = "grantId", getter)]
    pub fn grant_id(&self) -> String {
        self.0.grant_id.clone()
    }

    /// Application/client identifier.
    #[wasm_bindgen(js_name = "clientId", getter)]
    pub fn client_id(&self) -> String {
        self.0.client_id.clone()
    }

    /// Authorized capabilities.
    #[wasm_bindgen(getter)]
    pub fn capabilities(&self) -> Vec<String> {
        self.0.capabilities.clone()
    }

    /// Underlying grant expiry timestamp, in Unix seconds.
    #[wasm_bindgen(js_name = "grantExpiresAt", getter)]
    pub fn grant_expires_at(&self) -> f64 {
        self.0.grant_expires_at
    }

    /// Local save timestamp, in Unix milliseconds.
    #[wasm_bindgen(js_name = "createdAt", getter)]
    pub fn created_at(&self) -> f64 {
        self.0.created_at
    }
}

/// Browser-backed durable store for completed grant sessions.
#[wasm_bindgen]
pub struct BrowserSessionStore(pub(crate) pubky::Pubky);

#[wasm_bindgen]
impl BrowserSessionStore {
    /// Whether IndexedDB and Web Locks are available.
    #[wasm_bindgen(js_name = "isAvailable")]
    pub async fn is_available(&self) -> JsResult<bool> {
        let value = JsFuture::from(js_store_is_available())
            .await
            .map_err(store_error)?;
        Ok(value.as_bool().unwrap_or(false))
    }

    /// Persist a completed grant session in IndexedDB.
    #[wasm_bindgen]
    pub async fn save(&self, session: &Session) -> JsResult<StoredSessionInfo> {
        let grant = session.0.as_grant().ok_or_else(|| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Only grant-backed sessions can be saved in BrowserSessionStore.",
            )
        })?;
        let session_info = grant.session_info().await;
        let grant_id = session_info.grant_id.to_string();
        let public_key = session_info.pubky.z32();

        let (storage_mode, credential) =
            if let Some(state) = grant.export_delegated_restore_state().await {
                (
                    MODE_DELEGATED.to_string(),
                    encode_delegated_grant_state(state)?,
                )
            } else {
                let secret = grant.export_local_secret().await.ok_or_else(|| {
                    PubkyError::new(
                        PubkyErrorName::ClientStateError,
                        "This grant session cannot export restorable local secret material.",
                    )
                })?;
                (MODE_LOCAL_SECRET.to_string(), secret)
            };

        let record = StoredSessionRecord {
            version: STORE_VERSION.to_string(),
            id: stored_session_id(&session_info),
            storage_mode,
            credential,
            public_key,
            homeserver: session_info.homeserver.z32(),
            grant_id,
            client_id: session_info.client_id.to_string(),
            capabilities: session_info
                .capabilities
                .iter()
                .map(ToString::to_string)
                .collect(),
            grant_expires_at: session_info.grant_expires_at as f64,
            created_at: js_sys::Date::now(),
        };

        let value = serde_wasm_bindgen::to_value(&record).map_err(|e| {
            PubkyError::new(
                PubkyErrorName::InternalError,
                format!("Failed to serialize stored session: {e}"),
            )
        })?;
        let coordinator = Arc::new(BrowserSessionCoordinator::new(
            &record.id,
            &record.homeserver,
        ));
        let lease = coordinator.acquire_browser(true).await?;
        JsFuture::from(js_store_put(value, lease.token))
            .await
            .map_err(store_error)?;
        grant.coordinate(coordinator, &lease).await?;
        Ok(StoredSessionInfo(record))
    }

    /// List all locally stored sessions for this origin.
    #[wasm_bindgen]
    pub async fn list(&self) -> JsResult<Vec<StoredSessionInfo>> {
        self.stored_records()
            .await
            .map(|records| records.into_iter().map(StoredSessionInfo).collect())
    }

    /// Restore a specific stored session by id.
    ///
    /// Shares one bearer with other tabs on this origin. Requires IndexedDB and
    /// Web Locks in a secure browser context.
    #[wasm_bindgen]
    pub async fn restore(&self, id: String) -> JsResult<Session> {
        let record = self.load_record(id.clone()).await?;
        let coordinator = Arc::new(BrowserSessionCoordinator::new(&id, &record.homeserver));
        let lease = coordinator.acquire(true).await?;
        let credential = match record.storage_mode.as_str() {
            MODE_DELEGATED => {
                let state = decode_delegated_grant_state(&record.credential)?;
                let stored_public_key =
                    BrowserGrantKeyStore::load_public_key(state.key_id.clone()).await?;
                if stored_public_key != state.client_pk {
                    return Err(PubkyError::new(
                        PubkyErrorName::ClientStateError,
                        "Delegated grant key public key does not match saved session.",
                    ));
                }
                let sign = BrowserGrantKeyStore::signer(state.key_id.clone());
                pubky::GrantCredential::from_shared_delegated_state(state, sign)?
            }
            MODE_LOCAL_SECRET => pubky::GrantCredential::from_shared_secret(&record.credential)?,
            _ => {
                return Err(PubkyError::new(
                    PubkyErrorName::ClientStateError,
                    "Unsupported stored session storage mode.",
                ));
            }
        };
        let session =
            pubky::PubkySession::from_grant_credential(self.0.client().clone(), credential);
        let grant = session.as_grant().expect("grant credential");
        let info = grant.session_info().await;
        if record.id != stored_session_id(&info) || record.homeserver != info.homeserver.z32() {
            return Err(PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Stored session identity does not match its grant.",
            ));
        }
        grant.coordinate(coordinator, lease.as_ref()).await?;
        let logout_pending = lease
            .load()
            .await?
            .is_some_and(|shared| shared.logout_pending);
        drop(lease);
        if logout_pending {
            session.signout().await.map_err(|(error, _)| error)?;
            return Err(PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Browser session was signed out.",
            ));
        }
        if session.revalidate().await?.is_none() {
            return Err(PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Browser session is no longer valid.",
            ));
        }
        Ok(Session(session))
    }

    /// Remove local stored session metadata and any SDK-owned delegated key for that record.
    #[wasm_bindgen]
    pub async fn remove(&self, id: String) -> JsResult<()> {
        let record = self.load_record(id.clone()).await?;
        let coordinator = BrowserSessionCoordinator::new(&id, &record.homeserver);
        coordinator.acquire(true).await?.remove().await?;

        Ok(())
    }

    /// Clear all local stored session records for this origin.
    ///
    /// Delegated keys referenced by those stored session records are removed.
    /// Delegated keys that only belong to pending grant flows are preserved.
    #[wasm_bindgen]
    pub async fn clear(&self) -> JsResult<()> {
        JsFuture::from(js_store_clear())
            .await
            .map_err(store_error)?;
        Ok(())
    }

    /// Clear all browser auth persistence owned by this SDK origin.
    ///
    /// This removes all stored session records and all browser-held delegated
    /// grant keys, including keys for pending delegated grant flows. Saved
    /// delegated flow state becomes unrestorable. This does not revoke remote
    /// grants. Browser-managed handles stop working when their saved record is removed.
    #[wasm_bindgen(js_name = "clearAll")]
    pub async fn clear_all(&self) -> JsResult<()> {
        JsFuture::from(js_store_clear_all())
            .await
            .map_err(store_error)?;
        Ok(())
    }
}

impl BrowserSessionStore {
    async fn stored_records(&self) -> JsResult<Vec<StoredSessionRecord>> {
        let value = JsFuture::from(js_store_list()).await.map_err(store_error)?;
        let records: Vec<StoredSessionRecord> =
            serde_wasm_bindgen::from_value(value).map_err(|e| {
                PubkyError::new(
                    PubkyErrorName::ClientStateError,
                    format!("Invalid stored session record: {e}"),
                )
            })?;
        records
            .into_iter()
            .map(validate_record)
            .map(|info| info.map(|info| info.0))
            .collect()
    }

    async fn load_record(&self, id: String) -> JsResult<StoredSessionRecord> {
        let value = JsFuture::from(js_store_get(id.clone()))
            .await
            .map_err(store_error)?;
        if value.is_undefined() {
            return Err(PubkyError::new(
                PubkyErrorName::ClientStateError,
                format!("Stored Pubky session not found: {id}"),
            ));
        }
        let record: StoredSessionRecord = serde_wasm_bindgen::from_value(value).map_err(|e| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                format!("Invalid stored session record: {e}"),
            )
        })?;
        validate_record(record).map(|info| info.0)
    }
}

/// Identifier of a stored session record: one per user and grant.
pub(crate) fn stored_session_id(
    info: &pubky_common::auth::grant_session_responses::GrantSessionInfo,
) -> String {
    format!("{}:{}", info.pubky.z32(), info.grant_id)
}

fn validate_record(record: StoredSessionRecord) -> JsResult<StoredSessionInfo> {
    if record.version != STORE_VERSION {
        return Err(PubkyError::new(
            PubkyErrorName::ClientStateError,
            "Unsupported stored session version.",
        ));
    }
    if record.storage_mode != MODE_DELEGATED && record.storage_mode != MODE_LOCAL_SECRET {
        return Err(PubkyError::new(
            PubkyErrorName::ClientStateError,
            "Unsupported stored session storage mode.",
        ));
    }
    Ok(StoredSessionInfo(record))
}

pub(crate) fn store_error(value: JsValue) -> PubkyError {
    PubkyError::new(
        PubkyErrorName::ClientStateError,
        js_error_message(&value, "Pubky session store operation failed."),
    )
}
