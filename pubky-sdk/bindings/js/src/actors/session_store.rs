use super::browser_session::BrowserSessionCoordinator;
use pubky::GrantSessionCoordinator;
use pubky_common::{auth::jws::GrantId, crypto::PublicKey};
use std::sync::Arc;

use js_sys::Reflect;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::{
    browser_grant_key_store::BrowserGrantKeyStore,
    encryption_keys::EncryptionKeys,
    grant_session::{decode_delegated_grant_state, encode_delegated_grant_state},
    session::Session,
};
use crate::js_error::{JsResult, PubkyError, PubkyErrorName};

const STORE_VERSION: &str = "pubky-session-v1";
const STORE_APPROVAL_VERSION: &str = "pubky-session-v2";

/// How a stored session retains its proof-of-possession signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum StorageMode {
    Delegated,
    LocalSecret,
}

impl StorageMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Delegated => "delegated",
            Self::LocalSecret => "localSecret",
        }
    }
}

#[wasm_bindgen(inline_js = r#"
const PUBKY_SESSIONS_DB_NAME = "pubky-auth";
const PUBKY_SESSIONS_DB_VERSION = 1;
const PUBKY_SESSIONS_STORE_NAME = "storedSessions";
const PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME = "delegatedGrantKeys";
const PUBKY_APPROVAL_SESSION_VERSION = "pubky-session-v2";

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
 * Run an IndexedDB operation across session records and browser keys.
 *
 * The callback receives the transaction and returns a request. This wrapper
 * resolves only after the transaction commits, not when the request succeeds.
 */
async function withSessionStores(mode, operation) {
  const db = await openSessionStoreDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(
        [PUBKY_SESSIONS_STORE_NAME, PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME], mode,
      );
      let result;
      try {
        const request = operation(tx);
        request.onsuccess = () => {
          result = request.result;
        };
        request.onerror = () => reject(request.error ?? new Error("Pubky session store request failed."));
      } catch (error) {
        tx.abort();
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
    if (previous?.version === PUBKY_APPROVAL_SESSION_VERSION && record.version !== previous.version) {
      throw new Error("Cannot replace a stored approval with an authentication-only record.");
    }
    const stored = { ...record };
    if (previous?.sharedSession) stored.sharedSession = previous.sharedSession;
    await withSessionStores("readwrite", tx => {
      const held = requireSessionLease(lease, true);
      if (held.id !== record.id || held.homeserver !== record.homeserver) {
        throw new Error("Session record does not match its browser lock.");
      }
      return tx.objectStore(PUBKY_SESSIONS_STORE_NAME).put(stored);
    });
  } catch (error) {
    throw contextualSessionStoreError("Saving Pubky session failed.", error);
  }
}

function sessionMetadata(record) {
  if (!record) return record;
  const { version, id, storageMode, publicKey, homeserver, grantId, clientId,
    capabilities, grantExpiresAt, createdAt } = record;
  return { version, id, storageMode, publicKey, homeserver, grantId, clientId,
    capabilities, grantExpiresAt, createdAt,
    hasStoredApproval: record.signedApproval !== undefined,
  };
}

export async function __pubkySessionStoreMetadata(id) {
  return sessionMetadata(await __pubkySessionStoreGet(id));
}

/** Load a browser session record by id. */
export async function __pubkySessionStoreGet(id) {
  requireIndexedDb();
  try {
    return await withSessionStores("readonly", tx =>
      tx.objectStore(PUBKY_SESSIONS_STORE_NAME).get(id),
    );
  } catch (error) {
    throw contextualSessionStoreError("Reading Pubky session failed.", error);
  }
}

/** List all browser session records, returning an empty list if storage is unavailable. */
export async function __pubkySessionStoreList() {
  if (!globalThis.indexedDB) return [];
  try {
    const records = await withSessionStores("readonly", tx =>
      tx.objectStore(PUBKY_SESSIONS_STORE_NAME).getAll(),
    );
    return records.map(sessionMetadata);
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
  await withSessionStores("readwrite", tx => {
    requireSessionLease(token, true);
    return tx.objectStore(PUBKY_SESSIONS_STORE_NAME).put({ ...record, sharedSession });
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

    #[wasm_bindgen(js_name = __pubkySessionStoreMetadata)]
    fn js_store_metadata(id: String) -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreList)]
    fn js_store_list() -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreClear)]
    fn js_store_clear() -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreClearAll)]
    fn js_store_clear_all() -> js_sys::Promise;
}

/// Public session details shared by stored records and metadata-only reads.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionMetadata {
    version: String,
    id: String,
    storage_mode: StorageMode,
    public_key: String,
    homeserver: String,
    grant_id: String,
    client_id: String,
    capabilities: Vec<String>,
    grant_expires_at: f64,
    created_at: f64,
}

/// Listing/removal projection that omits confidential restore material.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredSessionMetadata {
    #[serde(flatten)]
    metadata: SessionMetadata,
    #[serde(default)]
    has_stored_approval: bool,
}

/// Confidential restore material. V2 delegated records require the actual
/// signed approval; metadata's presence flag cannot substitute for its bytes.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredSessionRecord {
    #[serde(flatten)]
    metadata: SessionMetadata,
    credential: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signed_approval: Option<String>,
}

impl Drop for StoredSessionRecord {
    fn drop(&mut self) {
        use zeroize::Zeroize;

        // JS/IndexedDB retain their own copies; clear the Rust-owned secrets.
        self.credential.zeroize();
        self.signed_approval.zeroize();
    }
}

/// Metadata for a session saved in the browser session store.
#[wasm_bindgen]
pub struct StoredSessionInfo(SessionMetadata);

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
        self.0.storage_mode.as_str().to_owned()
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

    /// Persist a completed grant session and its optional signed approval.
    /// Confidential restore material is stored as plaintext in IndexedDB.
    /// Delegated signing keys remain non-extractable WebCrypto keys.
    /// Records are identified by user and grant ID. Reauthorizing the same
    /// client creates a separate record; use the returned ID to restore it.
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
                (StorageMode::Delegated, encode_delegated_grant_state(state)?)
            } else {
                let secret = grant.export_local_secret().await.ok_or_else(|| {
                    PubkyError::new(
                        PubkyErrorName::ClientStateError,
                        "This grant session cannot export restorable local secret material.",
                    )
                })?;
                (StorageMode::LocalSecret, secret)
            };

        let metadata = SessionMetadata {
            version: if grant.encryption_keys().is_some() {
                STORE_APPROVAL_VERSION
            } else {
                STORE_VERSION
            }
            .to_string(),
            id: format!("{public_key}:{grant_id}"),
            storage_mode,
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
        let record = StoredSessionRecord {
            signed_approval: match metadata.storage_mode {
                StorageMode::Delegated => grant.signed_approval().map(str::to_owned),
                // Local V2 tokens already include the signed approval.
                StorageMode::LocalSecret => None,
            },
            metadata,
            credential,
        };

        // Flattened metadata must remain a plain JS object for IndexedDB readers.
        let value = record
            .serialize(&serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true))
            .map_err(|e| {
                PubkyError::new(
                    PubkyErrorName::InternalError,
                    format!("Failed to serialize stored session: {e}"),
                )
            })?;
        let coordinator = Arc::new(BrowserSessionCoordinator::new(
            &record.metadata.id,
            &record.metadata.homeserver,
        ));
        let lease = coordinator.acquire_browser(true).await?;
        JsFuture::from(js_store_put(value, lease.token))
            .await
            .map_err(store_error)?;
        grant.coordinate(coordinator, &lease).await?;
        Ok(StoredSessionInfo(record.metadata.clone()))
    }

    /// List all locally stored sessions for this origin.
    #[wasm_bindgen]
    pub async fn list(&self) -> JsResult<Vec<StoredSessionInfo>> {
        self.stored_metadata()
            .await
            .map(|records| records.into_iter().map(StoredSessionInfo).collect())
    }

    /// Recover a stored session's encryption keys without network access.
    /// Verifies the signed approval, exact grant binding, and requested session
    /// identity. Works after grant expiry/revocation and without the delegated
    /// WebCrypto signing key.
    /// Restore material is stored as plaintext in IndexedDB.
    /// Bare-grant records return undefined; signed approvals without `e` scopes
    /// return an empty bundle. Creates no session.
    #[wasm_bindgen(js_name = "restoreEncryptionKeys")]
    pub async fn restore_encryption_keys(&self, id: String) -> JsResult<Option<EncryptionKeys>> {
        let record = self.load_record(&id).await?;
        let recovered = match record.metadata.storage_mode {
            StorageMode::Delegated => {
                let state = decode_delegated_grant_state(&record.credential)?;
                pubky::GrantCredential::restore_encryption_keys_from_approval(
                    &state.grant_jws,
                    record.signed_approval.as_deref(),
                )
            }
            StorageMode::LocalSecret => {
                pubky::GrantCredential::restore_encryption_keys(&record.credential)
            }
        }?;
        let Some((claims, keys)) = recovered else {
            return Ok(None);
        };
        record
            .metadata
            .validate_grant_identity(&id, &claims.iss, &claims.jti)?;
        Ok(Some(EncryptionKeys(keys)))
    }

    /// Restore a specific stored session by id.
    ///
    /// Shares one bearer with other tabs on this origin. Requires IndexedDB and
    /// Web Locks in a secure browser context.
    #[wasm_bindgen]
    pub async fn restore(&self, id: String) -> JsResult<Session> {
        let record = self.load_record(&id).await?;
        let coordinator = Arc::new(BrowserSessionCoordinator::new(
            &id,
            &record.metadata.homeserver,
        ));
        let lease = coordinator.acquire(true).await?;
        let credential = match record.metadata.storage_mode {
            StorageMode::Delegated => {
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
                pubky::GrantCredential::from_shared_delegated_state(
                    state,
                    sign,
                    record.signed_approval.as_deref(),
                )?
            }
            StorageMode::LocalSecret => {
                pubky::GrantCredential::from_shared_secret(&record.credential)?
            }
        };
        let session =
            pubky::PubkySession::from_grant_credential(self.0.client().clone(), credential);
        let grant = session.as_grant().expect("grant credential");
        let info = grant.session_info().await;
        record
            .metadata
            .validate_grant_identity(&id, &info.pubky, &info.grant_id)?;
        if record.metadata.homeserver != info.homeserver.z32() {
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
        let record = self.load_metadata(id.clone()).await?;
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
    async fn stored_metadata(&self) -> JsResult<Vec<SessionMetadata>> {
        let value = JsFuture::from(js_store_list()).await.map_err(store_error)?;
        let records: Vec<StoredSessionMetadata> =
            serde_wasm_bindgen::from_value(value).map_err(|_| invalid_record())?;
        records.into_iter().map(validate_stored_metadata).collect()
    }

    async fn load_record(&self, id: &str) -> JsResult<StoredSessionRecord> {
        let value = JsFuture::from(js_store_get(id.to_owned()))
            .await
            .map_err(store_error)?;
        let record = decode_store_value(value, id)?;
        validate_record(record)
    }

    async fn load_metadata(&self, id: String) -> JsResult<SessionMetadata> {
        let value = JsFuture::from(js_store_metadata(id.clone()))
            .await
            .map_err(store_error)?;
        let metadata = decode_store_value(value, &id)?;
        validate_stored_metadata(metadata)
    }
}

fn invalid_record() -> PubkyError {
    PubkyError::new(
        PubkyErrorName::ClientStateError,
        "Invalid stored session record.",
    )
}

fn decode_store_value<T: serde::de::DeserializeOwned>(value: JsValue, id: &str) -> JsResult<T> {
    if value.is_undefined() {
        return Err(PubkyError::new(
            PubkyErrorName::ClientStateError,
            format!("Stored Pubky session not found: {id}"),
        ));
    }
    serde_wasm_bindgen::from_value(value).map_err(|_| invalid_record())
}

impl SessionMetadata {
    fn validate_grant_identity(
        &self,
        requested_id: &str,
        public_key: &PublicKey,
        grant_id: &GrantId,
    ) -> JsResult<()> {
        let grant_session_id = format!("{}:{grant_id}", public_key.z32());
        if requested_id != grant_session_id || self.id != grant_session_id {
            return Err(PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Stored session identity does not match its grant.",
            ));
        }
        Ok(())
    }

    fn validate(&self) -> JsResult<()> {
        if self.version != STORE_VERSION && self.version != STORE_APPROVAL_VERSION {
            return Err(PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Unsupported stored session version.",
            ));
        }
        Ok(())
    }

    fn requires_separate_approval(&self) -> bool {
        self.version == STORE_APPROVAL_VERSION && self.storage_mode == StorageMode::Delegated
    }
}

fn missing_approval() -> PubkyError {
    PubkyError::new(
        PubkyErrorName::ClientStateError,
        "Stored session is missing its signed approval.",
    )
}

fn validate_stored_metadata(record: StoredSessionMetadata) -> JsResult<SessionMetadata> {
    record.metadata.validate()?;
    if record.metadata.requires_separate_approval() && !record.has_stored_approval {
        return Err(missing_approval());
    }
    Ok(record.metadata)
}

fn validate_record(record: StoredSessionRecord) -> JsResult<StoredSessionRecord> {
    record.metadata.validate()?;
    if record.metadata.requires_separate_approval() && record.signed_approval.is_none() {
        return Err(missing_approval());
    }
    Ok(record)
}

pub(crate) fn store_error(value: JsValue) -> PubkyError {
    PubkyError::new(PubkyErrorName::ClientStateError, js_error_message(value))
}

fn js_error_message(value: JsValue) -> String {
    value
        .as_string()
        .or_else(|| {
            Reflect::get(&value, &JsValue::from_str("message"))
                .ok()
                .and_then(|value| value.as_string())
        })
        .unwrap_or_else(|| "Pubky session store operation failed.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen(inline_js = r#"
export async function inspectApprovalStore(id, action) {
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open("pubky-auth", 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(["storedSessions", "delegatedGrantKeys"], "readwrite");
      const sessions = tx.objectStore("storedSessions");
      const keys = tx.objectStore("delegatedGrantKeys");
      const record = sessions.get(id);
      const key = keys.get("test-pop");
      record.onsuccess = () => {
        if (action === "delete-pop") keys.delete("test-pop");
      };
      tx.oncomplete = () => resolve({ record: record.result, key: key.result });
      tx.onerror = tx.onabort = () => reject(tx.error);
    });
  } finally { db.close(); }
}
"#)]
    extern "C" {
        #[wasm_bindgen(js_name = inspectApprovalStore)]
        fn inspect_store(id: &str, action: &str) -> js_sys::Promise;
    }

    fn field(value: &JsValue, name: &str) -> JsValue {
        Reflect::get(value, &JsValue::from_str(name)).unwrap()
    }

    async fn inspect(id: &str, action: &str) -> JsValue {
        JsFuture::from(inspect_store(id, action)).await.unwrap()
    }

    #[wasm_bindgen_test]
    fn metadata_presence_does_not_replace_restore_material() {
        let value = js_sys::JSON::parse(
            r#"{"version":"pubky-session-v2","id":"test","storageMode":"delegated","credential":"saved-grant","homeserver":"home","publicKey":"user","grantId":"grant","clientId":"client","capabilities":[],"grantExpiresAt":0,"createdAt":0,"hasStoredApproval":true}"#,
        )
        .unwrap();
        let metadata: StoredSessionMetadata = decode_store_value(value.clone(), "test").unwrap();
        assert!(validate_stored_metadata(metadata).is_ok());
        let record: StoredSessionRecord = decode_store_value(value.clone(), "test").unwrap();
        assert!(validate_record(record).is_err());

        // Neither legacy delegated records nor local tokens need a separate approval.
        for (version, mode) in [
            (STORE_VERSION, StorageMode::Delegated),
            (STORE_APPROVAL_VERSION, StorageMode::LocalSecret),
        ] {
            Reflect::set(&value, &"version".into(), &version.into()).unwrap();
            Reflect::set(&value, &"storageMode".into(), &mode.as_str().into()).unwrap();
            let record: StoredSessionRecord = decode_store_value(value.clone(), "test").unwrap();
            assert_eq!(record.metadata.storage_mode, mode);
            assert_eq!(
                StoredSessionInfo(record.metadata.clone()).storage_mode(),
                mode.as_str()
            );
            let serialized = serde_wasm_bindgen::to_value(&mode).unwrap();
            assert_eq!(serialized.as_string().unwrap(), mode.as_str());
            assert!(validate_record(record).is_ok());
        }

        // Unknown modes are rejected before restore dispatch.
        Reflect::set(&value, &"storageMode".into(), &"unsupported".into()).unwrap();
        assert!(decode_store_value::<StoredSessionRecord>(value.clone(), "test").is_err());
        assert!(decode_store_value::<StoredSessionMetadata>(value, "test").is_err());
    }

    #[wasm_bindgen_test]
    fn records_preserve_the_flat_browser_storage_format() {
        let original = js_sys::JSON::parse(
            r#"{"version":"pubky-session-v2","id":"test","storageMode":"delegated","credential":"saved-grant","homeserver":"home","publicKey":"user","grantId":"grant","clientId":"client","capabilities":["/pub/chat/:r"],"grantExpiresAt":123,"createdAt":456,"signedApproval":"signed-approval"}"#,
        )
        .unwrap();
        let record = decode_store_value(original.clone(), "test").unwrap();
        let record = validate_record(record).unwrap();
        let serialized = record
            .serialize(&serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true))
            .unwrap();
        assert!(field(&serialized, "metadata").is_undefined());
        assert!(field(&serialized, "hasStoredApproval").is_undefined());
        for key in js_sys::Object::keys(&js_sys::Object::from(original.clone())).iter() {
            let name = key.as_string().unwrap();
            assert_eq!(
                js_sys::JSON::stringify(&field(&serialized, &name)).unwrap(),
                js_sys::JSON::stringify(&field(&original, &name)).unwrap(),
                "{name}",
            );
        }
    }

    #[wasm_bindgen_test]
    async fn stored_approvals_survive_bearer_updates_and_signing_key_removal() {
        for mode in [StorageMode::Delegated, StorageMode::LocalSecret] {
            let id = format!("approval-storage-{}", mode.as_str());
            let record = js_sys::JSON::parse(
                r#"{"version":"pubky-session-v2","id":"placeholder","storageMode":"delegated","credential":"{\"keyId\":\"test-pop\"}","homeserver":"test-home","publicKey":"test-user","grantId":"test-grant","clientId":"test-client","capabilities":[],"grantExpiresAt":0,"createdAt":0}"#,
            )
            .unwrap();
            Reflect::set(&record, &"id".into(), &id.clone().into()).unwrap();
            Reflect::set(&record, &"storageMode".into(), &mode.as_str().into()).unwrap();
            let material_field = if mode == StorageMode::Delegated {
                "signedApproval"
            } else {
                "credential"
            };
            Reflect::set(
                &record,
                &material_field.into(),
                &"confidential-approval".into(),
            )
            .unwrap();
            let lease = js_session_acquire(&id, "test-home", true).unwrap();
            JsFuture::from(js_session_wait(lease)).await.unwrap();
            JsFuture::from(js_store_put(record.clone(), lease))
                .await
                .unwrap();

            let saved = inspect(&id, "read").await;
            assert!(field(&saved, "key").is_undefined());
            assert_eq!(
                field(&field(&saved, "record"), material_field),
                JsValue::from_str("confidential-approval")
            );
            inspect(&id, "delete-pop").await;
            let loaded = JsFuture::from(js_store_get(id.clone())).await.unwrap();
            assert_eq!(
                field(&loaded, material_field),
                JsValue::from_str("confidential-approval")
            );

            let metadata = JsFuture::from(js_store_list()).await.unwrap();
            for entry in js_sys::Array::from(&metadata).iter() {
                assert!(field(&entry, "signedApproval").is_undefined());
                assert!(field(&entry, "credential").is_undefined());
                assert!(field(&entry, "sharedSession").is_undefined());
            }
            let shared = js_sys::JSON::parse(r#"{"bearer":"test-bearer"}"#).unwrap();
            JsFuture::from(js_shared_store(lease, shared))
                .await
                .unwrap();
            assert_eq!(
                field(
                    &JsFuture::from(js_store_get(id.clone())).await.unwrap(),
                    material_field
                ),
                JsValue::from_str("confidential-approval")
            );

            let downgraded = js_sys::Object::assign(
                &js_sys::Object::new(),
                &js_sys::Object::from(record.clone()),
            );
            Reflect::set(&downgraded, &"version".into(), &STORE_VERSION.into()).unwrap();
            assert!(
                JsFuture::from(js_store_put(downgraded.into(), lease))
                    .await
                    .is_err()
            );
            assert!(
                JsFuture::from(js_store_put(record.clone(), 0))
                    .await
                    .is_err()
            );

            JsFuture::from(js_store_put(record.clone(), lease))
                .await
                .unwrap();
            let replaced = JsFuture::from(js_store_get(id.clone())).await.unwrap();
            assert_eq!(
                field(&replaced, material_field),
                JsValue::from_str("confidential-approval")
            );
            assert_eq!(
                field(&field(&replaced, "sharedSession"), "bearer"),
                JsValue::from_str("test-bearer")
            );
            JsFuture::from(js_shared_remove(lease)).await.unwrap();
            assert!(field(&inspect(&id, "read").await, "record").is_undefined());
            JsFuture::from(js_store_put(record, lease)).await.unwrap();
            js_session_release(lease);
            JsFuture::from(js_store_clear()).await.unwrap();
            assert!(field(&inspect(&id, "read").await, "record").is_undefined());
        }
    }
}
