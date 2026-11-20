//! IndexedDB operations and browser locks.

use js_sys::Reflect;
use wasm_bindgen::prelude::*;

use crate::js_error::{PubkyError, PubkyErrorName};

#[wasm_bindgen(inline_js = r#"
const PUBKY_SESSIONS_DB_NAME = "pubky-auth";
// Version 2 adds `redirectFlows`. Keep the version and stores in sync with
// `openGrantKeyDb` in browser_grant_key_store.rs: both open this database.
const PUBKY_SESSIONS_DB_VERSION = 2;
const PUBKY_SESSIONS_STORE_NAME = "storedSessions";
const PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME = "delegatedGrantKeys";
const PUBKY_REDIRECT_FLOWS_STORE_NAME = "redirectFlows";
const PUBKY_CHILD_SESSION_VERSION = "pubky-session-v3";
const PUBKY_DB_BLOCKED_TIMEOUT_MS = 10000;

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

/** Create any missing store. Upgrades never touch existing records. */
function createPubkyAuthStores(db) {
  if (!db.objectStoreNames.contains(PUBKY_SESSIONS_STORE_NAME)) {
    db.createObjectStore(PUBKY_SESSIONS_STORE_NAME, { keyPath: "id" });
  }
  if (!db.objectStoreNames.contains(PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME)) {
    db.createObjectStore(PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME, { keyPath: "keyId" });
  }
  if (!db.objectStoreNames.contains(PUBKY_REDIRECT_FLOWS_STORE_NAME)) {
    db.createObjectStore(PUBKY_REDIRECT_FLOWS_STORE_NAME, { keyPath: "callbackUrl" });
  }
}

// Preserve existing records on upgrade; fail if an older tab blocks it for 10 seconds.
function openSessionStoreDb() {
  requireIndexedDb();
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(PUBKY_SESSIONS_DB_NAME, PUBKY_SESSIONS_DB_VERSION);
    let settled = false;
    let blocked;
    request.onupgradeneeded = () => createPubkyAuthStores(request.result);
    request.onblocked = () => {
      if (blocked === undefined) blocked = setTimeout(() => {
        if (settled) return;
        settled = true;
        reject(new Error(
          "Another tab of this site is using an older Pubky SDK. Reload or close it to finish the browser storage upgrade.",
        ));
      }, PUBKY_DB_BLOCKED_TIMEOUT_MS);
    };
    request.onsuccess = () => {
      clearTimeout(blocked);
      const db = request.result;
      if (settled) {
        db.close();
        return;
      }
      settled = true;
      db.onversionchange = () => db.close();
      resolve(db);
    };
    request.onerror = () => {
      clearTimeout(blocked);
      if (settled) return;
      settled = true;
      reject(request.error ?? new Error("Opening Pubky session store failed."));
    };
  });
}

// Resolve with the optional request's result after the transaction commits.
async function withStores(storeNames, mode, operation) {
  const db = await openSessionStoreDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(storeNames, mode);
      let result;
      try {
        const request = operation(tx);
        if (request) {
          request.onsuccess = () => {
            result = request.result;
          };
          request.onerror = () => reject(request.error ?? new Error("Pubky session store request failed."));
        }
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

// Session changes may also invalidate redirect requests and their keys.
function withSessionStores(mode, operation) {
  return withStores(
    [PUBKY_SESSIONS_STORE_NAME, PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME, PUBKY_REDIRECT_FLOWS_STORE_NAME], mode, operation,
  );
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

// Reject stale saves after sign-out/removal and preserve shared bearer state.
export async function __pubkySessionStorePut(record, lease, requireExisting) {
  requireIndexedDb();
  try {
    const previous = await __pubkySessionStoreGet(record.id);
    if (previous && previous.version !== record.version
      && previous.version !== "pubky-session-v1") {
      throw new Error("Cannot replace a stored approval with an authentication-only record.");
    }
    if (previous?.logoutPending) {
      throw new Error("Browser session is being signed out.");
    }
    if (!previous && requireExisting) {
      throw new Error("Browser session was removed or signed out.");
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
    logoutPending: record.logoutPending === true,
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

// Invalidate the callback in the same transaction that removes its session.
// A possibly exchanged child keeps only public material for proof-based logout.
function cancelStoredRedirect(tx, flow, revoke) {
  if (!flow || !["awaitingCallback", "exchangePending"].includes(flow.status)) return;
  const { authorizationUrl, keyId, clientPublicKey, approvalKeySecret,
    signedApproval, logoutRecord, ...finished } = flow;
  if (revoke && logoutRecord) {
    tx.objectStore(PUBKY_SESSIONS_STORE_NAME).put(logoutRecord);
    finished.sessionId = logoutRecord.id;
  } else if (keyId) {
    tx.objectStore(PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME).delete(keyId);
  }
  tx.objectStore(PUBKY_REDIRECT_FLOWS_STORE_NAME).put({
    ...finished, status: "cancelled", finishedAt: Date.now() / 1000,
  });
}

function cancelSessionRedirect(tx, record, revoke) {
  if (record.version !== PUBKY_CHILD_SESSION_VERSION) return;
  const request = tx.objectStore(PUBKY_REDIRECT_FLOWS_STORE_NAME).get(record.clientId);
  request.onsuccess = () => cancelStoredRedirect(tx, request.result, revoke);
}

async function clearSessionStore(keepKeyIds) {
  await withSessionStores("readwrite", tx => {
    const sessions = tx.objectStore(PUBKY_SESSIONS_STORE_NAME);
    const keys = tx.objectStore(PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME);
    const flows = tx.objectStore(PUBKY_REDIRECT_FLOWS_STORE_NAME);
    const records = sessions.getAll();
    records.onsuccess = () => {
      for (const record of records.result) {
        if (record.storageMode === "delegated") keys.delete(JSON.parse(record.credential).keyId);
      }
    };
    const pending = flows.getAll();
    pending.onsuccess = () => {
      for (const flow of pending.result) if (flow.keyId) keys.delete(flow.keyId);
    };
    if (keepKeyIds) {
      const stored = keys.getAllKeys();
      stored.onsuccess = () => {
        for (const keyId of stored.result) if (!keepKeyIds.includes(keyId)) keys.delete(keyId);
      };
    }
    sessions.clear();
    flows.clear();
  });
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

/** Queue a Web Lock request and return a token that `wait` and `release` use. */
function acquireLock(leases, token, lease, request) {
  const abort = new AbortController();
  let release, ready, failed;
  const held = new Promise(resolve => { release = resolve; });
  const waiting = new Promise((resolve, reject) => { ready = resolve; failed = reject; });
  // Cancellation can drop the Rust future before it starts awaiting this promise.
  waiting.catch(() => {});
  Object.assign(lease, { abort, release, waiting, active: false });
  leases.set(token, lease);
  request(abort.signal, async () => {
    lease.active = true;
    ready();
    await held;
  }).catch(failed);
  return token;
}
function releaseLock(leases, token) {
  const lease = leases.get(token);
  if (!lease) return;
  lease.active = false;
  lease.abort.abort();
  lease.release();
  leases.delete(token);
}

export function __pubkySessionAcquire(id, homeserver, exclusive) {
  if (!globalThis.navigator?.locks) throw new Error("Browser sessions require Web Locks in a secure context.");
  return acquireLock(sessionLeases, ++nextSessionLease, { id, homeserver, exclusive },
    (signal, hold) => navigator.locks.request(SESSION_STORE_LOCK, { mode: "shared", signal }, () =>
      navigator.locks.request(`pubky-shared-session:${homeserver}:${id}`, {
        mode: exclusive ? "exclusive" : "shared", signal,
      }, hold)));
}
export function __pubkyParentStoreAcquire(id) {
  if (!globalThis.navigator?.locks) throw new Error("The parent grant store requires Web Locks in a secure context.");
  const lease = {};
  const token = acquireLock(sessionLeases, ++nextSessionLease, lease, (signal, hold) =>
    navigator.locks.request(`pubky-parent-grant:${id}`, { signal }, hold));
  const timeout = setTimeout(() => lease.abort.abort(new Error("Waiting for the parent grant lock timed out.")), 10_000);
  const clear = () => clearTimeout(timeout);
  lease.waiting.then(clear, clear);
  return token;
}
export function __pubkySessionWait(token) {
  return sessionLeases.get(token).waiting;
}
export function __pubkySessionRelease(token) {
  releaseLock(sessionLeases, token);
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
// Sign-out deletes child keys and invalidates pending callbacks atomically.
export async function __pubkySharedSessionStore(token, sharedSession) {
  const lease = requireSessionLease(token, true);
  const record = await __pubkySessionStoreGet(lease.id);
  if (!record || record.homeserver !== lease.homeserver) throw new Error("Browser session was removed or changed.");
  let next = { ...record, sharedSession };
  // `sharedSession` is serialized from Rust, so its fields are snake_case.
  if (record.version === PUBKY_CHILD_SESSION_VERSION && sharedSession.logout_pending) {
    const { signedApproval: _deleted, ...logoutOnly } = next;
    next = { ...logoutOnly, logoutPending: true,
      sharedSession: { ...sharedSession, response: { ...sharedSession.response, token: "" } },
    };
  }
  await withSessionStores("readwrite", tx => {
    requireSessionLease(token, true);
    if (next.logoutPending && !record.logoutPending) cancelSessionRedirect(tx, record, true);
    return tx.objectStore(PUBKY_SESSIONS_STORE_NAME).put(next);
  });
}
export async function __pubkySharedSessionRemove(token) {
  const lease = requireSessionLease(token, true);
  const record = await __pubkySessionStoreGet(lease.id);
  if (!record) return;
  await withSessionStores("readwrite", tx => {
    requireSessionLease(token, true);
    if (!record.logoutPending) cancelSessionRedirect(tx, record, false);
    tx.objectStore(PUBKY_SESSIONS_STORE_NAME).delete(lease.id);
    if (record.storageMode === "delegated") {
      tx.objectStore(PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME).delete(JSON.parse(record.credential).keyId);
    }
  });
  sessionChanged(lease.id, "removed");
}
export async function __pubkySessionStoreClear() {
  await navigator.locks.request(SESSION_STORE_LOCK, () => clearSessionStore());
  sessionChanged(null, "cleared");
}
export async function __pubkySessionStoreClearAll(keepKeyIds) {
  await navigator.locks.request(SESSION_STORE_LOCK, () => clearSessionStore(keepKeyIds));
  sessionChanged(null, "cleared");
}

// --- Pending redirect sign-ins, one per callback URL ---

const redirectLeases = new Map();
let nextRedirectLease = 0;

/** Serialize callback processing with an exclusive Web Lock. */
export function __pubkyRedirectAcquire(callbackUrl) {
  if (!globalThis.navigator?.locks) throw new Error("Redirect sign-in requires Web Locks in a secure context.");
  return acquireLock(redirectLeases, ++nextRedirectLease, { callbackUrl },
    (signal, hold) => navigator.locks.request(`pubky-redirect-flow:${callbackUrl}`, { signal }, hold));
}
export function __pubkyRedirectWait(token) {
  return redirectLeases.get(token).waiting;
}
export function __pubkyRedirectRelease(token) {
  releaseLock(redirectLeases, token);
}
function requireRedirectLease(token, callbackUrl) {
  const lease = redirectLeases.get(token);
  if (!lease?.active || lease.callbackUrl !== callbackUrl) {
    throw new Error("Redirect sign-in lock was released.");
  }
}

export async function __pubkyRedirectGet(callbackUrl) {
  requireIndexedDb();
  try {
    return await withStores(PUBKY_REDIRECT_FLOWS_STORE_NAME, "readonly", tx =>
      tx.objectStore(PUBKY_REDIRECT_FLOWS_STORE_NAME).get(callbackUrl));
  } catch (error) {
    throw contextualSessionStoreError("Reading the pending redirect sign-in failed.", error);
  }
}

/** Whether the stored flow is the one the caller read: none, or the same status and state. */
function sameFlow(current, expected) {
  if (!expected) return current === undefined;
  return current?.status === expected.status && current?.state === expected.state;
}

// Compare and replace: concurrent sign-out or local deletion must win.
export async function __pubkyRedirectTransition(token, callbackUrl, expected, next, deleteKeyId) {
  requireRedirectLease(token, callbackUrl);
  let applied = false;
  await withStores(
    [PUBKY_REDIRECT_FLOWS_STORE_NAME, PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME], "readwrite", tx => {
      const flows = tx.objectStore(PUBKY_REDIRECT_FLOWS_STORE_NAME);
      const current = flows.get(callbackUrl);
      current.onsuccess = () => {
        if (!sameFlow(current.result, expected)) return;
        const keys = tx.objectStore(PUBKY_SESSIONS_DELEGATED_KEYS_STORE_NAME);
        const apply = () => {
          applied = true;
          if (next) flows.put(next); else flows.delete(callbackUrl);
          if (deleteKeyId) keys.delete(deleteKeyId);
        };
        if (next?.status === "awaitingCallback") {
          const key = keys.get(next.keyId);
          key.onsuccess = () => { if (key.result) apply(); };
        } else apply();
      };
    });
  return applied;
}

// Save the session, bearer and completed flow in one transaction under both locks.
export async function __pubkyRedirectCommit(token, callbackUrl, expected, next, sessionRecord, sessionLease) {
  requireRedirectLease(token, callbackUrl);
  const held = requireSessionLease(sessionLease, true);
  if (held.id !== sessionRecord.id || held.homeserver !== sessionRecord.homeserver) {
    throw new Error("Session record does not match its browser lock.");
  }
  let applied = false;
  await withStores(
    [PUBKY_REDIRECT_FLOWS_STORE_NAME, PUBKY_SESSIONS_STORE_NAME], "readwrite", tx => {
      const flows = tx.objectStore(PUBKY_REDIRECT_FLOWS_STORE_NAME);
      const current = flows.get(callbackUrl);
      current.onsuccess = () => {
        if (!sameFlow(current.result, expected)) return;
        applied = true;
        flows.put(next);
        tx.objectStore(PUBKY_SESSIONS_STORE_NAME).put(sessionRecord);
      };
    });
  return applied;
}

/**
 * Read the callback page's URL and remove its fragment before anything else
 * can read it. Returns the URL as it was.
 */
export function __pubkyRedirectCaptureLocation() {
  const location = globalThis.location;
  if (!location) throw new Error("Redirect sign-in requires a browser page.");
  const href = location.href;
  if (location.hash || href.includes('#')) {
    globalThis.history?.replaceState(globalThis.history.state, "", href.split('#')[0]);
  }
  return href;
}

/** The page's origin, or undefined outside a browser page. */
export function __pubkyRedirectOrigin() {
  return globalThis.location?.origin;
}
"#)]
extern "C" {
    #[wasm_bindgen(catch, js_name = __pubkySessionAcquire)]
    pub(crate) fn js_session_acquire(
        id: &str,
        homeserver: &str,
        exclusive: bool,
    ) -> Result<u32, JsValue>;
    #[wasm_bindgen(catch, js_name = __pubkyParentStoreAcquire)]
    pub(crate) fn js_parent_store_acquire(id: &str) -> Result<u32, JsValue>;
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
    pub(super) fn js_store_is_available() -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStorePut)]
    pub(super) fn js_store_put(
        record: JsValue,
        lease: u32,
        require_existing: bool,
    ) -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreGet)]
    pub(super) fn js_store_get(id: String) -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreMetadata)]
    pub(super) fn js_store_metadata(id: String) -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreList)]
    pub(super) fn js_store_list() -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreClear)]
    pub(super) fn js_store_clear() -> js_sys::Promise;

    #[wasm_bindgen(js_name = __pubkySessionStoreClearAll)]
    pub(super) fn js_store_clear_all(keep_key_ids: JsValue) -> js_sys::Promise;

    #[wasm_bindgen(catch, js_name = __pubkyRedirectAcquire)]
    pub(crate) fn js_redirect_acquire(callback_url: &str) -> Result<u32, JsValue>;
    #[wasm_bindgen(js_name = __pubkyRedirectWait)]
    pub(crate) fn js_redirect_wait(token: u32) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyRedirectRelease)]
    pub(crate) fn js_redirect_release(token: u32);
    #[wasm_bindgen(js_name = __pubkyRedirectGet)]
    pub(crate) fn js_redirect_get(callback_url: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyRedirectTransition)]
    pub(crate) fn js_redirect_transition(
        token: u32,
        callback_url: &str,
        expected: JsValue,
        next: JsValue,
        delete_key_id: Option<String>,
    ) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyRedirectCommit)]
    pub(crate) fn js_redirect_commit(
        token: u32,
        callback_url: &str,
        expected: JsValue,
        next: JsValue,
        session_record: JsValue,
        session_lease: u32,
    ) -> js_sys::Promise;
    #[wasm_bindgen(catch, js_name = __pubkyRedirectCaptureLocation)]
    pub(crate) fn js_redirect_capture_location() -> Result<String, JsValue>;
    #[wasm_bindgen(js_name = __pubkyRedirectOrigin)]
    pub(crate) fn js_redirect_origin() -> Option<String>;
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
