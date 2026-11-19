//! Browser bindings for parent grants.
//!
//! Parent records use their own database, so the session database's schema doesn't
//! change. Signing keys stay non-extractable WebCrypto keys in the existing delegated
//! key store, and `BrowserSessionStore.clearAll()` leaves the keys of saved parents
//! in place.
//! Each saved approval is encrypted with its own non-extractable WebCrypto
//! key, stored separately from the parent record.

use std::str::FromStr;

use pubky::{ParentGrantCredential, errors::RedirectDenial};
use pubky_common::auth::jws::ClientId;
use serde::{Deserialize, Serialize};
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroize;

use super::{
    browser_grant_key_store::BrowserGrantKeyStore, browser_session::BrowserSessionLease,
    encryption_keys::EncryptionKeys, session_store::store_error,
};
use crate::{
    js_error::{JsResult, PubkyError, PubkyErrorName},
    wrappers::keys::PublicKey,
};

#[wasm_bindgen(inline_js = r#"
const DB_NAME = "pubky-delegated-auth";
const PARENT_STORE = "parentGrants";
const APPROVAL_KEYS = "approvalKeys";

function openDb() {
  if (!globalThis.indexedDB) throw new Error("Pubky parent grants require IndexedDB.");
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 2);
    // Opens queued behind a blocked upgrade don't receive their own "blocked" event.
    const timeout = setTimeout(() => {
      request.onupgradeneeded = () => request.transaction.abort();
      request.onsuccess = () => request.result.close();
      reject(new Error(
        "Opening the parent grant store timed out. Close other tabs using this site and retry.",
      ));
    }, 10_000);
    request.onupgradeneeded = () => {
      clearTimeout(timeout);
      const db = request.result;
      // Replace the unreleased development layout, including any plaintext approvals.
      for (const name of Array.from(db.objectStoreNames)) db.deleteObjectStore(name);
      db.createObjectStore(PARENT_STORE, { keyPath: "id" });
      db.createObjectStore(APPROVAL_KEYS);
    };
    request.onsuccess = () => {
      clearTimeout(timeout);
      const db = request.result;
      db.onversionchange = () => db.close();
      resolve(db);
    };
    request.onerror = () => {
      clearTimeout(timeout);
      reject(request.error ?? new Error("Opening the parent grant store failed."));
    };
  });
}

/** Run an operation and resolve with its request's result once the transaction commits. */
async function inParentStores(mode, operation) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction([PARENT_STORE, APPROVAL_KEYS], mode);
      tx.onerror = tx.onabort = () => reject(tx.error ?? new Error("The parent grant store failed."));
      try {
        const request = operation(tx.objectStore(PARENT_STORE), tx.objectStore(APPROVAL_KEYS));
        tx.oncomplete = () => resolve(request.result);
      } catch (error) {
        tx.abort();
        reject(error);
      }
    });
  } finally {
    db.close();
  }
}

function approvalCipher(id, iv) {
  return { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(id) };
}

/** Finish WebCrypto work before opening the IndexedDB write transaction. */
export async function __pubkyParentGrantSave(record, signedApproval) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(signedApproval);
  let ciphertext;
  try {
    ciphertext = await crypto.subtle.encrypt(approvalCipher(record.id, iv), key, plaintext);
  } finally {
    plaintext.fill(0);
  }

  const previous = await inParentStores("readwrite", (store, keys) => {
    const get = store.get(record.id);
    get.onsuccess = () => {
      if (get.result?.logoutPending) return;
      store.put({ ...record, encryptedApproval: { iv, ciphertext } });
      keys.put(key, record.id);
    };
    return get;
  });
  return !previous?.logoutPending;
}

/** Whether a saved parent's sign-out has started. False for a parent that was never saved. */
export async function __pubkyParentGrantLogoutPending(id) {
  return Boolean((await __pubkyParentGrantGet(id))?.logoutPending);
}

export function __pubkyParentGrantGet(id) {
  return inParentStores("readonly", store => store.get(id));
}

export async function __pubkyParentGrantRestore(id) {
  let keyRequest;
  const record = await inParentStores("readonly", (store, keys) => {
    keyRequest = keys.get(id);
    return store.get(id);
  });
  if (!record || record.logoutPending) return record;
  let bytes;
  try {
    const { iv, ciphertext } = record.encryptedApproval;
    bytes = new Uint8Array(await crypto.subtle.decrypt(approvalCipher(id, iv), keyRequest.result, ciphertext));
    record.signedApproval = new TextDecoder().decode(bytes);
    return record;
  } catch {
    throw new Error("Invalid stored parent grant record.");
  } finally {
    bytes?.fill(0);
  }
}

/** Remove the approval and its key before returning the public record for revocation. */
export function __pubkyParentGrantBeginSignOut(id) {
  return inParentStores("readwrite", (store, keys) => {
    const get = store.get(id);
    get.onsuccess = () => {
      const record = get.result;
      if (!record) return;
      record.logoutPending = true;
      delete record.encryptedApproval;
      store.put(record);
      keys.delete(id);
    };
    return get;
  });
}

export function __pubkyParentGrantDelete(id) {
  return inParentStores("readwrite", (store, keys) => {
    keys.delete(id);
    return store.delete(id);
  });
}

/** List parent metadata, leaving confidential and restore material out of the result. */
export async function __pubkyParentGrantList() {
  const records = await inParentStores("readonly", store => store.getAll());
  return records.map(({ encryptedApproval, parentGrant, keyId, ...metadata }) => metadata);
}

/** Ids of the signing keys that saved parents need, also to finish a pending sign-out. */
export async function __pubkyParentGrantKeyIds() {
  const records = await inParentStores("readonly", store => store.getAll());
  return records.map(record => record.keyId);
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = __pubkyParentGrantSave)]
    fn js_save(record: JsValue, signed_approval: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyParentGrantLogoutPending)]
    fn js_logout_pending(id: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyParentGrantGet)]
    fn js_get(id: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyParentGrantRestore)]
    fn js_restore(id: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyParentGrantBeginSignOut)]
    fn js_begin_signout(id: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyParentGrantDelete)]
    fn js_delete(id: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyParentGrantList)]
    fn js_list() -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyParentGrantKeyIds)]
    fn js_key_ids() -> js_sys::Promise;
}

/// Ids of the signing keys of saved parents, as a JS array.
/// `BrowserSessionStore.clearAll()` leaves these keys in place.
pub(crate) async fn saved_key_ids() -> JsResult<JsValue> {
    store_call(js_key_ids()).await
}

fn client_state_error(message: impl Into<String>) -> PubkyError {
    PubkyError::new(PubkyErrorName::ClientStateError, message.into())
}

fn invalid_record() -> PubkyError {
    client_state_error("Invalid stored parent grant record.")
}

fn signing_out() -> PubkyError {
    client_state_error("Parent grant is being signed out.")
}

async fn store_call(promise: js_sys::Promise) -> JsResult<JsValue> {
    JsFuture::from(promise).await.map_err(store_error)
}

fn to_js_record<T: Serialize>(record: &T) -> JsResult<JsValue> {
    // Flattened metadata must remain a plain JS object for IndexedDB readers.
    record
        .serialize(&serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true))
        .map_err(|error| {
            PubkyError::new(
                PubkyErrorName::InternalError,
                format!("Failed to serialize stored record: {error}"),
            )
        })
}

/// Public details of a saved parent grant.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParentMetadata {
    id: String,
    public_key: String,
    grant_id: String,
    client_id: String,
    capabilities: Vec<String>,
    expires_at: f64,
    created_at: f64,
    logout_pending: bool,
}

/// Public restore and revocation material. Only an in-memory restore includes
/// the decrypted approval.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParentRecord {
    #[serde(flatten)]
    metadata: ParentMetadata,
    key_id: String,
    parent_grant: String,
    #[serde(default, skip_serializing)]
    signed_approval: Option<String>,
}

impl Drop for ParentRecord {
    fn drop(&mut self) {
        self.signed_approval.zeroize();
    }
}

/// A verified parent grant, its keys and its non-extractable signing key.
///
/// It issues child grants for first-party apps but can't open a storage session.
/// Its keys can decrypt existing and future data under the approved scopes.
#[wasm_bindgen]
pub struct ParentGrant(pub(crate) ParentGrantCredential);

#[wasm_bindgen]
impl ParentGrant {
    /// The user's public key.
    #[wasm_bindgen(js_name = "publicKey", getter)]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.claims().iss.clone())
    }

    /// The parent's grant ID.
    #[wasm_bindgen(js_name = "grantId", getter)]
    pub fn grant_id(&self) -> String {
        self.0.claims().jti.to_string()
    }

    /// The holder's exact callback URL.
    #[wasm_bindgen(js_name = "clientId", getter)]
    pub fn client_id(&self) -> String {
        self.0.claims().client_id.to_string()
    }

    /// The capabilities the user approved. These may be narrower than requested.
    #[wasm_bindgen(getter)]
    pub fn capabilities(&self) -> Vec<String> {
        self.0
            .claims()
            .caps
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Parent expiry, in Unix seconds.
    #[wasm_bindgen(js_name = "expiresAt", getter)]
    pub fn expires_at(&self) -> f64 {
        self.0.claims().exp as f64
    }

    /// Keys for the approved `e` scopes. Empty if the user declined `e`.
    /// Each access creates an owned copy; call `free()` when finished.
    #[wasm_bindgen(js_name = "encryptionKeys", getter)]
    pub fn encryption_keys(&self) -> EncryptionKeys {
        EncryptionKeys(self.0.encryption_keys().clone())
    }

    /// Issue a child grant and return the callback URL that delivers it to the app.
    ///
    /// Check `request.clientId` and `request.capabilities` against your app
    /// catalog first. The child lasts until `expiresAt` (Unix seconds), or until
    /// the parent expires when omitted. Navigate to the returned URL and don't
    /// log it: its fragment carries the encrypted approval.
    ///
    /// @throws {PubkyError} `AuthenticationError` with
    /// `data.denial === "insufficient_permissions"` if the request exceeds this
    /// parent. Send the user to `request.declinedUrl(error.data.denial)`.
    /// @throws {PubkyError} `ClientStateError` once `signOut` has started for
    /// this parent, in this tab or another.
    #[wasm_bindgen(js_name = "issueChild")]
    pub async fn issue_child(
        &self,
        request: &ChildGrantRequest,
        expires_at: Option<f64>,
    ) -> JsResult<String> {
        // The signing key outlives a failed revocation so it can be retried, and a
        // parent restored earlier still holds it.
        // ponytail: a sign-out that starts after this check still gets this one
        // child. Closing that needs a lock across tabs.
        let pending = store_call(js_logout_pending(&self.record_id())).await?;
        if pending.is_truthy() {
            return Err(signing_out());
        }
        let url = self
            .0
            .issue_child(&request.0, expires_at.map(|value| value as u64))
            .await?;
        Ok(url.to_string())
    }
}

impl ParentGrant {
    /// The ID of this parent's record in `ParentGrantStore`.
    fn record_id(&self) -> String {
        let claims = self.0.claims();
        format!("{}:{}", claims.iss.z32(), claims.jti)
    }
}

/// An app's redirect request for a child grant, as received by the parent holder.
///
/// Every field comes from the request URL. Treat it as untrusted until you've
/// checked it against your app catalog.
#[wasm_bindgen]
pub struct ChildGrantRequest(pubky::deep_links::ChildGrantRequest);

#[wasm_bindgen]
impl ChildGrantRequest {
    /// Parse the URL the app redirected to, usually `location.href`.
    ///
    /// @throws {PubkyError} `InvalidInput` for malformed requests and callbacks
    /// that aren't exact HTTPS URLs.
    #[wasm_bindgen(js_name = "parse")]
    pub fn parse(url: &str) -> JsResult<ChildGrantRequest> {
        let invalid = |error: String| {
            PubkyError::new(
                PubkyErrorName::InvalidInput,
                format!("Invalid child grant request: {error}"),
            )
        };
        let url = Url::parse(url).map_err(|error| invalid(error.to_string()))?;
        pubky::deep_links::ChildGrantRequest::parse(&url)
            .map(Self)
            .map_err(|error| invalid(error.to_string()))
    }

    /// The app's exact callback URL, which becomes the child's client ID.
    #[wasm_bindgen(js_name = "clientId", getter)]
    pub fn client_id(&self) -> String {
        self.0.callback().to_string()
    }

    /// Capabilities requested by the app.
    #[wasm_bindgen(getter)]
    pub fn capabilities(&self) -> Vec<String> {
        self.0
            .capabilities()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Build the callback URL that tells the app no child grant was issued.
    ///
    /// The URL points at the callback the request named. Redirect to it only
    /// after you've found `clientId` in your app catalog, or Accounts becomes an
    /// open redirect. For an unknown callback, show an error instead.
    ///
    /// @param {string} reason `access_denied`, `cancelled` or `insufficient_permissions`.
    #[wasm_bindgen(js_name = "declinedUrl")]
    pub fn declined_url(&self, reason: &str) -> JsResult<String> {
        let reason = RedirectDenial::from_str(reason).map_err(|()| {
            PubkyError::new(
                PubkyErrorName::InvalidInput,
                format!("Unknown redirect denial: {reason}"),
            )
        })?;
        Ok(self.0.declined_url(reason).to_string())
    }
}

/// Public details of a saved parent grant. Holds no secrets.
#[wasm_bindgen]
pub struct ParentGrantInfo(ParentMetadata);

#[wasm_bindgen]
impl ParentGrantInfo {
    /// Stable local identifier for this saved parent grant.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.0.id.clone()
    }

    /// User public key as z32.
    #[wasm_bindgen(js_name = "publicKey", getter)]
    pub fn public_key(&self) -> String {
        self.0.public_key.clone()
    }

    /// The parent's grant ID.
    #[wasm_bindgen(js_name = "grantId", getter)]
    pub fn grant_id(&self) -> String {
        self.0.grant_id.clone()
    }

    /// The holder's exact callback URL.
    #[wasm_bindgen(js_name = "clientId", getter)]
    pub fn client_id(&self) -> String {
        self.0.client_id.clone()
    }

    /// The approved capabilities.
    #[wasm_bindgen(getter)]
    pub fn capabilities(&self) -> Vec<String> {
        self.0.capabilities.clone()
    }

    /// Parent expiry, in Unix seconds.
    #[wasm_bindgen(js_name = "expiresAt", getter)]
    pub fn expires_at(&self) -> f64 {
        self.0.expires_at
    }

    /// Local save timestamp, in Unix milliseconds.
    #[wasm_bindgen(js_name = "createdAt", getter)]
    pub fn created_at(&self) -> f64 {
        self.0.created_at
    }

    /// Whether sign-out started and its revocation still has to finish.
    #[wasm_bindgen(js_name = "logoutPending", getter)]
    pub fn logout_pending(&self) -> bool {
        self.0.logout_pending
    }
}

/// Browser-backed store for parent grants.
///
/// Encrypts each approval with a non-extractable AES key in a separate
/// IndexedDB object store. Scripts on this origin can still decrypt it.
#[wasm_bindgen]
pub struct ParentGrantStore(pub(crate) pubky::Pubky);

#[wasm_bindgen]
impl ParentGrantStore {
    /// Save a parent grant so it survives reloads and browser restarts.
    ///
    /// Saving requires Web Locks and a browser-held signing key. Rejects a
    /// parent whose sign-out is still pending.
    #[wasm_bindgen]
    pub async fn save(&self, parent: &ParentGrant) -> JsResult<ParentGrantInfo> {
        let key_id = parent.0.delegated_key_id().ok_or_else(|| {
            client_state_error("Only parent grants with a browser-held key can be saved.")
        })?;
        let claims = parent.0.claims();
        let metadata = ParentMetadata {
            id: parent.record_id(),
            public_key: claims.iss.z32(),
            grant_id: claims.jti.to_string(),
            client_id: claims.client_id.to_string(),
            capabilities: parent.capabilities(),
            expires_at: claims.exp as f64,
            created_at: js_sys::Date::now(),
            logout_pending: false,
        };
        // The signing key lives in another database. A completed sign-out must
        // not land between checking that key and committing the encrypted record.
        let _lease = BrowserSessionLease::for_parent(&metadata.id).await?;
        BrowserGrantKeyStore::load_public_key(key_id.clone()).await?;
        let record = ParentRecord {
            metadata: metadata.clone(),
            key_id,
            parent_grant: parent.0.parent_grant().to_owned(),
            signed_approval: None,
        };
        // Saving again would bring back a parent whose sign-out hasn't finished.
        let saved = store_call(js_save(to_js_record(&record)?, parent.0.signed_approval())).await?;
        if !saved.is_truthy() {
            return Err(signing_out());
        }
        Ok(ParentGrantInfo(metadata))
    }

    /// List saved parent grants. The result holds no secrets.
    #[wasm_bindgen]
    pub async fn list(&self) -> JsResult<Vec<ParentGrantInfo>> {
        // Skip records this version can't read, so that one can't hide the rest.
        Ok(js_sys::Array::from(&store_call(js_list()).await?)
            .iter()
            .filter_map(|record| serde_wasm_bindgen::from_value(record).ok())
            .map(ParentGrantInfo)
            .collect())
    }

    /// Restore a saved parent grant, verifying its signatures, identity, key
    /// scopes and signing key.
    ///
    /// Restore it for each request rather than keeping it, so a sign-out in
    /// another tab takes effect. If a sign-out is pending, this retries the
    /// revocation and then rejects.
    #[wasm_bindgen]
    pub async fn restore(&self, id: String) -> JsResult<ParentGrant> {
        let record = load_record(&id, js_restore(&id)).await?;
        if record.metadata.logout_pending {
            self.finish_signout(&record).await?;
            return Err(client_state_error("Parent grant was signed out."));
        }
        // The credential rejects a stored key that doesn't match the parent's `cnf`.
        let signing_key = BrowserGrantKeyStore::load_public_key(record.key_id.clone()).await?;
        let parent = ParentGrantCredential::from_delegated(
            record
                .signed_approval
                .as_deref()
                .ok_or_else(invalid_record)?,
            record.key_id.clone(),
            signing_key,
            BrowserGrantKeyStore::signer(record.key_id.clone()),
        )?;
        let claims = parent.claims();
        if record.metadata.public_key != claims.iss.z32()
            || record.metadata.grant_id != claims.jti.to_string()
        {
            return Err(invalid_record());
        }
        Ok(ParentGrant(parent))
    }

    /// Sign out: stop issuing, delete the saved keys and revoke the parent.
    ///
    /// Revokes the parent, all its children and their sessions. Keys are deleted
    /// first, and only what's needed to retry remains if the revocation fails.
    /// Call this again or `restore` to retry. Keys already delivered to apps
    /// can't be taken back.
    #[wasm_bindgen(js_name = "signOut")]
    pub async fn sign_out(&self, id: String) -> JsResult<()> {
        let record = load_record(&id, js_begin_signout(&id)).await?;
        self.finish_signout(&record).await
    }

    /// Let an app sign in again after the user removed it, for example in Ring.
    ///
    /// Removing an app blocks new child grants for that callback under this
    /// parent. Call this only after the user confirms the reconnection, then issue
    /// a new child. You can retry this call safely.
    ///
    /// @param {string} id The saved parent's ID, from `save` or `list`.
    /// @param {string} clientId The app's exact callback URL.
    /// @throws {PubkyError} `InvalidInput` if `clientId` isn't a valid client ID.
    #[wasm_bindgen(js_name = "reconnectApp")]
    pub async fn reconnect_app(&self, id: String, client_id: String) -> JsResult<()> {
        let client_id = ClientId::new(&client_id)
            .map_err(|error| PubkyError::new(PubkyErrorName::InvalidInput, error.to_string()))?;
        let parent = self.restore(id).await?;
        parent.0.reconnect_app(self.0.client(), &client_id).await?;
        Ok(())
    }

    /// Delete a saved parent grant and its signing key without revoking it.
    ///
    /// The grant stays valid at the homeserver until it expires or the user
    /// revokes it from Ring. Prefer `signOut`.
    #[wasm_bindgen]
    pub async fn remove(&self, id: String) -> JsResult<()> {
        let record = load_record(&id, js_get(&id)).await?;
        self.delete(&record).await
    }
}

async fn load_record(id: &str, request: js_sys::Promise) -> JsResult<ParentRecord> {
    let value = store_call(request).await?;
    if value.is_undefined() {
        return Err(client_state_error(format!(
            "Stored parent grant not found: {id}"
        )));
    }
    serde_wasm_bindgen::from_value(value).map_err(|_| invalid_record())
}

impl ParentGrantStore {
    async fn finish_signout(&self, record: &ParentRecord) -> JsResult<()> {
        ParentGrantCredential::revoke_delegated(
            self.0.client(),
            &record.parent_grant,
            record.key_id.clone(),
            BrowserGrantKeyStore::signer(record.key_id.clone()),
        )
        .await?;
        self.delete(record).await
    }

    async fn delete(&self, record: &ParentRecord) -> JsResult<()> {
        let _lease = BrowserSessionLease::for_parent(&record.metadata.id).await?;
        // Once the parent record is gone, clearAll() can collect an orphaned signing key.
        store_call(js_delete(&record.metadata.id)).await?;
        BrowserGrantKeyStore::delete_key(record.key_id.clone()).await
    }
}
