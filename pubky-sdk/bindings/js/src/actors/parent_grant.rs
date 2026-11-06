//! Browser bindings for parent grants.
//!
//! Parent records use their own database, so the session database's schema doesn't
//! change. Signing keys stay non-extractable WebCrypto keys in the existing delegated
//! key store, marked so that `BrowserSessionStore.clearAll()` leaves them in place.
//! Approvals are stored as plaintext in IndexedDB, the same as signed approvals in
//! `BrowserSessionStore`.

use std::str::FromStr;

use pubky::{ParentGrantCredential, errors::RedirectDenial};
use pubky_common::auth::jws::ClientId;
use serde::{Deserialize, Serialize};
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::{
    browser_grant_key_store::BrowserGrantKeyStore, encryption_keys::EncryptionKeys,
    session_store::store_error,
};
use crate::{
    js_error::{JsResult, PubkyError, PubkyErrorName},
    wrappers::keys::PublicKey,
};

#[wasm_bindgen(inline_js = r#"
const DB_NAME = "pubky-delegated-auth";
const DB_VERSION = 1;
const PARENT_STORE = "parentGrants";

function openDb() {
  if (!globalThis.indexedDB) throw new Error("Pubky parent grants require IndexedDB.");
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(PARENT_STORE, { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Opening the parent grant store failed."));
  });
}

/** Run an operation and resolve with its request's result once the transaction commits. */
async function inStore(mode, operation) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(PARENT_STORE, mode);
      const request = operation(tx.objectStore(PARENT_STORE));
      tx.oncomplete = () => resolve(request.result);
      tx.onerror = tx.onabort = () => reject(tx.error ?? new Error("The parent grant store failed."));
    });
  } finally {
    db.close();
  }
}

export function __pubkyParentGrantPut(record) {
  return inStore("readwrite", store => store.put(record));
}
export function __pubkyParentGrantGet(id) {
  return inStore("readonly", store => store.get(id));
}
export function __pubkyParentGrantDelete(id) {
  return inStore("readwrite", store => store.delete(id));
}

/** List parent metadata, leaving confidential and restore material out of the result. */
export async function __pubkyParentGrantList() {
  const records = await inStore("readonly", store => store.getAll());
  return records.map(({ signedApproval, parentGrant, keyId, ...metadata }) => metadata);
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = __pubkyParentGrantPut)]
    fn js_put(record: JsValue) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyParentGrantGet)]
    fn js_get(id: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyParentGrantDelete)]
    fn js_delete(id: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyParentGrantList)]
    fn js_list() -> js_sys::Promise;
}

fn client_state_error(message: impl Into<String>) -> PubkyError {
    PubkyError::new(PubkyErrorName::ClientStateError, message.into())
}

fn invalid_record() -> PubkyError {
    client_state_error("Invalid stored parent grant record.")
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

/// A saved parent grant. Signing out deletes `signed_approval` before it revokes
/// the grant, which leaves only what's needed to retry the revocation.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParentRecord {
    #[serde(flatten)]
    metadata: ParentMetadata,
    key_id: String,
    parent_grant: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signed_approval: Option<String>,
}

impl Drop for ParentRecord {
    fn drop(&mut self) {
        use zeroize::Zeroize;

        // JS/IndexedDB retain their own copies; clear the Rust-owned secret.
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
    #[wasm_bindgen(js_name = "issueChild")]
    pub async fn issue_child(
        &self,
        request: &ChildGrantRequest,
        expires_at: Option<f64>,
    ) -> JsResult<String> {
        let url = self
            .0
            .issue_child(&request.0, expires_at.map(|value| value as u64))
            .await?;
        Ok(url.to_string())
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
/// Stores confidential approvals as plaintext in IndexedDB. Signing keys remain
/// non-extractable, and `browserSessionStore.clearAll()` leaves them in place.
#[wasm_bindgen]
pub struct ParentGrantStore(pub(crate) pubky::Pubky);

#[wasm_bindgen]
impl ParentGrantStore {
    /// Save a parent grant so it survives reloads and browser restarts.
    ///
    /// Only parents with a browser-held signing key can be saved.
    #[wasm_bindgen]
    pub async fn save(&self, parent: &ParentGrant) -> JsResult<ParentGrantInfo> {
        let key_id = parent.0.delegated_key_id().ok_or_else(|| {
            client_state_error("Only parent grants with a browser-held key can be saved.")
        })?;
        // Before the record exists, so a saved parent can always find its key.
        BrowserGrantKeyStore::hold_key_for_parent(key_id.clone()).await?;
        let claims = parent.0.claims();
        let public_key = claims.iss.z32();
        let grant_id = claims.jti.to_string();
        let metadata = ParentMetadata {
            id: format!("{public_key}:{grant_id}"),
            public_key,
            grant_id,
            client_id: claims.client_id.to_string(),
            capabilities: parent.capabilities(),
            expires_at: claims.exp as f64,
            created_at: js_sys::Date::now(),
            logout_pending: false,
        };
        let record = ParentRecord {
            metadata: metadata.clone(),
            key_id,
            parent_grant: parent.0.parent_grant().to_owned(),
            signed_approval: Some(parent.0.signed_approval().to_owned()),
        };
        if let Err(error) = store_call(js_put(to_js_record(&record)?)).await {
            // Without a record nothing would release the key, so `clearAll()`
            // could never remove it. The save already failed: report that error.
            let _ = BrowserGrantKeyStore::release_key_from_parent(record.key_id.clone()).await;
            return Err(error);
        }
        Ok(ParentGrantInfo(metadata))
    }

    /// List saved parent grants. The result holds no secrets.
    #[wasm_bindgen]
    pub async fn list(&self) -> JsResult<Vec<ParentGrantInfo>> {
        let records: Vec<ParentMetadata> =
            serde_wasm_bindgen::from_value(store_call(js_list()).await?)
                .map_err(|_| invalid_record())?;
        Ok(records.into_iter().map(ParentGrantInfo).collect())
    }

    /// Restore a saved parent grant, verifying its signatures, identity, key
    /// scopes and signing key.
    ///
    /// Restore it for each request rather than keeping it, so a sign-out in
    /// another tab takes effect. If a sign-out is pending, this retries the
    /// revocation and then rejects.
    #[wasm_bindgen]
    pub async fn restore(&self, id: String) -> JsResult<ParentGrant> {
        let record = self.load(&id).await?;
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
        let mut record = self.load(&id).await?;
        record.metadata.logout_pending = true;
        record.signed_approval = None;
        store_call(js_put(to_js_record(&record)?)).await?;
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
        let record = self.load(&id).await?;
        self.delete(&record).await
    }
}

impl ParentGrantStore {
    async fn load(&self, id: &str) -> JsResult<ParentRecord> {
        let value = store_call(js_get(id)).await?;
        if value.is_undefined() {
            return Err(client_state_error(format!(
                "Stored parent grant not found: {id}"
            )));
        }
        serde_wasm_bindgen::from_value(value).map_err(|_| invalid_record())
    }

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
        // Release the key first. If a later step fails, `clearAll()` can still
        // remove the key, and the record stays usable for a retry.
        BrowserGrantKeyStore::release_key_from_parent(record.key_id.clone()).await?;
        store_call(js_delete(&record.metadata.id)).await?;
        BrowserGrantKeyStore::delete_key(record.key_id.clone()).await
    }
}
