//! Browser session persistence.

pub(crate) mod browser;
mod record;
#[cfg(test)]
mod tests;

use pubky::{GrantSessionCoordinator, GrantSessionLease};
use std::sync::Arc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

pub(crate) use browser::store_error;
use browser::*;
pub use record::StoredSessionInfo;
pub(crate) use record::{SessionMetadata, StoredSessionRecord};
use record::{
    StorageMode, StoredSessionMetadata, missing_approval, validate_record, validate_stored_metadata,
};

use super::{
    browser_grant_key_store::BrowserGrantKeyStore,
    browser_session::BrowserSessionCoordinator,
    encryption_keys::EncryptionKeys,
    grant_session::{decode_delegated_child_state, decode_delegated_grant_state},
    parent_grant,
    session::Session,
};
use crate::js_error::{JsResult, PubkyError, PubkyErrorName};

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

    /// Save a grant session. Approval secrets are stored as plaintext in IndexedDB.
    /// Redirect sessions are saved automatically; saving after sign-out/removal fails.
    #[wasm_bindgen]
    pub async fn save(&self, session: &Session) -> JsResult<StoredSessionInfo> {
        let grant = session.0.as_grant().ok_or_else(|| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Only grant-backed sessions can be saved in BrowserSessionStore.",
            )
        })?;
        let record = StoredSessionRecord::for_session(&grant).await?;
        let value = record.to_js()?;
        let coordinator = Arc::new(BrowserSessionCoordinator::new(
            &record.metadata.id,
            &record.metadata.homeserver,
        ));
        let lease = coordinator.acquire_browser(true).await?;
        // Only completing a redirect sign-in creates a child record, so a stale
        // handle can't bring back one that was removed or signed out.
        JsFuture::from(js_store_put(value, lease.token, record.is_child()))
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

    /// Verify and recover saved keys offline, even after grant expiry or revocation.
    /// Creates no session. Child sign-out deletes these keys.
    #[wasm_bindgen(js_name = "restoreEncryptionKeys")]
    pub async fn restore_encryption_keys(&self, id: String) -> JsResult<Option<EncryptionKeys>> {
        let record = load_record(&id).await?;
        let recovered = if record.is_child() {
            if record.logout_pending {
                return Err(signed_out());
            }
            let (state, _) = decode_delegated_child_state(&record.credential)?;
            let approval = record
                .signed_approval
                .as_deref()
                .ok_or_else(missing_approval)?;
            Some(pubky::GrantCredential::restore_child_encryption_keys(
                &state.grant_jws,
                approval,
            )?)
        } else {
            match record.metadata.storage_mode {
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
            }?
        };
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
    /// Web Locks in a secure browser context. If the session's sign-out is
    /// pending, this retries the revocation and then rejects.
    #[wasm_bindgen]
    pub async fn restore(&self, id: String) -> JsResult<Session> {
        let record = load_record(&id).await?;
        if record.is_child() && record.logout_pending {
            finish_child_signout(self.0.client(), &id).await?;
            super::redirect_auth_flow::finish_signout(self.0.client(), &record.metadata.client_id)
                .await?;
            return Err(signed_out());
        }
        let coordinator = Arc::new(BrowserSessionCoordinator::new(
            &id,
            &record.metadata.homeserver,
        ));
        let lease = coordinator.acquire(true).await?;
        let credential = match record.metadata.storage_mode {
            StorageMode::Delegated => {
                let (state, parent) = if record.is_child() {
                    let (state, parent) = decode_delegated_child_state(&record.credential)?;
                    (state, Some(parent))
                } else {
                    (decode_delegated_grant_state(&record.credential)?, None)
                };
                let stored_public_key =
                    BrowserGrantKeyStore::load_public_key(state.key_id.clone()).await?;
                if stored_public_key != state.client_pk {
                    return Err(PubkyError::new(
                        PubkyErrorName::ClientStateError,
                        "Delegated grant key public key does not match saved session.",
                    ));
                }
                let sign = BrowserGrantKeyStore::signer(state.key_id.clone());
                let approval = record.signed_approval.as_deref();
                match parent {
                    Some(parent) => {
                        let credential = pubky::GrantCredential::from_shared_delegated_child(
                            state,
                            sign,
                            approval.ok_or_else(missing_approval)?,
                        )?;
                        if credential.parent_grant() != Some(parent.as_str()) {
                            return Err(invalid_record());
                        }
                        credential
                    }
                    None => {
                        pubky::GrantCredential::from_shared_delegated_state(state, sign, approval)?
                    }
                }
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
            Session(session).signout().await?;
            return Err(signed_out());
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

    /// Delete saved sessions, pending redirects, and their signing keys locally.
    /// Pending direct flows and saved parent grants keep their keys.
    #[wasm_bindgen]
    pub async fn clear(&self) -> JsResult<()> {
        JsFuture::from(js_store_clear())
            .await
            .map_err(store_error)?;
        Ok(())
    }

    /// Delete local sessions, redirects, and unused signing keys without revoking grants.
    /// Saved parents and their keys stay until `parentGrantStore.signOut()`.
    #[wasm_bindgen(js_name = "clearAll")]
    pub async fn clear_all(&self) -> JsResult<()> {
        // ponytail: read before the clear, not in one transaction. A parent saved
        // in between loses its key, and `restore` then reports the key missing.
        let keep = parent_grant::saved_key_ids().await?;
        JsFuture::from(js_store_clear_all(keep))
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

    async fn load_metadata(&self, id: String) -> JsResult<SessionMetadata> {
        let value = JsFuture::from(js_store_metadata(id.clone()))
            .await
            .map_err(store_error)?;
        let metadata = decode_store_value(value, &id)?;
        validate_stored_metadata(metadata)
    }
}

async fn load_record(id: &str) -> JsResult<StoredSessionRecord> {
    let value = JsFuture::from(js_store_get(id.to_owned()))
        .await
        .map_err(store_error)?;
    let record = decode_store_value(value, id)?;
    validate_record(record)
}

/// Revoke a signed-out child, then remove its record and signing key.
/// Succeeds if the record is already gone.
pub(crate) async fn finish_child_signout(
    client: &pubky::PubkyHttpClient,
    id: &str,
) -> JsResult<()> {
    let value = JsFuture::from(js_store_get(id.to_owned()))
        .await
        .map_err(store_error)?;
    if value.is_undefined() {
        return Ok(());
    }
    let initial: StoredSessionRecord = decode_store_value(value, id)?;
    let lease = BrowserSessionCoordinator::new(id, &initial.metadata.homeserver)
        .acquire_browser(true)
        .await?;
    // Another tab may have finished while this one waited for the lock.
    let value = JsFuture::from(js_store_get(id.to_owned()))
        .await
        .map_err(store_error)?;
    if value.is_undefined() {
        return Ok(());
    }
    let record = validate_record(decode_store_value(value, id)?)?;
    if !record.is_child() || !record.logout_pending {
        return Err(invalid_record());
    }
    let (state, parent) = decode_delegated_child_state(&record.credential)?;
    let sign = BrowserGrantKeyStore::signer(state.key_id.clone());
    let credential =
        pubky::GrantCredential::from_shared_delegated_child_logout(state, &parent, sign)?;
    pubky::PubkySession::from_grant_credential(client.clone(), credential)
        .signout()
        .await
        .map_err(|(error, _)| error)?;
    lease.remove().await?;
    Ok(())
}

pub(crate) fn invalid_record() -> PubkyError {
    PubkyError::new(
        PubkyErrorName::ClientStateError,
        "Invalid stored session record.",
    )
}

fn signed_out() -> PubkyError {
    PubkyError::new(
        PubkyErrorName::ClientStateError,
        "Browser session was signed out.",
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
