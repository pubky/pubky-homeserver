//! Stored session formats and metadata.

use pubky::SharedGrantSession;
use pubky_common::auth::grant_session_responses::GrantSessionResponse;
use pubky_common::{auth::jws::GrantId, crypto::PublicKey};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use super::super::grant_session::{encode_delegated_child_state, encode_delegated_grant_state};
use super::invalid_record;
use crate::js_error::{JsResult, PubkyError, PubkyErrorName};

pub(super) const STORE_VERSION: &str = "pubky-session-v1";
pub(super) const STORE_APPROVAL_VERSION: &str = "pubky-session-v2";
/// A child grant session: its record holds the public parent and its signed
/// child approval. Older SDKs reject the version.
pub(super) const STORE_CHILD_VERSION: &str = "pubky-session-v3";

/// How a stored session retains its proof-of-possession signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum StorageMode {
    Delegated,
    LocalSecret,
}

impl StorageMode {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Delegated => "delegated",
            Self::LocalSecret => "localSecret",
        }
    }
}

/// Public session details shared by stored records and metadata-only reads.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionMetadata {
    pub(super) version: String,
    pub(crate) id: String,
    pub(super) storage_mode: StorageMode,
    pub(super) public_key: String,
    pub(crate) homeserver: String,
    pub(super) grant_id: String,
    pub(super) client_id: String,
    pub(super) capabilities: Vec<String>,
    pub(super) grant_expires_at: f64,
    pub(super) created_at: f64,
}

/// Listing/removal projection that omits confidential restore material.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StoredSessionMetadata {
    #[serde(flatten)]
    pub(super) metadata: SessionMetadata,
    #[serde(default)]
    pub(super) has_stored_approval: bool,
    #[serde(default)]
    logout_pending: bool,
}

/// Confidential restore material. V2 delegated records and V3 records require
/// the actual signed approval; metadata's presence flag cannot substitute for
/// its bytes. A V3 record whose sign-out started has no approval left.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredSessionRecord {
    #[serde(flatten)]
    pub(crate) metadata: SessionMetadata,
    pub(super) credential: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) signed_approval: Option<String>,
    /// True once a child session starts signing out.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) logout_pending: bool,
    #[serde(default, skip_deserializing, skip_serializing_if = "Option::is_none")]
    shared_session: Option<SharedGrantSession>,
}

impl Drop for StoredSessionRecord {
    fn drop(&mut self) {
        // JS/IndexedDB retain their own copies; clear the Rust-owned secrets.
        self.credential.zeroize();
        self.signed_approval.zeroize();
        if let Some(shared) = &mut self.shared_session {
            shared.response.token.zeroize();
        }
    }
}

impl StoredSessionRecord {
    /// Build the record that saves a grant session. A child session keeps its
    /// public parent in the credential and its signed child approval separately.
    pub(crate) async fn for_session(grant: &pubky::GrantSessionView<'_>) -> JsResult<Self> {
        let session_info = grant.session_info().await;
        let grant_id = session_info.grant_id.to_string();
        let public_key = session_info.pubky.z32();
        let parent = grant.parent_grant();
        let shared_session = if parent.is_some() {
            Some(SharedGrantSession {
                response: GrantSessionResponse {
                    token: grant.current_bearer().await,
                    session: session_info.clone(),
                },
                refresh_pending: false,
                logout_pending: false,
            })
        } else {
            None
        };

        let (storage_mode, credential) =
            match (grant.export_delegated_restore_state().await, parent) {
                (Some(state), Some(parent)) => (
                    StorageMode::Delegated,
                    encode_delegated_child_state(state, parent)?,
                ),
                (Some(state), None) => {
                    (StorageMode::Delegated, encode_delegated_grant_state(state)?)
                }
                // Child sessions are only created with a browser-held key.
                (None, Some(_)) => {
                    return Err(PubkyError::new(
                        PubkyErrorName::ClientStateError,
                        "Child grant sessions need a browser-held key to be saved.",
                    ));
                }
                (None, None) => {
                    let secret = grant.export_local_secret().await.ok_or_else(|| {
                        PubkyError::new(
                            PubkyErrorName::ClientStateError,
                            "This grant session cannot export restorable local secret material.",
                        )
                    })?;
                    (StorageMode::LocalSecret, secret)
                }
            };

        let version = if parent.is_some() {
            STORE_CHILD_VERSION
        } else if grant.encryption_keys().is_some() {
            STORE_APPROVAL_VERSION
        } else {
            STORE_VERSION
        };
        let metadata = SessionMetadata {
            version: version.to_string(),
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
        Ok(Self {
            signed_approval: match metadata.storage_mode {
                StorageMode::Delegated => grant.signed_approval().map(str::to_owned),
                // Local V2 tokens already include the signed approval.
                StorageMode::LocalSecret => None,
            },
            metadata,
            credential,
            logout_pending: false,
            shared_session,
        })
    }

    /// The same record with only what's needed to finish signing out: no approval.
    pub(crate) fn logout_only(mut self) -> Self {
        self.signed_approval.zeroize();
        self.logout_pending = true;
        self.shared_session = None;
        self
    }

    /// The record as a plain JS object for IndexedDB.
    pub(crate) fn to_js(&self) -> JsResult<JsValue> {
        // Flattened metadata must remain a plain JS object for IndexedDB readers.
        let value = self
            .serialize(&serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true))
            .map_err(|e| {
                PubkyError::new(
                    PubkyErrorName::InternalError,
                    format!("Failed to serialize stored session: {e}"),
                )
            })?;
        Ok(value)
    }

    pub(super) fn is_child(&self) -> bool {
        self.metadata.version == STORE_CHILD_VERSION
    }
}

/// Metadata for a session saved in the browser session store.
#[wasm_bindgen]
pub struct StoredSessionInfo(pub(crate) SessionMetadata);

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

impl SessionMetadata {
    pub(super) fn validate_grant_identity(
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
        match self.version.as_str() {
            STORE_VERSION | STORE_APPROVAL_VERSION => Ok(()),
            // Child sessions are only saved with a browser-held key.
            STORE_CHILD_VERSION if self.storage_mode == StorageMode::Delegated => Ok(()),
            STORE_CHILD_VERSION => Err(invalid_record()),
            _ => Err(PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Unsupported stored session version.",
            )),
        }
    }

    fn requires_separate_approval(&self, logout_pending: bool) -> bool {
        match self.version.as_str() {
            STORE_APPROVAL_VERSION => self.storage_mode == StorageMode::Delegated,
            // Only the dedicated sign-out path reads a child record without it.
            STORE_CHILD_VERSION => !logout_pending,
            _ => false,
        }
    }
}

pub(super) fn missing_approval() -> PubkyError {
    PubkyError::new(
        PubkyErrorName::ClientStateError,
        "Stored session is missing its signed approval.",
    )
}

pub(super) fn validate_stored_metadata(record: StoredSessionMetadata) -> JsResult<SessionMetadata> {
    record.metadata.validate()?;
    if record
        .metadata
        .requires_separate_approval(record.logout_pending)
        && !record.has_stored_approval
    {
        return Err(missing_approval());
    }
    Ok(record.metadata)
}

pub(super) fn validate_record(record: StoredSessionRecord) -> JsResult<StoredSessionRecord> {
    record.metadata.validate()?;
    if record
        .metadata
        .requires_separate_approval(record.logout_pending)
        && record.signed_approval.is_none()
    {
        return Err(missing_approval());
    }
    Ok(record)
}
