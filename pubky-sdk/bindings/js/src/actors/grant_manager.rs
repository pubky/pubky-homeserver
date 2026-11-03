use wasm_bindgen::prelude::*;

use super::{grant_session::GrantInfo, session::Session};
use crate::js_error::{JsResult, PubkyError, PubkyErrorName};
use pubky_common::auth::jws::GrantId;

/// Account-level grant management for a signed-in user.
#[wasm_bindgen]
pub struct GrantManager(pub(crate) pubky::GrantManager);

#[wasm_bindgen]
impl GrantManager {
    /// Create a grant manager authenticated by a session.
    ///
    /// @param {Session} session
    /// @returns {GrantManager}
    #[wasm_bindgen(constructor)]
    pub fn new(session: &Session) -> Self {
        Self(pubky::GrantManager::new(&session.0))
    }

    /// List all active grants for this user.
    ///
    /// Requires a root-capability session. Non-root sessions surface the
    /// homeserver `403` as the standard request error. Each entry's `kind` and
    /// `parentId` group child grants under their delegation parent.
    ///
    /// @returns {Promise<GrantInfo[]>}
    #[wasm_bindgen]
    pub async fn list(&self) -> JsResult<Vec<GrantInfo>> {
        Ok(self.0.list().await?.into_iter().map(GrantInfo).collect())
    }

    /// Revoke a specific grant by id.
    ///
    /// Revoking a delegation parent also revokes its children. Revoking a child
    /// also blocks that app under its parent until Accounts reconnects it.
    ///
    /// Requires a root-capability session. Malformed ids throw
    /// `InvalidInput`.
    ///
    /// @param {string} grantId
    /// @returns {Promise<void>}
    #[wasm_bindgen]
    pub async fn revoke(&self, grant_id: String) -> JsResult<()> {
        let grant_id = GrantId::parse(&grant_id).map_err(|e| {
            PubkyError::new(
                PubkyErrorName::InvalidInput,
                format!("Invalid grant id: {e}"),
            )
        })?;
        self.0.revoke(&grant_id).await?;
        Ok(())
    }
}
