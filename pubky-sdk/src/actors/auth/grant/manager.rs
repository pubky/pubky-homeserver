//! Account-level grant management.
//!
//! [`GrantManager`] is authenticated by a [`PubkySession`], but is not tied to
//! grant-backed sessions. The homeserver decides whether the session has the
//! root capability required to list and revoke grants.

use pubky_common::auth::{grant_session_responses::GrantInfo, jws::GrantId};
use pubky_common::crypto::PublicKey;
use reqwest::Method;
use std::sync::Arc;

use crate::actors::session::credential::SessionCredential;
use crate::actors::storage::resource::resolve_pubky;
use crate::errors::{RequestError, Result};
use crate::util::check_http_status;
use crate::{PubkyHttpClient, PubkySession};

/// Account-level grant management for a signed-in user.
///
/// Use this to list and revoke grants (app permissions) for your account.
/// Requires a session with the **root capability**; non-root sessions get
/// `403 Forbidden` from the homeserver.
///
/// # Example
///
/// ```no_run
/// use pubky::GrantManager;
///
/// # async fn example(session: pubky::PubkySession) -> pubky::Result<()> {
/// let manager = GrantManager::new(&session);
///
/// // List all active grants
/// let grants = manager.list().await?;
/// for grant in &grants {
///     println!("grant {} from client {}", grant.grant_id, grant.client_id);
/// }
///
/// // Revoke a specific grant
/// if let Some(grant) = grants.first() {
///     manager.revoke(&grant.grant_id).await?;
/// }
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct GrantManager {
    client: PubkyHttpClient,
    user: PublicKey,
    credential: Arc<dyn SessionCredential>,
}

impl GrantManager {
    /// Construct a grant manager authenticated by `session`.
    #[must_use]
    pub fn new(session: &PubkySession) -> Self {
        Self {
            client: session.client().clone(),
            user: session.info().public_key().clone(),
            credential: Arc::clone(session.credential()),
        }
    }

    /// List all active grants for this user.
    ///
    /// Calls `GET /auth/grant/sessions`. Requires a root-capability session;
    /// non-root sessions get `403 Forbidden` from the homeserver.
    ///
    /// # Errors
    /// - Propagates HTTP errors from the homeserver (`401`/`403` for invalid
    ///   auth or missing root capability).
    pub async fn list(&self) -> Result<Vec<GrantInfo>> {
        let url = format!("pubky://{}/auth/grant/sessions", self.user.z32());
        let resolved = resolve_pubky(&url)?;
        let rb = self.client.cross_request(Method::GET, resolved).await?;
        let resp = self
            .credential
            .attach(rb, &self.client)
            .await?
            .send()
            .await?;
        let resp = check_http_status(resp).await?;
        let grants: Vec<GrantInfo> = resp.json().await.map_err(|e| RequestError::DecodeJson {
            message: format!("decoding /auth/grant/sessions response: {e}"),
        })?;
        Ok(grants)
    }

    /// Revoke a specific grant by id, killing all of its sessions.
    ///
    /// Calls `DELETE /auth/grant/session/{gid}`. Requires a root-capability
    /// session.
    ///
    /// # Errors
    /// - Propagates HTTP errors from the homeserver (`401`/`403` for invalid
    ///   auth or missing root capability).
    pub async fn revoke(&self, grant_id: &GrantId) -> Result<()> {
        let url = format!(
            "pubky://{}/auth/grant/session/{}",
            self.user.z32(),
            grant_id.as_str()
        );
        let resolved = resolve_pubky(&url)?;
        let rb = self.client.cross_request(Method::DELETE, resolved).await?;
        let resp = self
            .credential
            .attach(rb, &self.client)
            .await?
            .send()
            .await?;
        check_http_status(resp).await?;
        Ok(())
    }
}
