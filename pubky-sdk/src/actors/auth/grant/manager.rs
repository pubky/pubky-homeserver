//! Account-level grant management.
//!
//! [`GrantManager`] is authenticated by a [`PubkySession`], but is not tied to
//! grant-backed sessions. The homeserver decides whether the session has the
//! root capability required to list and revoke grants.

use pubky_common::auth::{grant_session_responses::GrantInfo, jws::GrantId};
use reqwest::Method;

use crate::PubkySession;
use crate::errors::Result;
use crate::util::read_json_body;

/// Maximum size, inclusive, of a `/auth/grant/sessions` listing. A client-side
/// bound: the homeserver returns every grant in one uncapped response, so an
/// overflow fails the whole call.
const MAX_GRANT_LIST_BYTES: usize = 1024 * 1024;

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
    session: PubkySession,
}

impl GrantManager {
    /// Construct a grant manager authenticated by `session`.
    #[must_use]
    pub fn new(session: &PubkySession) -> Self {
        Self {
            session: session.clone(),
        }
    }

    /// List all active grants for this user.
    ///
    /// Calls `GET /auth/grant/sessions`. Requires a root-capability session;
    /// non-root sessions get `403 Forbidden` from the homeserver. Each entry's
    /// `kind` and `parent_id` group child grants under their parent grant.
    ///
    /// # Errors
    /// - Propagates HTTP errors from the homeserver (`401`/`403` for invalid
    ///   auth or missing root capability).
    pub async fn list(&self) -> Result<Vec<GrantInfo>> {
        let resp = self
            .session
            .send_account_request(Method::GET, "/auth/grant/sessions")
            .await?;
        read_json_body(resp, MAX_GRANT_LIST_BYTES, "/auth/grant/sessions response").await
    }

    /// Revoke a specific grant by id, killing all of its sessions.
    ///
    /// Revoking a parent grant also revokes its children. Revoking a child
    /// also blocks that app under its parent until Accounts reconnects it.
    ///
    /// Calls `DELETE /auth/grant/session/{gid}`. Requires a root-capability
    /// session.
    ///
    /// # Errors
    /// - Propagates HTTP errors from the homeserver (`401`/`403` for invalid
    ///   auth or missing root capability).
    pub async fn revoke(&self, grant_id: &GrantId) -> Result<()> {
        let path = format!("/auth/grant/session/{}", grant_id.as_str());
        self.session
            .send_account_request(Method::DELETE, &path)
            .await?;
        Ok(())
    }
}
