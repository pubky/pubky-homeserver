//! grant-only capability view — type-safe access to grant-specific operations.
//!
//! [`GrantSessionView`] is obtained via
//! [`PubkySession::as_grant`](crate::actors::session::core::PubkySession::as_grant).
//! The view borrows the session, so it cannot outlive it; this is what makes
//! the grant-only API impossible to misuse against a cookie session.

use pubky_common::auth::{
    grant_session_responses::{GrantSessionInfo, GrantSessionResponse},
    jws::GrantId,
};

use super::{DelegatedGrantCredentialState, GrantCredential};
use crate::actors::session::core::PubkySession;
use crate::errors::Result;

/// grant-only operations on a [`PubkySession`].
#[derive(Debug)]
pub struct GrantSessionView<'a> {
    session: &'a PubkySession,
    credential: &'a GrantCredential,
}

impl PubkySession {
    /// Returns a [`GrantSessionView`] if this session is grant-backed.
    ///
    /// grant-only operations (`session_info`, `export_secret`,
    /// `current_bearer`, `force_refresh`, `grant_id`) live on the view.
    /// Cookie-backed sessions return `None`.
    #[must_use]
    pub fn as_grant(&self) -> Option<GrantSessionView<'_>> {
        self.try_downcast_credential::<GrantCredential>()
            .map(|c| GrantSessionView::new(self, c))
    }
}

impl<'a> GrantSessionView<'a> {
    pub(crate) const fn new(session: &'a PubkySession, credential: &'a GrantCredential) -> Self {
        Self {
            session,
            credential,
        }
    }

    /// Returns the full grant session metadata from the homeserver.
    ///
    /// This gives access to grant-specific fields like `grant_id`,
    /// `client_id`, `token_expires_at`, and `grant_expires_at` that are
    /// not available via the shared
    /// [`PubkySession::info`](crate::actors::session::core::PubkySession::info)
    /// accessor.
    pub async fn session_info(&self) -> GrantSessionInfo {
        self.credential.state.lock().await.session.clone()
    }

    /// Export the portable local secret material needed to restore this session.
    ///
    /// The returned token contains the grant JWS and `PoP` client secret. Treat
    /// it as a bearer-equivalent secret until the grant expires or is revoked.
    /// Delegated/browser-held `PoP` keys return `None` because the private key
    /// is intentionally not extractable.
    pub async fn export_local_secret(&self) -> Option<String> {
        self.credential.export_local_secret().await
    }

    /// Export non-secret delegated restore metadata, if this session uses a
    /// browser-held delegated `PoP` key.
    pub async fn export_delegated_restore_state(&self) -> Option<DelegatedGrantCredentialState> {
        self.credential.export_delegated_restore_state().await
    }

    /// Returns the current opaque bearer for this session.
    pub async fn current_bearer(&self) -> String {
        self.credential.current_bearer().await
    }

    /// Returns the grant id (`jti`) backing this session, for callers that
    /// need to revoke or display it.
    pub async fn grant_id(&self) -> GrantId {
        self.credential.state.lock().await.grant_claims.jti.clone()
    }

    /// Refresh shared credential state if its bearer is near expiry.
    ///
    /// Browser restore calls this to keep existing handles usable.
    /// # Errors
    /// Propagates grant exchange errors.
    #[doc(hidden)]
    pub async fn refresh_if_needed(&self) -> Result<()> {
        self.credential.refresh(self.session.client(), None).await
    }

    /// Attach browser coordination to this session and its existing clones.
    #[doc(hidden)]
    pub async fn coordinate(
        &self,
        coordinator: std::sync::Arc<dyn crate::GrantSessionCoordinator>,
        lease: &dyn crate::GrantSessionLease,
    ) -> Result<()> {
        self.credential.coordinate(coordinator, lease).await
    }

    /// Current bearer for a remote client that shares this grant.
    ///
    /// Auth agents call this to answer another origin's bearer request.
    /// `rejected` is the bearer the homeserver refused: the grant is exchanged
    /// when that is still the current bearer or the bearer is near expiry,
    /// otherwise the newer bearer already held is returned. Shared browser
    /// sessions do this under the tab lock, so concurrent asks and the
    /// agent's own requests cannot produce competing exchanges.
    ///
    /// # Errors
    /// Propagates grant exchange errors.
    pub async fn bearer_for_remote(&self, rejected: Option<&str>) -> Result<GrantSessionResponse> {
        self.credential
            .refresh(self.session.client(), rejected)
            .await?;
        Ok(self.credential.state.lock().await.response())
    }

    /// Test/debug helper: force a refresh of the credential right now.
    ///
    /// Used by integration tests to verify that a refresh yields a new
    /// bearer. Returns the new bearer for assertions.
    ///
    /// # Errors
    /// - Propagates HTTP errors from the refresh exchange.
    #[doc(hidden)]
    pub async fn force_refresh(&self) -> Result<String> {
        // Treating the current bearer as rejected bypasses the time check.
        let bearer = self.credential.current_bearer().await;
        self.credential
            .refresh(self.session.client(), Some(&bearer))
            .await?;
        Ok(self.credential.current_bearer().await)
    }
}
