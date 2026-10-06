//! grant-only capability view — type-safe access to grant-specific operations.
//!
//! [`GrantSessionView`] is obtained via
//! [`PubkySession::as_grant`](crate::actors::session::core::PubkySession::as_grant).
//! The view borrows the session, so it cannot outlive it; this is what makes
//! the grant-only API impossible to misuse against a cookie session.

use pubky_common::auth::{grant_session_responses::GrantSessionInfo, jws::GrantId};

use super::{DelegatedGrantCredentialState, GrantCredential, ServiceAuthProofError};
use crate::actors::session::core::PubkySession;
use crate::errors::Result;
use crate::service_auth::ServiceAuthProof;

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
    /// Create external-service credentials without making network requests.
    ///
    /// The audience is an opaque, case-sensitive string of 1–1024 UTF-8 bytes,
    /// preserved exactly. Agree on its value with the service. The homeserver
    /// bearer may be expired; only the grant and signing key are needed.
    /// Generate fresh credentials for each exchange attempt, including retries.
    /// Homeserver revocation does not revoke external sessions; services should
    /// bound their sessions by grant expiry.
    ///
    /// # Errors
    /// Returns [`ServiceAuthProofError`] for invalid audiences, expired or unusable
    /// grants, unavailable signing keys, and signing failures. Browser coordination
    /// and lifecycle failures retain their source in its `SessionState` variant.
    pub async fn create_service_auth_proof(
        &self,
        audience: &str,
    ) -> std::result::Result<ServiceAuthProof, ServiceAuthProofError> {
        self.credential.create_service_auth_proof(audience).await
    }

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
        self.credential.refresh(self.session.client()).await
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

    /// Test/debug helper: force a refresh of the credential right now.
    ///
    /// Used by integration tests to verify that a refresh yields a new
    /// bearer. Returns the new bearer for assertions.
    ///
    /// Bypasses the proactive-refresh time check so the refresh always runs.
    ///
    /// # Errors
    /// - Propagates HTTP errors from the refresh exchange.
    #[doc(hidden)]
    pub async fn force_refresh(&self) -> Result<String> {
        if let Some(coordinator) = self.credential.coordinator().await {
            let bearer = self.credential.current_bearer().await;
            self.credential
                .refresh_shared(self.session.client(), coordinator.as_ref(), Some(&bearer))
                .await?;
            return Ok(self.credential.current_bearer().await);
        }
        // Bypass the proactive-refresh time check by setting the expiry
        // to 0; the refresh helper then always hits the network.
        self.credential.state.lock().await.session.token_expires_at = 0;
        self.credential.refresh(self.session.client()).await?;
        Ok(self.credential.state.lock().await.bearer.clone())
    }
}
