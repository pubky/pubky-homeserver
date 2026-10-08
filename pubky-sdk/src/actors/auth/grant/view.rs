//! grant-only capability view — type-safe access to grant-specific operations.
//!
//! [`GrantSessionView`] is obtained via
//! [`PubkySession::as_grant`](crate::actors::session::core::PubkySession::as_grant).
//! The view borrows the session, so it cannot outlive it; this is what makes
//! the grant-only API impossible to misuse against a cookie session.

use pubky_common::auth::{grant_session_responses::GrantSessionInfo, jws::GrantId};

use super::credential::{REFRESH_SLACK_SECS, now_unix};
use super::{CustomPopError, DelegatedGrantCredentialState, GrantCredential};
use crate::actors::session::core::PubkySession;
use crate::actors::session::lent::LentBearer;
use crate::custom_pop::CustomPop;
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
    /// Sign arbitrary JSON and return both the custom proof and its root-signed grant.
    ///
    /// Makes no network requests and does not require a fresh homeserver bearer.
    /// Applications define the data's meaning and handle freshness and replay protection.
    /// Future grant issue times are checked by the verifier using its clock-skew policy.
    ///
    /// # Errors
    /// Returns [`CustomPopError`](crate::custom_pop::CustomPopError) for expired or unusable
    /// grants, unavailable signing keys, and signing failures. Browser coordination
    /// and lifecycle failures retain their source in its `SessionState` variant.
    pub async fn create_custom_pop(
        &self,
        data: serde_json::Value,
    ) -> std::result::Result<CustomPop, CustomPopError> {
        self.credential.create_custom_pop(data).await
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

    /// Lend the current bearer to a client on another origin.
    ///
    /// Session agents call this to answer an app's bearer request. The grant
    /// is exchanged when `rejected` is still the current bearer (the
    /// homeserver refused it) or when less than the refresh slack remains;
    /// otherwise the bearer already held is returned. Shared browser sessions
    /// do this under the tab lock, so concurrent asks and the agent's own
    /// requests cannot produce competing exchanges. The result carries no
    /// grant JWS, grant id or key.
    ///
    /// # Errors
    /// Propagates grant exchange errors.
    #[doc(hidden)]
    pub async fn lend_bearer(&self, rejected: Option<&str>) -> Result<LentBearer> {
        let near_expiry = {
            let state = self.credential.state.lock().await;
            state
                .needs_refresh(now_unix(), REFRESH_SLACK_SECS)
                .then(|| state.bearer.clone())
        };
        // A near-expiry bearer is treated like a rejected one: exchanged if
        // it is still current, otherwise the newer shared bearer is adopted.
        let rejected = rejected.map(str::to_owned).or(near_expiry);
        self.credential
            .refresh(self.session.client(), rejected.as_deref())
            .await?;
        let state = self.credential.state.lock().await;
        Ok(LentBearer {
            token: state.bearer.clone(),
            expires_at: state.session.token_expires_at,
            pubky: state.session.pubky.clone(),
            capabilities: state.session.capabilities.clone(),
            homeserver: state.session.homeserver.clone(),
        })
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
