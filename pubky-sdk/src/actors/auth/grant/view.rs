//! grant-only capability view — type-safe access to grant-specific operations.
//!
//! [`GrantSessionView`] is obtained via
//! [`PubkySession::as_grant`](crate::actors::session::core::PubkySession::as_grant).
//! The view borrows the session, so it cannot outlive it; this is what makes
//! the grant-only API impossible to misuse against a cookie session.

use pubky_common::{
    auth::{grant_session_responses::GrantSessionInfo, jws::GrantId},
    encryption_keys::ScopedEncryptionKeyBundle,
};

use super::{CustomPopError, DelegatedGrantCredentialState, GrantCredential};
use crate::actors::session::core::PubkySession;
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

    /// Verified scoped keys retained by this session's grant credential.
    ///
    /// Bare grants return `None`; signed approvals return `Some`, with an empty
    /// bundle when no `e` scopes were approved. Secret tokens of signed
    /// approvals (`pubky-grant-credential-v2`) preserve the bundle; bare-grant
    /// tokens have no keys.
    ///
    /// The signer may narrow the requested scopes or decline `e`, so check the
    /// approved scopes before deriving keys. Keys stay usable after the grant
    /// expires or is revoked; see the
    /// [scoped encryption keys guide](https://github.com/pubky/pubky-homeserver/blob/main/docs/scoped-encryption-keys.md).
    ///
    /// ```no_run
    /// # use pubky::{PubkySession, StoragePath};
    /// # fn use_keys(session: &PubkySession) -> Result<(), Box<dyn std::error::Error>> {
    /// let grant = session.as_grant().expect("grant-backed session");
    /// let chat = StoragePath::new("/pub/chat/")?;
    /// if let Some(keys) = grant.encryption_keys() {
    ///     if keys.scopes().any(|scope| scope == &chat) {
    ///         let path = StoragePath::new("/pub/chat/message")?;
    ///         let key = keys.derive_for_path(&path)?; // 32 bytes, wiped on drop.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    pub fn encryption_keys(&self) -> Option<&ScopedEncryptionKeyBundle> {
        self.credential.encryption_keys()
    }

    /// Borrow the confidential signed approval for secure browser persistence.
    ///
    /// May contain scoped secret keys. Store separately from non-secret delegated
    /// metadata. Use [`GrantCredential::restore_delegated_encryption_keys`] for
    /// offline key recovery, or import the credential to authenticate again.
    pub fn signed_approval(&self) -> Option<&str> {
        self.credential.signed_approval()
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
    /// it as a bearer-equivalent secret. Sessions with signed approvals include
    /// those approvals, even with an empty key bundle. Delivered keys remain
    /// sensitive after expiry or revocation.
    /// Delegated/browser-held `PoP` keys return `None` because the private key
    /// is intentionally not extractable.
    pub async fn export_local_secret(&self) -> Option<String> {
        self.credential.export_local_secret().await
    }

    /// Export non-secret delegated restore metadata, if this session uses a
    /// browser-held delegated `PoP` key.
    /// Scoped keys are omitted; persist [`Self::signed_approval`] separately
    /// to restore keys alongside authentication.
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
