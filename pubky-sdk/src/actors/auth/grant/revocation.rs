//! One-use revocation of a captured bearer, without credential refresh or replay.

use std::fmt;

use pubky_common::auth::{
    grant_revocation::{ConditionalGrantRevocation, GrantRevocationReceipt},
    jws::RandomId,
};
use zeroize::Zeroizing;

use super::{GrantCredential, credential::now_unix};
use crate::{PubkyHttpClient, PublicKey};

#[cfg(target_arch = "wasm32")]
mod browser;

const PATH: &str = "/auth/grant/session-revocation";
const MAX_RECEIPT_BYTES: usize = 4096;

/// A captured, one-use request to revoke exactly the original grant bearer.
///
/// Obtain this through [`crate::GrantSessionView::prepare_revocation`] before
/// confirmation. No refresh credential or mutable session is retained. Dropping
/// the operation before execution sends nothing; cancellation after sending may
/// leave an unknown remote outcome. Neither an error nor a receipt authorizes
/// local credential deletion: callers must enforce their original owner/lifecycle
/// and durable cleanup obligations separately.
#[must_use]
pub struct GrantRevocation {
    client: PubkyHttpClient,
    bearer: Zeroizing<String>,
    binding: ConditionalGrantRevocation,
    homeserver: PublicKey,
}

/// Revocation failures never establish remote success or authorize replay.
///
/// Error text contains no response body, URL, bearer, or refresh material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GrantRevocationError {
    /// No usable bearer/identity snapshot was available; no request was sent.
    #[error("No current grant bearer is available for capture")]
    InvalidSnapshot,
    /// Transport preparation failed before sending the mutation.
    #[error("Could not prepare the captured grant revocation")]
    Preparation,
    /// No matching affirmative receipt was obtained. The remote outcome may
    /// be unknown even after a successful HTTP status or cancellation.
    #[error("Captured grant revocation was not acknowledged")]
    Unacknowledged {
        /// HTTP status, if one was observed. This is not permission to retry.
        status: Option<u16>,
    },
}

impl GrantRevocation {
    /// Non-secret original bindings to show and retain with the confirmation.
    pub const fn binding(&self) -> &ConditionalGrantRevocation {
        &self.binding
    }

    /// Original homeserver that must issue the receipt.
    pub const fn homeserver(&self) -> &PublicKey {
        &self.homeserver
    }

    /// Consume this operation with one HTTP attempt using only its captured bearer.
    ///
    /// Never refreshes, adopts shared credentials, follows redirects, retries,
    /// or clears local/shared session state. Only an exact versioned receipt
    /// acknowledges success. A cancelled or dropped response can remain unknown.
    ///
    /// # Errors
    /// Returns a preparation error or an unacknowledged outcome; the operation
    /// is consumed on every outcome. Reconciliation and fresh user confirmation
    /// are caller responsibilities, not automatic retry authorization.
    pub async fn execute(self) -> Result<GrantRevocationReceipt, GrantRevocationError> {
        #[cfg(not(target_arch = "wasm32"))]
        let bytes = self.send_native().await?;
        #[cfg(target_arch = "wasm32")]
        let bytes = browser::send(&self, None).await?;
        self.validate_receipt(&bytes)
    }

    /// Browser execution with explicit cancellation for a JavaScript caller.
    ///
    /// Ignoring a Promise does not cancel it. Abort the signal to stop waiting;
    /// abortion after dispatch does not prove that the server did not commit.
    /// # Errors
    /// Returns the same unacknowledged/preparation outcomes as [`Self::execute`].
    #[cfg(target_arch = "wasm32")]
    pub async fn execute_with_abort_signal(
        self,
        signal: Option<web_sys::AbortSignal>,
    ) -> Result<GrantRevocationReceipt, GrantRevocationError> {
        let bytes = browser::send(&self, signal).await?;
        self.validate_receipt(&bytes)
    }

    pub(super) async fn capture(
        credential: &GrantCredential,
        client: PubkyHttpClient,
        operation_id: RandomId,
    ) -> Result<Self, GrantRevocationError> {
        let state = credential.state.lock().await;
        let claims = &state.grant_claims;
        let session = &state.session;
        let now = now_unix();
        if state.bearer.is_empty()
            || session.token_expires_at <= now
            || claims.exp <= now
            || session.grant_id != claims.jti
            || session.pubky != claims.iss
            || session.client_id != claims.client_id
            || session.homeserver != state.homeserver_pk
        {
            return Err(GrantRevocationError::InvalidSnapshot);
        }
        Ok(Self {
            client,
            bearer: Zeroizing::new(state.bearer.clone()),
            binding: ConditionalGrantRevocation {
                operation_id,
                grant_id: claims.jti.clone(),
                pubky: claims.iss.clone(),
                client_id: claims.client_id.clone(),
            },
            homeserver: state.homeserver_pk.clone(),
        })
    }

    fn validate_receipt(
        &self,
        bytes: &[u8],
    ) -> Result<GrantRevocationReceipt, GrantRevocationError> {
        let unknown = GrantRevocationError::Unacknowledged { status: Some(200) };
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(unknown);
        }
        let receipt: GrantRevocationReceipt =
            serde_json::from_slice(bytes).map_err(|_error| unknown)?;
        if receipt.operation_id != self.binding.operation_id
            || receipt.grant_id != self.binding.grant_id
            || receipt.pubky != self.binding.pubky
            || receipt.client_id != self.binding.client_id
            || receipt.homeserver != self.homeserver
        {
            return Err(unknown);
        }
        Ok(receipt)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn send_native(&self) -> Result<Vec<u8>, GrantRevocationError> {
        let request = self
            .client
            .request_via_homeserver_once(&self.homeserver, &self.binding.pubky, PATH)
            .await
            .map_err(|_error| GrantRevocationError::Preparation)?;
        let mut response = request
            .bearer_auth(self.bearer.as_str())
            .json(&self.binding)
            .send()
            .await
            .map_err(|_error| GrantRevocationError::Unacknowledged { status: None })?;
        let status = response.status().as_u16();
        let unknown = GrantRevocationError::Unacknowledged {
            status: Some(status),
        };
        if status != 200 {
            return Err(unknown);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_error| unknown)? {
            if chunk.len() > MAX_RECEIPT_BYTES - bytes.len() {
                return Err(unknown);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

impl fmt::Debug for GrantRevocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantRevocation")
            .field("binding", &self.binding)
            .field("homeserver", &self.homeserver)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
