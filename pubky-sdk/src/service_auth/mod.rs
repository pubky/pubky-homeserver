//! External-service credentials and optional native verification with replay protection.
//!
//! Enable `service-auth-verifier` to use `ServiceAuthVerifier` on native targets.
//! The application owns authorization and the resulting service session.
//!
//! ```no_run
//! # #[cfg(all(feature = "service-auth-verifier", not(target_arch = "wasm32")))]
//! # async fn example(credentials: pubky::ServiceAuthProof) -> Result<(), Box<dyn std::error::Error>> {
//! use pubky::service_auth::{MemoryReplayStore, ServiceAuthVerifier, VerificationPolicy};
//! let verifier = ServiceAuthVerifier::new(
//!     "inbox:production", VerificationPolicy::default(), MemoryReplayStore::new(10_000)?,
//! )?;
//! let authenticated = verifier.verify_and_consume(&credentials).await?;
//! // Authorize authenticated.identity() and cap the service session at
//! // authenticated.grant_expires_at(). Keep the verifier between requests.
//! # Ok(()) }
//! ```

use serde::{Deserialize, Serialize};

/// JWS type for external proofs, distinct from homeserver `pubky-pop` proofs.
pub const SERVICE_POP_JWS_TYP: &str = "pubky-service-pop-v1";

/// Credentials submitted to an external service for a single exchange attempt.
///
/// Treat these strings as sensitive credentials; generate a fresh proof on retry.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAuthProof {
    /// Original root-signed compact grant JWS.
    pub grant: String,
    /// Audience-bound compact proof JWS signed by the grant's client key.
    pub pop: String,
}

impl std::fmt::Debug for ServiceAuthProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAuthProof").finish_non_exhaustive()
    }
}

/// Decoded external proof claims. Deserialization alone does not verify a proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceProofClaims {
    /// Opaque audience, compared exactly without normalization.
    pub aud: String,
    /// Identifier of the supplied grant.
    pub gid: crate::GrantId,
    /// 32 random bytes encoded as unpadded base64url.
    pub nonce: String,
    /// Issue time in Unix seconds.
    pub iat: u64,
}

pub(crate) fn valid_audience(audience: &str) -> bool {
    !audience.is_empty() && audience.len() <= 1024
}

#[cfg(all(feature = "service-auth-verifier", not(target_arch = "wasm32")))]
mod file_store;
#[cfg(all(feature = "service-auth-verifier", not(target_arch = "wasm32")))]
mod memory_store;
#[cfg(all(feature = "service-auth-verifier", not(target_arch = "wasm32")))]
mod replay_store;
#[cfg(all(feature = "service-auth-verifier", not(target_arch = "wasm32")))]
mod verifier;

#[cfg(all(feature = "service-auth-verifier", not(target_arch = "wasm32")))]
pub use file_store::{FileReplayStore, FileReplayStoreOptions};
#[cfg(all(feature = "service-auth-verifier", not(target_arch = "wasm32")))]
pub use memory_store::MemoryReplayStore;
#[cfg(all(feature = "service-auth-verifier", not(target_arch = "wasm32")))]
pub use replay_store::{ConsumeOutcome, ReplayKey, ReplayRequest, ReplayStore, ReplayStoreError};
#[cfg(all(feature = "service-auth-verifier", not(target_arch = "wasm32")))]
pub use verifier::{
    ServiceAuthVerificationError, ServiceAuthVerifier, VerificationPolicy, VerifiedServiceAuth,
};
