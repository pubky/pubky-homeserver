//! Proof-of-Possession claims type.
//!
//! A PoP proof is a client-signed JWS that proves possession of the key bound
//! to a Grant's `cnf` claim. This module provides the claims type shared
//! between the SDK (signs) and homeserver (verifies).

use serde::{Deserialize, Serialize};

use crate::{
    auth::jws::{ClientId, GrantId, PopNonce},
    crypto::PublicKey,
};

/// Proof-of-Possession JWS claims — the serializable JWS claims.
///
/// # JSON representation
/// ```json
/// {
///   "aud": "{homeserver_pubkey_z32}",
///   "gid": "{grant_id}",
///   "nonce": "{random_nonce}",
///   "iat": 1700000000
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PopProofClaims {
    /// Target homeserver public key — prevents cross-homeserver replay.
    pub aud: PublicKey,
    /// Grant ID — binds proof to a specific Grant.
    pub gid: GrantId,
    /// Random value — prevents replay within time window.
    pub nonce: PopNonce,
    /// Issued-at timestamp (Unix seconds).
    pub iat: u64,
}

/// Proof that the holder of a parent grant's `cnf` key confirmed
/// reconnecting a blocked app.
///
/// `gid` is the parent's `jti` and `client_id` is the app's exact callback. The
/// `pubky-reconnect` JWS type binds the operation, so an ordinary PoP proof
/// cannot authorize it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconnectProofClaims {
    /// Homeserver, parent, nonce and timestamp bindings.
    #[serde(flatten)]
    pub pop: PopProofClaims,
    /// The app callback to unblock.
    pub client_id: ClientId,
}

#[cfg(test)]
mod tests {
    use crate::{
        auth::jws::{GrantId, PopNonce},
        crypto::Keypair,
    };

    use super::*;

    #[test]
    fn pop_proof_claims_serde_roundtrip() {
        let homeserver_kp = Keypair::random();
        let claims = PopProofClaims {
            aud: homeserver_kp.public_key(),
            gid: GrantId::generate(),
            nonce: PopNonce::generate(),
            iat: 1_700_000_000,
        };

        let json = serde_json::to_string(&claims).unwrap();
        let parsed: PopProofClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(claims, parsed);
    }
}
