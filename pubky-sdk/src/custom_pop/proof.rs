use serde::{Deserialize, Serialize};

/// Domain separator for custom proofs, distinct from homeserver `PoP` tokens.
pub const CUSTOM_POP_JWS_TYP: &str = "pubky-custom-pop-v1";

/// Self-contained credentials: a root-signed grant and client-signed custom proof.
#[derive(Clone, Serialize, Deserialize)]
pub struct CustomPop {
    /// Original root-signed compact grant JWS.
    pub grant: String,
    /// Compact custom proof JWS signed by the client key bound in the grant.
    pub pop: String,
}

impl std::fmt::Debug for CustomPop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomPop").finish_non_exhaustive()
    }
}

/// Signed proof payload. SDK-owned metadata sits beside, never inside, application data.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustomPopClaims {
    /// Grant ID of the root-signed grant.
    pub gid: crate::GrantId,
    /// Unix seconds at which the client signed the proof.
    pub iat: u64,
    /// Random per-proof value applications can record for replay detection.
    pub nonce: crate::PopNonce,
    pub data: serde_json::Value,
}
