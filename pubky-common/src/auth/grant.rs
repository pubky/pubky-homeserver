//! Grant token claims type.
//!
//! A Grant is a user-signed JWS that authorizes a client to act on behalf
//! of the user with specific capabilities. This module provides the claims
//! type shared between Ring (signs), SDK (decodes), and homeserver (verifies).
//!
//! Parent grants use the same claims with the `pubky-parent-grant` JWS type.
//! [`ChildGrantClaims`] are signed by the parent's `cnf` key instead of the user.

use serde::{Deserialize, Serialize};

use crate::{
    auth::jws::{self, ClientId, GrantId},
    capabilities::Capability,
    crypto::PublicKey,
    keys::Keypair,
};

/// Grant JWS claims — the serializable JWS claims.
///
/// All public key fields use [`PublicKey`] (z32 string in JSON).
/// Capabilities use [`Capability`] (serializes as `"/scope:actions"` strings).
///
/// # JSON representation
/// ```json
/// {
///   "iss": "{user_pubky_z32}",
///   "client_id": "franky.pubky.app",
///   "caps": ["/pub/franky/:rw"],
///   "cnf": "{client_pubky_z32}",
///   "jti": "{grant_id}",
///   "iat": 1700000000,
///   "exp": 1731536000
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantClaims {
    /// User public key (grant signer).
    pub iss: PublicKey,
    /// Application identifier (domain string).
    pub client_id: ClientId,
    /// Authorized capabilities.
    pub caps: Vec<Capability>,
    /// Client public key for Proof-of-Possession.
    pub cnf: PublicKey,
    /// Grant ID (revocation target).
    pub jti: GrantId,
    /// Issued-at timestamp (Unix seconds).
    pub iat: u64,
    /// Expiry timestamp (Unix seconds).
    pub exp: u64,
}

impl GrantClaims {
    /// Decode a Grant JWS without verifying the signature.
    ///
    /// `compact` is a JWS Compact Serialization string (`header.payload.signature`).
    /// SDK uses this to inspect grant contents and check expiry
    /// without needing the signer's public key.
    pub fn decode(compact: &str) -> Result<Self, jws::Error> {
        jws::decode_jws_payload(compact)
    }

    /// Sign the GrantClaims as a JWS using the provided keypair.
    /// `jws_type` is the JWS "typ" header value (e.g. "pubky-grant").
    pub fn sign(&self, keypair: &Keypair, jws_type: &str) -> String {
        jws::sign_jws(keypair, jws_type, self)
    }
}

/// Child grant JWS claims: [`GrantClaims`] plus a reference to the parent.
///
/// `iss` names the authorized user, but the signature is verified against the
/// parent's `cnf` key rather than `iss`. `client_id` is the app's exact HTTPS
/// callback URL.
///
/// # JSON representation
/// ```json
/// {
///   "iss": "{user_pubky_z32}",
///   "client_id": "https://chat.example/auth/callback",
///   "caps": ["/pub/chat/v1/:rw", "/priv/chat/v1/:rwe"],
///   "cnf": "{app_pubky_z32}",
///   "jti": "{grant_id}",
///   "parent_jti": "{parent_grant_id}",
///   "iat": 1700000000,
///   "exp": 1731536000
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildGrantClaims {
    /// Claims shared with direct grants and parent grants.
    #[serde(flatten)]
    pub grant: GrantClaims,
    /// The `jti` of the parent grant.
    pub parent_jti: GrantId,
}

impl ChildGrantClaims {
    /// Decode a child grant JWS without verifying the signature.
    pub fn decode(compact: &str) -> Result<Self, jws::Error> {
        jws::decode_jws_payload(compact)
    }

    /// Sign the claims as a `pubky-child-grant` JWS with the parent's `cnf` key.
    pub fn sign(&self, parent_keypair: &Keypair) -> String {
        jws::sign_jws(parent_keypair, jws::CHILD_GRANT_JWS_TYP, self)
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    use crate::crypto::Keypair;

    use super::*;

    #[test]
    fn grant_claims_serde_roundtrip() {
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();

        let grant = GrantClaims {
            iss: user_kp.public_key(),
            client_id: ClientId::new("test.app").unwrap(),
            caps: vec![Capability::root()],
            cnf: client_kp.public_key(),
            jti: GrantId::generate(),
            iat: 1700000000,
            exp: 1731536000,
        };

        let json = serde_json::to_string(&grant).unwrap();
        let parsed: GrantClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(grant, parsed);
    }

    #[test]
    fn grant_claims_decode_from_jws() {
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();

        let grant = GrantClaims {
            iss: user_kp.public_key(),
            client_id: ClientId::new("test.app").unwrap(),
            caps: vec![Capability::root()],
            cnf: client_kp.public_key(),
            jti: GrantId::generate(),
            iat: 1700000000,
            exp: 1731536000,
        };

        // Construct a fake JWS compact string (header.payload.signature)
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"EdDSA\",\"typ\":\"pubky-grant\"}");
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&grant).unwrap());
        let compact = format!("{}.{}.fakesignature", header, payload);

        let decoded = GrantClaims::decode(&compact).unwrap();
        assert_eq!(decoded, grant);
    }

    #[test]
    fn child_grant_claims_use_flat_json() {
        let child = ChildGrantClaims {
            grant: GrantClaims {
                iss: Keypair::random().public_key(),
                client_id: ClientId::new("https://chat.example/auth/callback").unwrap(),
                caps: vec!["/priv/chat/:rwe".parse().unwrap()],
                cnf: Keypair::random().public_key(),
                jti: GrantId::generate(),
                iat: 1700000000,
                exp: 1731536000,
            },
            parent_jti: GrantId::generate(),
        };

        let compact = child.sign(&Keypair::random());
        assert_eq!(ChildGrantClaims::decode(&compact).unwrap(), child);

        let json = serde_json::to_value(&child).unwrap();
        assert_eq!(json["jti"], child.grant.jti.as_str());
        assert_eq!(json["parent_jti"], child.parent_jti.as_str());
    }
}
