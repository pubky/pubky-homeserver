//! JWS parsing and Ed25519 verification helpers.
//!
//! Bridges pubky-common's raw Ed25519 public keys to the `jsonwebtoken` verifier.
//! Signing is handled by `pubky-common`.

use std::fmt;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use pubky_common::crypto::PublicKey;
use serde::{Deserialize, Deserializer};

// ── JWS Compact Serialization ────────────────────────────────────────────────

/// A JWS Compact Serialization string (RFC 7515 §7.1).
///
/// Three base64url-encoded segments separated by dots: `header.payload.signature`.
/// Validated on construction to contain exactly three dot-separated parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JwsCompact(String);

impl JwsCompact {
    /// Parse a string into a [`JwsCompact`], validating the three-part structure.
    pub fn parse(s: &str) -> Result<Self, JwsCompactError> {
        if s.splitn(4, '.').count() != 3 {
            return Err(JwsCompactError);
        }
        Ok(Self(s.to_string()))
    }

    /// Returns the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JwsCompact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for JwsCompact {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Error returned when a string is not a valid JWS Compact Serialization.
#[derive(Debug)]
pub struct JwsCompactError;

impl fmt::Display for JwsCompactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JWS Compact Serialization must have exactly 3 dot-separated parts")
    }
}

impl std::error::Error for JwsCompactError {}

// ── Key conversion ───────────────────────────────────────────────────────────

/// Fixed ASN.1 prefix for Ed25519 SPKI public keys (RFC 8410).
/// Structure: SEQUENCE { AlgorithmIdentifier { Ed25519 }, BIT STRING { pubkey } }
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Create a `jsonwebtoken` [`DecodingKey`] from a pubky [`PublicKey`].
pub fn decoding_key(pubkey: &PublicKey) -> DecodingKey {
    let pem = ed25519_pubkey_to_pem(pubkey.as_bytes());
    DecodingKey::from_ed_pem(pem.as_bytes())
        .expect("invariant: PEM is constructed from valid Ed25519 key bytes")
}

/// Create a [`Validation`] configured for EdDSA without default claim checks.
///
/// Disables `iss`, `sub`, and `aud` validation — those are checked manually
/// in each verifier with domain-specific logic.
pub fn eddsa_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    validation
}

/// Encode an Ed25519 public key as SPKI PEM.
fn ed25519_pubkey_to_pem(pubkey: &[u8; 32]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let mut der = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
    der.extend_from_slice(&ED25519_SPKI_PREFIX);
    der.extend_from_slice(pubkey);

    let b64 = STANDARD.encode(&der);
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        b64
    )
}

#[cfg(test)]
mod tests {
    use pubky_common::{auth::jws::sign_jws, crypto::Keypair};

    use super::*;

    #[test]
    fn pubky_common_sign_jws_round_trips_through_jsonwebtoken_decode() {
        // The SDK signs with raw ed25519-dalek via `pubky_common::auth::jws::sign_jws`,
        // while the homeserver verifies with `jsonwebtoken` + PEM-wrapped keys. This
        // proves the two sides agree on the byte-level JWS Compact format (RFC 7515 +
        // RFC 8037). If this test ever breaks, the SDK and homeserver would silently
        // disagree on signature shape — a critical interop bug.
        let kp = Keypair::random();
        let claims = serde_json::json!({"sub": "interop", "exp": 9_999_999_999u64});
        let compact = sign_jws(&kp, "test-jws", &claims);

        let dec = decoding_key(&kp.public_key());
        let validation = eddsa_validation();
        let decoded: jsonwebtoken::TokenData<serde_json::Value> =
            jsonwebtoken::decode(&compact, &dec, &validation).unwrap();
        assert_eq!(decoded.claims["sub"], "interop");
        assert_eq!(decoded.header.typ.as_deref(), Some("test-jws"));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let keypair = Keypair::random();
        let wrong_keypair = Keypair::random();

        let wrong_dec = decoding_key(&wrong_keypair.public_key());

        let claims = serde_json::json!({"sub": "test"});
        let token = sign_jws(&keypair, "test-jws", &claims);

        let validation = eddsa_validation();
        let result = jsonwebtoken::decode::<serde_json::Value>(&token, &wrong_dec, &validation);

        assert!(result.is_err());
    }
}
