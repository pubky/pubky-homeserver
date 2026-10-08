//! Shared JWS encoding/decoding utilities and token identifier types.
//!
//! This module provides:
//! - JWS Compact Serialization signing for `EdDSA` (Ed25519)
//! - Lightweight JWS payload decoding (no signature verification)
//! - Typed identifiers for grants, tokens, nonces, and client IDs

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

use crate::crypto::{random_bytes, Keypair};

/// JWS header `typ` for Grant tokens.
pub const GRANT_JWS_TYP: &str = "pubky-grant";

/// JWS header `typ` for Proof-of-Possession proofs.
pub const POP_JWS_TYP: &str = "pubky-pop";

/// Maximum length for a [`RandomId`] generated from 128-bit random bytes as base64url.
const RANDOM_ID_MAX_LENGTH: usize = 22;

/// Maximum length for a [`ClientId`] (DNS domain name limit per RFC 1035).
const CLIENT_ID_MAX_LENGTH: usize = 253;

// ── JWS Encoding ────────────────────────────────────────────────────────────

/// Sign claims as a JWS Compact Serialization string with Ed25519 (EdDSA).
///
/// Implements RFC 7515 (JWS) + RFC 8037 (CFRG curves):
/// - Header: `{"alg":"EdDSA","typ":"<typ>"}`
/// - Payload: JSON-encoded `claims`
/// - Signature: Ed25519 over the ASCII bytes `b64url(header) || "." || b64url(payload)`
///
/// Returns the canonical compact form `<header>.<payload>.<signature>` so it can
/// be passed straight into the homeserver's JSON request body or any RFC-7515
/// JWS verifier (e.g. `jsonwebtoken::decode`).
pub fn sign_jws<T: Serialize>(keypair: &Keypair, typ: &str, claims: &T) -> String {
    let signing_input = jws_signing_input(typ, claims);
    let signature = keypair.sign(signing_input.as_bytes());
    finish_jws(signing_input, signature.to_bytes())
}

/// Build the canonical JWS signing input `base64url(header).base64url(payload)`.
///
/// This is useful for runtimes where the private key is held by an external
/// signer, such as WebCrypto, while keeping the JWS bytes identical to
/// [`sign_jws`].
pub fn jws_signing_input<T: Serialize>(typ: &str, claims: &T) -> String {
    let header = serde_json::json!({ "alg": "EdDSA", "typ": typ });
    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header)
            .expect("invariant: serde_json serialization of a static header object cannot fail"),
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(claims).expect("invariant: claims must be serde_json-serializable"),
    );

    format!("{header_b64}.{payload_b64}")
}

/// Finish compact JWS serialization from a signing input and raw signature.
/// Merges the signing input with the base64url-encoded signature to produce the final
/// JWS string. This is useful for runtimes where the signing step is separate from
/// the signing input construction, such as when using an external signer.
#[must_use]
pub fn finish_jws(signing_input: String, signature: impl AsRef<[u8]>) -> String {
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);
    format!("{signing_input}.{signature_b64}")
}

// ── JWS Decoding ────────────────────────────────────────────────────────────

/// Decode a JWS Compact Serialization string's payload WITHOUT signature verification.
///
/// `compact` is a JWS in Compact Serialization form (RFC 7515 §7.1):
/// three base64url-encoded segments separated by dots (`header.payload.signature`).
///
/// Splits on `.`, base64url-decodes the payload (second) segment,
/// and deserializes from JSON. Useful for the SDK to inspect token
/// contents and check expiry without needing the signer's public key.
pub fn decode_jws_payload<T: serde::de::DeserializeOwned>(compact: &str) -> Result<T, Error> {
    let parts: Vec<&str> = compact.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(Error::InvalidFormat(
            "JWS compact must have 3 dot-separated parts",
        ));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| Error::InvalidFormat("invalid base64url in JWS payload"))?;

    serde_json::from_slice(&payload_bytes).map_err(|e| Error::JsonParse(e.to_string()))
}

// ── RandomId ────────────────────────────────────────────────────────────────

/// A cryptographically random identifier, max 22 characters.
///
/// Uses base64url (22 chars for 128-bit).
/// Serde-transparent: serializes as a plain string in JSON.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RandomId(String);

impl RandomId {
    /// Generate a new random ID: 128-bit random bytes → base64url (22 chars).
    pub fn generate() -> Self {
        let bytes = random_bytes::<16>();
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Parse and validate an existing ID string.
    ///
    /// Must be non-empty, at most 22 characters, and contain only base64url characters.
    pub fn parse(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            return Err(Error::InvalidFormat("RandomId must not be empty"));
        }
        if s.len() > RANDOM_ID_MAX_LENGTH {
            return Err(Error::InvalidFormat(
                "RandomId must be at most 22 characters",
            ));
        }
        if !s
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(Error::InvalidFormat(
                "RandomId must contain only base64url characters",
            ));
        }
        Ok(Self(s.to_string()))
    }

    /// Returns the inner string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RandomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for RandomId {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<RandomId> for String {
    fn from(id: RandomId) -> Self {
        id.0
    }
}

/// Grant identifier — a [`RandomId`] used as the `jti` claim in a Grant JWS.
pub type GrantId = RandomId;

/// Proof-of-Possession nonce — a [`RandomId`] used to prevent PoP replay.
pub type PopNonce = RandomId;

// ── ClientId ────────────────────────────────────────────────────────────────

/// An application identifier, typically a domain string (e.g., `franky.pubky.app`).
///
/// Max 253 characters (DNS domain name limit per RFC 1035).
/// Serde-transparent: serializes as a plain string in JSON.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClientId(String);

impl ClientId {
    /// Create a new [`ClientId`], validating that it is non-empty and at most 253 characters.
    pub fn new(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            return Err(Error::InvalidFormat("ClientId must not be empty"));
        }
        if s.len() > CLIENT_ID_MAX_LENGTH {
            return Err(Error::InvalidFormat(
                "ClientId must be at most 253 characters",
            ));
        }
        Ok(Self(s.to_string()))
    }

    /// Returns the inner string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ClientId {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl TryFrom<&str> for ClientId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<ClientId> for String {
    fn from(id: ClientId) -> Self {
        id.0
    }
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Errors from JWS decoding and ID parsing.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The input format is invalid.
    #[error("{0}")]
    InvalidFormat(&'static str),

    /// JSON parsing failed.
    #[error("JSON parse error: {0}")]
    JsonParse(String),
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn try_into_test() {
        let domain = "example.com";
        let client_id: ClientId = domain.try_into().unwrap();
        assert_eq!(client_id.as_str(), domain);
    }

    #[test]
    fn random_id_generate_is_valid() {
        let id = RandomId::generate();
        assert!(!id.as_str().is_empty());
        assert!(id.as_str().len() <= RANDOM_ID_MAX_LENGTH);
        // base64url of 16 bytes = 22 chars
        assert_eq!(id.as_str().len(), 22);
    }

    #[test]
    fn random_id_uniqueness() {
        let a = RandomId::generate();
        let b = RandomId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn random_id_parse_valid() {
        RandomId::parse("abc123").unwrap();
        RandomId::parse("AZaz09-_").unwrap();
        RandomId::parse("a").unwrap(); // min length
    }

    #[test]
    fn random_id_parse_rejects_non_base64url_characters() {
        for value in [
            ".",
            "..",
            "../../../pub/a.txt",
            "a/b",
            "a?b",
            "a#b",
            "a+b",
            "a=b",
            "a b",
        ] {
            assert!(RandomId::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn random_id_parse_rejects_empty() {
        assert!(RandomId::parse("").is_err());
    }

    #[test]
    fn random_id_parse_rejects_too_long() {
        let long = "a".repeat(RANDOM_ID_MAX_LENGTH + 1);
        assert!(RandomId::parse(&long).is_err());
    }

    #[test]
    fn random_id_serde_roundtrip() {
        let id = RandomId::generate();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: RandomId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn client_id_valid() {
        ClientId::new("franky.pubky.app").unwrap();
        ClientId::new("a").unwrap();
    }

    #[test]
    fn client_id_rejects_empty() {
        assert!(ClientId::new("").is_err());
    }

    #[test]
    fn client_id_rejects_too_long() {
        let long = "a".repeat(CLIENT_ID_MAX_LENGTH + 1);
        assert!(ClientId::new(&long).is_err());
    }

    #[test]
    fn client_id_serde_roundtrip() {
        let id = ClientId::new("test.app").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: ClientId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn sign_jws_round_trips_through_decode_jws_payload() {
        let kp = Keypair::random();
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Claims {
            sub: String,
            iat: u64,
        }
        let claims = Claims {
            sub: "alice".into(),
            iat: 1_700_000_000,
        };
        let compact = sign_jws(&kp, "pubky-test", &claims);

        // Three dot-separated parts.
        assert_eq!(compact.matches('.').count(), 2);

        // Payload survives decode.
        let decoded: Claims = decode_jws_payload(&compact).unwrap();
        assert_eq!(decoded, claims);
    }

    #[test]
    fn sign_jws_signature_verifies_with_raw_ed25519() {
        let kp = Keypair::random();
        let claims = serde_json::json!({"foo": "bar"});
        let compact = sign_jws(&kp, "pubky-test", &claims);

        let mut parts = compact.splitn(3, '.');
        let header_b64 = parts.next().unwrap();
        let payload_b64 = parts.next().unwrap();
        let signature_b64 = parts.next().unwrap();
        let signing_input = format!("{header_b64}.{payload_b64}");

        let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).unwrap();
        assert_eq!(signature_bytes.len(), 64);
        let signature_arr: [u8; 64] = signature_bytes.try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&signature_arr);
        kp.public_key()
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature must verify against the keypair's public key");
    }

    #[test]
    fn sign_jws_header_contains_alg_and_typ() {
        let kp = Keypair::random();
        let compact = sign_jws(&kp, GRANT_JWS_TYP, &serde_json::json!({}));
        let header_b64 = compact.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], GRANT_JWS_TYP);
    }

    #[test]
    fn decode_jws_payload_valid() {
        // Manually construct a JWS-like string: header.payload.signature
        // Payload: {"sub":"hello"}
        let payload = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"hello\"}");
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"EdDSA\"}");
        let compact = format!("{}.{}.fakesig", header, payload);

        #[derive(Deserialize)]
        struct Claims {
            sub: String,
        }

        let claims: Claims = decode_jws_payload(&compact).unwrap();
        assert_eq!(claims.sub, "hello");
    }

    #[test]
    fn decode_jws_payload_rejects_malformed() {
        assert!(decode_jws_payload::<serde_json::Value>("not.a.valid.jws.toomanyparts").is_err());
        assert!(decode_jws_payload::<serde_json::Value>("only-one-part").is_err());
    }
}
