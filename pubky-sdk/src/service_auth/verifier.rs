//! Strict credential verification followed by atomic replay consumption.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::crypto::{Hasher, Signature};
use serde::{
    Deserialize,
    de::{DeserializeOwned, MapAccess, Visitor},
};

use super::replay_store::{
    ConsumeOutcome, ReplayKey, ReplayRequest, ReplayStore, ReplayStoreError, now_unix,
};
use super::{SERVICE_POP_JWS_TYP, ServiceAuthProof, ServiceProofClaims, valid_audience};
use crate::{ClientId, GRANT_JWS_TYP, GrantClaims, GrantId, PublicKey};

/// Explicit local acceptance policy, bound to replay storage on use.
/// Stop exchanges and drain the old/new acceptance windows before replacing a
/// store to change policy; immediately resetting replay history permits replay.
#[derive(Clone, Debug)]
pub struct VerificationPolicy {
    /// Proof age in seconds; acceptance ends strictly before `iat + max_proof_age_seconds`.
    pub max_proof_age_seconds: u64,
    /// Maximum future offset for grant/proof issue timestamps, inclusive.
    pub future_clock_skew_seconds: u64,
    /// Maximum bytes in the compact grant JWS (before decoding).
    pub max_grant_bytes: usize,
    /// Maximum bytes in the compact proof JWS (before decoding).
    pub max_proof_bytes: usize,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            max_proof_age_seconds: 180,
            future_clock_skew_seconds: 30,
            max_grant_bytes: 64 * 1024,
            max_proof_bytes: 16 * 1024,
        }
    }
}

/// Authentication result produced after both signatures, claim bindings, and
/// time checks pass and the nonce has been consumed.
/// Services must apply their own authorization policy and cap sessions at `grant_expires_at`.
#[derive(Debug)]
pub struct VerifiedServiceAuth {
    grant_claims: GrantClaims,
    proof_claims: ServiceProofClaims,
}

impl VerifiedServiceAuth {
    /// Verified root-signed grant claims.
    ///
    /// Verified provenance does not imply external-service authorization:
    /// homeserver storage capabilities do not grant service-specific permissions.
    #[must_use]
    pub const fn grant_claims(&self) -> &GrantClaims {
        &self.grant_claims
    }

    /// Verified audience-bound proof claims, for auditing or request correlation.
    ///
    /// The nonce has already been consumed. Callers need no additional replay
    /// check; retaining these claims does not make the proof reusable.
    #[must_use]
    pub const fn proof_claims(&self) -> &ServiceProofClaims {
        &self.proof_claims
    }

    /// Verified root identity on whose behalf the client acts.
    #[must_use]
    pub const fn identity(&self) -> &PublicKey {
        &self.grant_claims.iss
    }
    /// Root-signed application identifier; not a verified web origin.
    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        &self.grant_claims.client_id
    }
    /// Identifier of the verified grant.
    #[must_use]
    pub const fn grant_id(&self) -> &GrantId {
        &self.grant_claims.jti
    }
    /// Unix seconds at which the grant expires, without grace.
    #[must_use]
    pub const fn grant_expires_at(&self) -> u64 {
        self.grant_claims.exp
    }
}

/// Failures from external-service verification, separate from SDK login errors.
#[derive(Debug, thiserror::Error)]
pub enum ServiceAuthVerificationError {
    /// Configured or supplied audience is not 1–1024 UTF-8 bytes.
    #[error("Invalid service audience")]
    InvalidAudience,
    /// Zero or unreasonable policy bounds were configured.
    #[error("Invalid verification policy")]
    InvalidPolicy,
    /// Compact credential exceeded the configured byte limit.
    #[error("Credential exceeds the input size limit")]
    InputTooLarge,
    /// JWS structure, base64url, JSON, required fields, or duplicate fields are invalid.
    #[error("Malformed service credential")]
    MalformedCredential,
    /// Only `EdDSA` with the expected type and no header extensions is supported.
    #[error("Unsupported JWS header")]
    UnsupportedHeader,
    /// Grant signature does not verify against its claimed issuer.
    #[error("Invalid grant signature")]
    InvalidGrantSignature,
    /// Proof signature does not verify against the grant's bound client key.
    #[error("Invalid proof signature")]
    InvalidProofSignature,
    /// The grant's issue/expiry ordering is invalid.
    #[error("Invalid grant validity period")]
    InvalidGrant,
    /// The grant has reached its expiration timestamp.
    #[error("Grant has expired")]
    GrantExpired,
    /// Proof or grant issue time is outside the acceptance window.
    #[error("Invalid credential timestamp")]
    InvalidTimestamp,
    /// The proof targets another service audience.
    #[error("Proof audience does not match this service")]
    AudienceMismatch,
    /// The proof references another grant.
    #[error("Proof grant ID does not match the supplied grant")]
    GrantMismatch,
    /// Nonce is not exactly 32 bytes in canonical unpadded base64url.
    #[error("Invalid proof nonce")]
    InvalidNonce,
    /// The proof was previously consumed.
    #[error("Proof was already consumed")]
    Replay,
    /// Replay protection could not safely consume the proof.
    #[error("Replay protection failed: {0}")]
    Storage(#[from] ReplayStoreError),
}

/// Verifies credentials and consumes their nonce before returning an identity.
///
/// Clones use the store's clone semantics; built-in stores share their state.
/// A failed, canceled, or ambiguous exchange may consume the proof. Retry with
/// fresh credentials. Verification does not contact the homeserver or other services.
#[derive(Clone, Debug)]
pub struct ServiceAuthVerifier<S> {
    audience: String,
    policy: VerificationPolicy,
    policy_fingerprint: [u8; 32],
    store: S,
}

impl<S: ReplayStore> ServiceAuthVerifier<S> {
    /// Configure an audience, acceptance policy, and replay store.
    ///
    /// # Errors
    /// Rejects invalid audiences, zero input limits, or time windows over one day.
    pub fn new(
        audience: impl Into<String>,
        policy: VerificationPolicy,
        store: S,
    ) -> Result<Self, ServiceAuthVerificationError> {
        let audience = audience.into();
        if !valid_audience(&audience) {
            return Err(ServiceAuthVerificationError::InvalidAudience);
        }
        if policy.max_proof_age_seconds == 0
            || policy.max_proof_age_seconds > 86_400
            || policy.future_clock_skew_seconds > 86_400
            || policy.max_grant_bytes == 0
            || policy.max_proof_bytes == 0
        {
            return Err(ServiceAuthVerificationError::InvalidPolicy);
        }
        let policy_fingerprint = fingerprint(&[
            SERVICE_POP_JWS_TYP.as_bytes(),
            audience.as_bytes(),
            &policy.max_proof_age_seconds.to_be_bytes(),
            &policy.future_clock_skew_seconds.to_be_bytes(),
            &(policy.max_grant_bytes as u64).to_be_bytes(),
            &(policy.max_proof_bytes as u64).to_be_bytes(),
        ]);
        Ok(Self {
            audience,
            policy,
            policy_fingerprint,
            store,
        })
    }

    /// Authenticate an exchange and atomically consume its nonce.
    ///
    /// # Errors
    /// Rejects invalid signatures, fields, timestamps, bindings, replay, and
    /// storage failures. Invalid credentials do not allocate replay entries.
    pub async fn verify_and_consume(
        &self,
        credentials: &ServiceAuthProof,
    ) -> Result<VerifiedServiceAuth, ServiceAuthVerificationError> {
        if credentials.grant.len() > self.policy.max_grant_bytes
            || credentials.pop.len() > self.policy.max_proof_bytes
        {
            return Err(ServiceAuthVerificationError::InputTooLarge);
        }
        let grant_jws = ParsedJws::parse(&credentials.grant, GRANT_JWS_TYP)?;
        let grant: GrantClaims =
            grant_jws.claims(&["iss", "client_id", "caps", "cnf", "jti", "iat", "exp"])?;
        grant
            .iss
            .verify(grant_jws.signing_input.as_bytes(), &grant_jws.signature)
            .map_err(|_error| ServiceAuthVerificationError::InvalidGrantSignature)?;

        let proof_jws = ParsedJws::parse(&credentials.pop, SERVICE_POP_JWS_TYP)?;
        let proof: ServiceProofClaims = proof_jws.claims(&["aud", "gid", "nonce", "iat"])?;
        grant
            .cnf
            .verify(proof_jws.signing_input.as_bytes(), &proof_jws.signature)
            .map_err(|_error| ServiceAuthVerificationError::InvalidProofSignature)?;
        if !valid_audience(&proof.aud) {
            return Err(ServiceAuthVerificationError::InvalidAudience);
        }
        if proof.aud != self.audience {
            return Err(ServiceAuthVerificationError::AudienceMismatch);
        }
        if proof.gid != grant.jti {
            return Err(ServiceAuthVerificationError::GrantMismatch);
        }
        if proof.nonce.len() != 43
            || URL_SAFE_NO_PAD
                .decode(&proof.nonce)
                .map_or(true, |bytes| bytes.len() != 32)
        {
            return Err(ServiceAuthVerificationError::InvalidNonce);
        }
        let (not_before, expires_at) = self.time_bounds(&grant, &proof, now_unix()?)?;
        let key = fingerprint(&[
            grant.iss.as_bytes(),
            grant.jti.as_str().as_bytes(),
            proof.aud.as_bytes(),
            proof.nonce.as_bytes(),
        ]);
        let request = ReplayRequest {
            key: ReplayKey(key),
            not_before,
            expires_at,
            policy: self.policy_fingerprint,
        };
        if self.store.consume_once(request).await? == ConsumeOutcome::AlreadyConsumed {
            return Err(ServiceAuthVerificationError::Replay);
        }
        // A slow disk flush may cross the expiry boundary after the store's check.
        self.time_bounds(&grant, &proof, now_unix()?)?;
        Ok(VerifiedServiceAuth {
            grant_claims: grant,
            proof_claims: proof,
        })
    }

    fn time_bounds(
        &self,
        grant: &GrantClaims,
        proof: &ServiceProofClaims,
        now: u64,
    ) -> Result<(u64, u64), ServiceAuthVerificationError> {
        if grant.iat >= grant.exp {
            return Err(ServiceAuthVerificationError::InvalidGrant);
        }
        if now >= grant.exp {
            return Err(ServiceAuthVerificationError::GrantExpired);
        }
        let skew = self.policy.future_clock_skew_seconds;
        let not_before = grant.iat.max(proof.iat).saturating_sub(skew);
        let proof_end = proof
            .iat
            .checked_add(self.policy.max_proof_age_seconds)
            .ok_or(ServiceAuthVerificationError::InvalidTimestamp)?;
        let expires_at = grant.exp.min(proof_end);
        if now < not_before
            || now >= expires_at
            || proof.iat >= grant.exp
            || proof.iat < grant.iat.saturating_sub(skew)
        {
            return Err(ServiceAuthVerificationError::InvalidTimestamp);
        }
        Ok((not_before, expires_at))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
}

/// Parsed compact framing; signatures always cover the original, unmodified bytes.
struct ParsedJws<'a> {
    signing_input: &'a str,
    payload: Vec<u8>,
    signature: Signature,
}

impl<'a> ParsedJws<'a> {
    fn parse(compact: &'a str, expected_type: &str) -> Result<Self, ServiceAuthVerificationError> {
        use ServiceAuthVerificationError::{MalformedCredential, UnsupportedHeader};
        let mut parts = compact.split('.');
        let header = parts.next().ok_or(MalformedCredential)?;
        let payload = parts.next().ok_or(MalformedCredential)?;
        let signature = parts.next().ok_or(MalformedCredential)?;
        if parts.next().is_some()
            || header.is_empty()
            || header.len() > 512
            || payload.is_empty()
            || signature.len() != 86
        {
            return Err(MalformedCredential);
        }
        let header = URL_SAFE_NO_PAD
            .decode(header)
            .map_err(|_error| MalformedCredential)?;
        let header: Header = serde_json::from_slice(&header).map_err(|_error| UnsupportedHeader)?;
        if header.alg != "EdDSA" || header.typ != expected_type {
            return Err(UnsupportedHeader);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_error| MalformedCredential)?;
        let signature = Signature::from_slice(&signature).map_err(|_error| MalformedCredential)?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_error| MalformedCredential)?;
        let (signing_input, _) = compact.rsplit_once('.').ok_or(MalformedCredential)?;
        Ok(Self {
            signing_input,
            payload,
            signature,
        })
    }

    fn claims<T: DeserializeOwned>(
        &self,
        allowed_fields: &[&str],
    ) -> Result<T, ServiceAuthVerificationError> {
        let object: UniqueClaims = serde_json::from_slice(&self.payload)
            .map_err(|_error| ServiceAuthVerificationError::MalformedCredential)?;
        if object
            .0
            .keys()
            .any(|key| !allowed_fields.contains(&key.as_str()))
        {
            return Err(ServiceAuthVerificationError::MalformedCredential);
        }
        serde_json::from_value(serde_json::Value::Object(object.0))
            .map_err(|_error| ServiceAuthVerificationError::MalformedCredential)
    }
}

/// Reject duplicate top-level claims before converting into existing SDK types.
/// Accepted claim schemas contain only scalars and arrays of strings, not objects.
struct UniqueClaims(serde_json::Map<String, serde_json::Value>);

impl<'de> Deserialize<'de> for UniqueClaims {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ClaimsVisitor;
        impl<'de> Visitor<'de> for ClaimsVisitor {
            type Value = UniqueClaims;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("claims with unique field names")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut claims = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if claims.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate claim"));
                    }
                }
                Ok(UniqueClaims(claims))
            }
        }
        deserializer.deserialize_map(ClaimsVisitor)
    }
}

/// Length-prefix fields so distinct tuples cannot share the same hash input.
fn fingerprint(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    for field in fields {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
#[path = "verifier_tests.rs"]
mod tests;
