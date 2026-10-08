use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::crypto::Signature;
use serde::{Deserialize, de::DeserializeOwned};
use std::time::Duration;

use super::{CUSTOM_POP_JWS_TYP, CustomPop, CustomPopClaims};
use crate::{GRANT_JWS_TYP, GrantClaims, PopNonce, PublicKey};

/// Default allowance for a grant issuer's clock being ahead of the verifier.
/// Grant expiry is never extended.
pub const DEFAULT_CUSTOM_POP_CLOCK_SKEW: Duration = Duration::from_secs(30);

/// Verified provenance and application data. This does not establish freshness
/// or application authorization and does not check homeserver revocation.
#[derive(Debug)]
pub struct VerifiedCustomPop {
    grant_claims: GrantClaims,
    iat: u64,
    nonce: PopNonce,
    data: serde_json::Value,
}

impl VerifiedCustomPop {
    /// Root-signed grant claims. Storage capabilities do not grant service permissions.
    #[must_use]
    pub const fn grant_claims(&self) -> &GrantClaims {
        &self.grant_claims
    }

    /// Root identity on whose behalf the client signed the data.
    #[must_use]
    pub const fn identity(&self) -> &PublicKey {
        &self.grant_claims.iss
    }

    /// Unix seconds at which the client signed the proof. The verifier only bounds
    /// it by the clock-skew allowance and the grant's validity; apply your own max age.
    #[must_use]
    pub const fn iat(&self) -> u64 {
        self.iat
    }

    /// Random per-proof value. Record it until grant expiry to detect replays.
    #[must_use]
    pub const fn nonce(&self) -> &PopNonce {
        &self.nonce
    }

    /// Signed application data; the caller must validate its meaning.
    #[must_use]
    pub const fn data(&self) -> &serde_json::Value {
        &self.data
    }
}

/// Failures in custom proof framing, signatures, grant binding, or validity.
#[derive(Debug, thiserror::Error)]
pub enum CustomPopVerificationError {
    /// Invalid compact JWS, base64url, or claims.
    #[error("Malformed custom proof credentials")]
    MalformedCredential,
    /// Only `EdDSA` and the expected grant/custom-proof type are supported.
    #[error("Unsupported JWS header")]
    UnsupportedHeader,
    /// The grant was not signed by its claimed root identity.
    #[error("Invalid grant signature")]
    InvalidGrantSignature,
    /// The proof was not signed by the grant's client key.
    #[error("Invalid proof signature")]
    InvalidProofSignature,
    /// The grant's issue time must precede its expiry.
    #[error("Invalid grant validity period")]
    InvalidGrant,
    /// The grant has reached its expiry timestamp.
    #[error("Grant has expired")]
    GrantExpired,
    /// The grant's issue timestamp exceeds the configured future-clock allowance.
    #[error("Grant is not yet valid")]
    GrantNotYetValid,
    /// The proof's issue timestamp exceeds the configured future-clock allowance.
    #[error("Proof is not yet valid")]
    ProofNotYetValid,
    /// The proof's issue timestamp lies outside the grant's validity period.
    #[error("Proof was issued outside the grant validity period")]
    ProofOutsideGrantValidity,
    /// The proof references a different grant.
    #[error("Proof grant ID does not match the supplied grant")]
    GrantMismatch,
    /// Local time is before the Unix epoch.
    #[error("System clock is before the Unix epoch")]
    InvalidClock,
}

/// Verify both signatures, the grant binding, and grant validity without network access.
///
/// Accepts a grant `iat <= now + clock_skew` while always requiring `now < exp` and
/// `iat < exp`. The proof `iat` must satisfy `iat <= now + clock_skew` and
/// `grant.iat <= iat + clock_skew` and `iat < grant.exp`; no maximum proof age is
/// enforced. The allowance is truncated to whole seconds; zero disables it.
/// Pass [`DEFAULT_CUSTOM_POP_CLOCK_SKEW`] for the recommended 30-second allowance.
/// It applies only to the grant, not timestamps in application data.
/// Applications own input size limits, data validation, replay protection, and
/// authorization. Repeated verification is allowed until grant expiry.
///
/// # Errors
/// Returns [`CustomPopVerificationError`] for invalid credentials or local time.
pub fn verify_custom_grant_pop(
    credentials: &CustomPop,
    clock_skew: Duration,
) -> Result<VerifiedCustomPop, CustomPopVerificationError> {
    let now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_err(|_error| CustomPopVerificationError::InvalidClock)?
        .as_secs();
    verify_at(credentials, now, clock_skew.as_secs())
}

fn verify_at(
    credentials: &CustomPop,
    now: u64,
    clock_skew_seconds: u64,
) -> Result<VerifiedCustomPop, CustomPopVerificationError> {
    use CustomPopVerificationError as Error;
    let grant_jws = ParsedJws::parse(&credentials.grant, GRANT_JWS_TYP)?;
    let grant: GrantClaims = grant_jws.claims()?;
    grant
        .iss
        .verify(grant_jws.signing_input.as_bytes(), &grant_jws.signature)
        .map_err(|_error| Error::InvalidGrantSignature)?;
    let proof_jws = ParsedJws::parse(&credentials.pop, CUSTOM_POP_JWS_TYP)?;
    grant
        .cnf
        .verify(proof_jws.signing_input.as_bytes(), &proof_jws.signature)
        .map_err(|_error| Error::InvalidProofSignature)?;
    let proof: CustomPopClaims = proof_jws.claims()?;
    if proof.gid != grant.jti {
        return Err(Error::GrantMismatch);
    }
    if grant.iat >= grant.exp {
        return Err(Error::InvalidGrant);
    }
    if now >= grant.exp {
        return Err(Error::GrantExpired);
    }
    if now.saturating_add(clock_skew_seconds) < grant.iat {
        return Err(Error::GrantNotYetValid);
    }
    if now.saturating_add(clock_skew_seconds) < proof.iat {
        return Err(Error::ProofNotYetValid);
    }
    if proof.iat.saturating_add(clock_skew_seconds) < grant.iat || proof.iat >= grant.exp {
        return Err(Error::ProofOutsideGrantValidity);
    }
    Ok(VerifiedCustomPop {
        grant_claims: grant,
        iat: proof.iat,
        nonce: proof.nonce,
        data: proof.data,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
}

/// Verify the original compact bytes rather than reserializing signed JSON.
struct ParsedJws<'a> {
    signing_input: &'a str,
    payload: Vec<u8>,
    signature: Signature,
}

impl<'a> ParsedJws<'a> {
    fn parse(compact: &'a str, expected_type: &str) -> Result<Self, CustomPopVerificationError> {
        use CustomPopVerificationError::{MalformedCredential, UnsupportedHeader};
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

    fn claims<T: DeserializeOwned>(&self) -> Result<T, CustomPopVerificationError> {
        serde_json::from_slice(&self.payload)
            .map_err(|_error| CustomPopVerificationError::MalformedCredential)
    }
}

#[cfg(test)]
#[path = "verifier_tests.rs"]
mod tests;
