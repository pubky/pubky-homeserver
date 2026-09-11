//! Grant verification with full Ed25519 signature check.
//!
//! Verifies a Grant JWS compact string, extracting and validating all claims.
//! Homeserver-only — the SDK only decodes grants without verification.
//!
//! Pubky Ring creates these grants to give the SDKs the necessary information to authenticate and authorize requests to the homeserver.
//! The homeserver verifies the grant and returns a short-lived access token for API calls.

use pubky_common::{
    auth::{grant::GrantClaims, jws::GRANT_JWS_TYP},
    crypto::PublicKey,
};

use super::jws_crypto::{self, JwsCompact};

/// Verify a Grant JWS Compact Serialization string.
///
/// Checks:
/// 1. Header `typ` is `"pubky-grant"` and `alg` is `EdDSA`
/// 2. Ed25519 signature is valid against the `iss` public key
/// 3. Grant has not expired
/// 4. All required fields are present and valid
pub fn verify_grant(compact: &JwsCompact) -> Result<GrantClaims, Error> {
    let issuer_key = extract_issuer_key(compact.as_str())?;
    let claims = verify_signature(compact.as_str(), &issuer_key)?;
    check_header_type(compact.as_str())?;
    check_expiry(&claims)?;
    Ok(claims)
}

/// Extract the `iss` claim from the JWS payload without verifying the signature.
/// Needed because we must know the public key before we can verify.
fn extract_issuer_key(compact: &str) -> Result<PublicKey, Error> {
    let raw = GrantClaims::decode(compact).map_err(|_| Error::InvalidFormat)?;
    Ok(raw.iss)
}

/// Verify the JWS signature against the issuer's public key.
fn verify_signature(compact: &str, issuer_key: &PublicKey) -> Result<GrantClaims, Error> {
    let decoding_key = jws_crypto::decoding_key(issuer_key);
    let validation = jws_crypto::eddsa_validation();
    let token_data = jsonwebtoken::decode::<GrantClaims>(compact, &decoding_key, &validation)
        .map_err(|_| Error::InvalidSignature)?;
    Ok(token_data.claims)
}

/// Check that the JWS header has `typ: "pubky-grant"`.
fn check_header_type(compact: &str) -> Result<(), Error> {
    let header = jsonwebtoken::decode_header(compact).map_err(|_| Error::InvalidFormat)?;
    match header.typ.as_deref() {
        Some(GRANT_JWS_TYP) => Ok(()),
        _ => Err(Error::InvalidHeaderType),
    }
}

/// Check that the grant has not expired.
fn check_expiry(raw: &GrantClaims) -> Result<(), Error> {
    let now = chrono::Utc::now().timestamp() as u64;
    if raw.exp <= now {
        return Err(Error::Expired);
    }
    Ok(())
}

/// Errors from Grant verification.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The JWS format is invalid or unparseable.
    #[error("invalid grant format")]
    InvalidFormat,

    /// The JWS header `typ` is not `"pubky-grant"`.
    #[error("invalid grant header type, expected pubky-grant")]
    InvalidHeaderType,

    /// The Ed25519 signature does not match the `iss` public key.
    #[error("invalid grant signature")]
    InvalidSignature,

    /// The grant has expired (`exp` is in the past).
    #[error("grant has expired")]
    Expired,
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use pubky_common::{
        auth::jws::{sign_jws, ClientId, GrantId},
        capabilities::Capability,
        crypto::Keypair,
    };

    use super::*;

    fn sign_raw_grant(keypair: &Keypair, raw: &GrantClaims) -> JwsCompact {
        let token = sign_jws(keypair, GRANT_JWS_TYP, raw);
        JwsCompact::parse(&token).unwrap()
    }

    fn make_valid_raw_grant(user_kp: &Keypair, client_kp: &Keypair) -> GrantClaims {
        let now = Utc::now().timestamp() as u64;
        GrantClaims {
            iss: user_kp.public_key(),
            client_id: ClientId::new("test.app").unwrap(),
            caps: vec![Capability::root()],
            cnf: client_kp.public_key(),
            jti: GrantId::generate(),
            iat: now,
            exp: now + 3600,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        // Interop check: verify the shared signer used by SDKs through the
        // homeserver's full grant verification pipeline.
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();
        let raw = make_valid_raw_grant(&user_kp, &client_kp);
        let compact = sign_raw_grant(&user_kp, &raw);

        let claims = verify_grant(&compact).unwrap();
        assert_eq!(claims.iss, user_kp.public_key());
        assert_eq!(claims.cnf, client_kp.public_key());
        assert_eq!(claims.client_id, raw.client_id);
        assert_eq!(claims.jti, raw.jti);
    }

    #[test]
    fn reject_wrong_signer() {
        let user_kp = Keypair::random();
        let wrong_kp = Keypair::random();
        let client_kp = Keypair::random();
        let raw = make_valid_raw_grant(&user_kp, &client_kp);

        // Sign with wrong key but claim iss is user_kp
        let compact = sign_raw_grant(&wrong_kp, &raw);
        let result = verify_grant(&compact);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn reject_expired_grant() {
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();
        let mut raw = make_valid_raw_grant(&user_kp, &client_kp);
        raw.exp = 1000; // far in the past

        let compact = sign_raw_grant(&user_kp, &raw);
        let result = verify_grant(&compact);
        assert!(matches!(result, Err(Error::Expired)));
    }

    #[test]
    fn reject_wrong_header_type() {
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();
        let raw = make_valid_raw_grant(&user_kp, &client_kp);

        // Sign with wrong typ header
        let token = sign_jws(&user_kp, "wrong-typ", &raw);
        let compact = JwsCompact::parse(&token).unwrap();

        let result = verify_grant(&compact);
        assert!(matches!(result, Err(Error::InvalidHeaderType)));
    }
}
