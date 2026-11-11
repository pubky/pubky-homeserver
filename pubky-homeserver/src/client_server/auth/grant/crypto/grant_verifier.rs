//! Grant verification with full Ed25519 signature check.
//!
//! Verifies Grant JWS compact strings, extracting and validating all claims.
//! Homeserver-only — the SDK only decodes grants without verification.
//!
//! Pubky Ring creates these grants to give the SDKs the necessary information to authenticate and authorize requests to the homeserver.
//! The homeserver verifies the grant and returns a short-lived access token for API calls.
//!
//! A chain has two levels: a parent signed by the user, and a child signed by the
//! parent's `cnf` key. JWS types keep the three grant forms apart:
//! a parent can't be exchanged for storage, and a child can't act as a parent.

use pubky_common::{
    auth::{
        grant::{
            caps_within, is_exact_callback, parent_grant_ceiling, ChildGrantClaims, GrantClaims,
        },
        jws::{CHILD_GRANT_JWS_TYP, GRANT_JWS_TYP, PARENT_GRANT_JWS_TYP},
    },
    capabilities::{Capabilities, Capability},
    crypto::PublicKey,
};
use serde::de::DeserializeOwned;

use super::{
    jws_crypto::{self, JwsCompact},
    pop_verifier::POP_MAX_AGE_SECS,
};

/// Maximum parent lifetime: 730 days, matching the SDK's default grant lifetime.
const MAX_PARENT_GRANT_LIFETIME_SECS: u64 = 2 * 365 * 24 * 3600;

/// A verified parent and child.
#[derive(Debug, Clone)]
pub struct GrantChain {
    pub parent: GrantClaims,
    pub child: ChildGrantClaims,
}

/// Verify a Grant JWS Compact Serialization string.
///
/// Checks:
/// 1. Header `typ` is `"pubky-grant"` and `alg` is `EdDSA`
/// 2. Ed25519 signature is valid against the `iss` public key
/// 3. Grant has not expired
/// 4. All required fields are present and valid
pub fn verify_grant(compact: &JwsCompact) -> Result<GrantClaims, Error> {
    let claims = verify_grant_for_revocation(compact)?;
    check_expiry(&claims)?;
    Ok(claims)
}

/// Verify the grant's signature and header, allowing expired grants for revocation.
pub fn verify_grant_for_revocation(compact: &JwsCompact) -> Result<GrantClaims, Error> {
    let issuer_key = extract_issuer_key(compact.as_str())?;
    verify_signed(compact.as_str(), &issuer_key, GRANT_JWS_TYP)
}

/// Verify a usable parent grant with a lifetime of at most 730 days.
pub fn verify_parent(compact: &JwsCompact) -> Result<GrantClaims, Error> {
    let parent = verify_parent_for_revocation(compact)?;
    check_parent_usable(&parent)?;
    Ok(parent)
}

/// Verify a parent grant, allowing expired or overlong parents for revocation.
///
/// Checks the user's signature, the type, the lifetime order, the callback, and
/// the parent ceiling.
pub fn verify_parent_for_revocation(compact: &JwsCompact) -> Result<GrantClaims, Error> {
    let issuer_key = extract_issuer_key(compact.as_str())?;
    let parent: GrantClaims = verify_signed(compact.as_str(), &issuer_key, PARENT_GRANT_JWS_TYP)?;
    if parent.iat >= parent.exp {
        return Err(Error::InvalidTimestamps);
    }
    check_callback(&parent)?;
    check_permitted(&parent_grant_ceiling(), &parent.caps)?;
    Ok(parent)
}

/// Verify a usable parent and child, enforcing the parent's maximum lifetime.
pub fn verify_chain(parent: &JwsCompact, child: &JwsCompact) -> Result<GrantChain, Error> {
    let chain = verify_chain_for_revocation(parent, child)?;
    check_parent_usable(&chain.parent)?;
    check_usable(&chain.child.grant)?;
    Ok(chain)
}

/// Verify a parent and child, allowing expired grants and overlong parents for revocation.
///
/// The child must be signed by the parent's `cnf` key, name the same user and
/// parent, satisfy `parent.iat <= child.iat < child.exp <= parent.exp`, and stay
/// within the parent's capabilities.
pub fn verify_chain_for_revocation(
    parent: &JwsCompact,
    child: &JwsCompact,
) -> Result<GrantChain, Error> {
    let parent = verify_parent_for_revocation(parent)?;
    let child: ChildGrantClaims = verify_signed(child.as_str(), &parent.cnf, CHILD_GRANT_JWS_TYP)?;
    if child.grant.iss != parent.iss || child.parent_jti != parent.jti {
        return Err(Error::ParentMismatch);
    }
    if !(parent.iat <= child.grant.iat
        && child.grant.iat < child.grant.exp
        && child.grant.exp <= parent.exp)
    {
        return Err(Error::InvalidTimestamps);
    }
    check_callback(&child.grant)?;
    check_permitted(&parent.caps.clone().into(), &child.grant.caps)?;
    Ok(GrantChain { parent, child })
}

/// Whether `compact` has the `pubky-parent-grant` type, without verifying it.
pub fn is_parent_grant(compact: &JwsCompact) -> bool {
    jsonwebtoken::decode_header(compact.as_str())
        .is_ok_and(|header| header.typ.as_deref() == Some(PARENT_GRANT_JWS_TYP))
}

/// Extract the `iss` claim from the JWS payload without verifying the signature.
/// Needed because we must know the public key before we can verify.
fn extract_issuer_key(compact: &str) -> Result<PublicKey, Error> {
    let raw = GrantClaims::decode(compact).map_err(|_| Error::InvalidFormat)?;
    Ok(raw.iss)
}

/// Verify the JWS signature against `key`, then its `typ` header.
fn verify_signed<T: DeserializeOwned>(
    compact: &str,
    key: &PublicKey,
    typ: &'static str,
) -> Result<T, Error> {
    let decoding_key = jws_crypto::decoding_key(key);
    let validation = jws_crypto::eddsa_validation();
    let token_data = jsonwebtoken::decode::<T>(compact, &decoding_key, &validation)
        .map_err(|_| Error::InvalidSignature)?;
    if token_data.header.typ.as_deref() != Some(typ) {
        return Err(Error::InvalidHeaderType(typ));
    }
    Ok(token_data.claims)
}

/// Check that the grant has not expired.
fn check_expiry(raw: &GrantClaims) -> Result<(), Error> {
    let now = chrono::Utc::now().timestamp() as u64;
    if raw.exp <= now {
        return Err(Error::Expired);
    }
    Ok(())
}

/// Check that a delegated grant has not expired or been issued too far ahead.
fn check_usable(raw: &GrantClaims) -> Result<(), Error> {
    check_expiry(raw)?;
    if raw.iat > chrono::Utc::now().timestamp() as u64 + POP_MAX_AGE_SECS {
        return Err(Error::IssuedInFuture);
    }
    Ok(())
}

/// Enforce the parent lifetime limit only when authorizing use, not revocation.
fn check_parent_usable(raw: &GrantClaims) -> Result<(), Error> {
    check_usable(raw)?;
    if raw.exp.saturating_sub(raw.iat) > MAX_PARENT_GRANT_LIFETIME_SECS {
        return Err(Error::InvalidTimestamps);
    }
    Ok(())
}

/// Check that a delegated grant's callback is a canonical HTTPS URL.
///
/// Accounts must enforce each app's registered callback. Canonical URLs with
/// different paths, queries or non-default ports remain distinct app identities.
fn check_callback(raw: &GrantClaims) -> Result<(), Error> {
    if !is_exact_callback(&raw.client_id) {
        return Err(Error::InvalidCallback);
    }
    Ok(())
}

/// Check every scope and action against `limit`.
fn check_permitted(limit: &Capabilities, caps: &[Capability]) -> Result<(), Error> {
    if !caps_within(limit, caps) {
        return Err(Error::CapabilitiesExceeded);
    }
    Ok(())
}

/// Errors from Grant verification.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The JWS format is invalid or unparseable.
    #[error("invalid grant format")]
    InvalidFormat,

    /// The JWS header `typ` is not the expected type.
    #[error("invalid grant header type, expected {0}")]
    InvalidHeaderType(&'static str),

    /// The Ed25519 signature does not match the expected key.
    #[error("invalid grant signature")]
    InvalidSignature,

    /// The grant has expired (`exp` is in the past).
    #[error("grant has expired")]
    Expired,

    /// The child names a different user or parent than the parent presented.
    #[error("child grant does not match its parent")]
    ParentMismatch,

    /// The grant timestamps are inconsistent or the parent's lifetime is too long.
    #[error("invalid grant timestamps")]
    InvalidTimestamps,

    /// The grant was issued further ahead than the clock-skew allowance.
    #[error("grant was issued in the future")]
    IssuedInFuture,

    /// A delegated grant's `client_id` is not an exact HTTPS callback URL.
    #[error("delegated grant client_id must be an exact HTTPS callback URL")]
    InvalidCallback,

    /// A capability exceeds the parent, or the parent exceeds the ceiling.
    #[error("grant capabilities exceed the parent grant limit")]
    CapabilitiesExceeded,
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
    fn verify_grant_accepts_pubky_common_sign_jws() {
        // Interop check: SDKs sign grants via `pubky_common::auth::jws::sign_jws`
        // (raw ed25519-dalek + base64url). The homeserver must accept that wire
        // format byte-for-byte through the existing `verify_grant` pipeline.
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();
        let raw = make_valid_raw_grant(&user_kp, &client_kp);

        let compact_str = pubky_common::auth::jws::sign_jws(&user_kp, GRANT_JWS_TYP, &raw);
        let compact = JwsCompact::parse(&compact_str).unwrap();

        let claims = verify_grant(&compact).unwrap();
        assert_eq!(claims.jti, raw.jti);
        assert_eq!(claims.cnf, client_kp.public_key());
    }

    #[test]
    fn reject_wrong_signer() {
        let user_kp = Keypair::random();
        let wrong_kp = Keypair::random();
        let client_kp = Keypair::random();
        let raw = make_valid_raw_grant(&user_kp, &client_kp);

        // Sign with wrong key but claim iss is user_kp
        let compact = sign_raw_grant(&wrong_kp, &raw);
        for verify in [verify_grant, verify_grant_for_revocation] {
            assert!(matches!(verify(&compact), Err(Error::InvalidSignature)));
        }
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
        assert_eq!(verify_grant_for_revocation(&compact).unwrap().jti, raw.jti);
    }

    #[test]
    fn reject_wrong_header_type() {
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();
        let raw = make_valid_raw_grant(&user_kp, &client_kp);

        // Sign with wrong typ header
        let compact = JwsCompact::parse(&sign_jws(&user_kp, "wrong-typ", &raw)).unwrap();

        for verify in [verify_grant, verify_grant_for_revocation] {
            assert!(matches!(
                verify(&compact),
                Err(Error::InvalidHeaderType(GRANT_JWS_TYP))
            ));
        }
    }

    // ── Grant chains ───────────────────────────────────────────────

    const PARENT_CALLBACK: &str = "https://accounts.example/auth/callback";
    const CHILD_CALLBACK: &str = "https://chat.example/auth/callback";

    struct ChainFixture {
        user: Keypair,
        accounts: Keypair,
        parent: GrantClaims,
        child: ChildGrantClaims,
    }

    impl ChainFixture {
        fn new() -> Self {
            let user = Keypair::random();
            let accounts = Keypair::random();
            let now = Utc::now().timestamp() as u64;
            let parent = GrantClaims {
                iss: user.public_key(),
                client_id: ClientId::new(PARENT_CALLBACK).unwrap(),
                caps: vec!["/pub/:rwe".parse().unwrap(), "/priv/:rwe".parse().unwrap()],
                cnf: accounts.public_key(),
                jti: GrantId::generate(),
                iat: now,
                exp: now + 3600,
            };
            let child = ChildGrantClaims {
                grant: GrantClaims {
                    iss: user.public_key(),
                    client_id: ClientId::new(CHILD_CALLBACK).unwrap(),
                    caps: vec!["/priv/chat/:rwe".parse().unwrap()],
                    cnf: Keypair::random().public_key(),
                    jti: GrantId::generate(),
                    iat: now,
                    exp: now + 3600,
                },
                parent_jti: parent.jti.clone(),
            };
            Self {
                user,
                accounts,
                parent,
                child,
            }
        }

        fn parent_jws(&self) -> JwsCompact {
            sign(&self.user, PARENT_GRANT_JWS_TYP, &self.parent)
        }

        fn child_jws(&self) -> JwsCompact {
            sign(&self.accounts, CHILD_GRANT_JWS_TYP, &self.child)
        }

        fn verify(&self) -> Result<GrantChain, Error> {
            verify_chain(&self.parent_jws(), &self.child_jws())
        }
    }

    fn sign<T: serde::Serialize>(keypair: &Keypair, typ: &str, claims: &T) -> JwsCompact {
        JwsCompact::parse(&sign_jws(keypair, typ, claims)).unwrap()
    }

    #[test]
    fn accepts_valid_chains_with_narrower_rights_and_lifetime() {
        let mut chain = ChainFixture::new();
        chain.verify().unwrap();

        chain.child.grant.exp -= 60;
        chain.child.grant.caps = vec![
            "/pub/chat/v1/:r".parse().unwrap(),
            "/priv/chat/v1/keys/:e".parse().unwrap(),
        ];
        let verified = chain.verify().unwrap();
        assert_eq!(verified.child, chain.child);
        assert_eq!(verified.parent, chain.parent);
    }

    #[test]
    fn rejects_wrong_chain_signers() {
        let chain = ChainFixture::new();
        let stranger = Keypair::random();

        // A parent not signed by the user it names.
        let forged_parent = sign(&stranger, PARENT_GRANT_JWS_TYP, &chain.parent);
        assert!(matches!(
            verify_chain(&forged_parent, &chain.child_jws()),
            Err(Error::InvalidSignature)
        ));

        // A child signed by anyone but the parent's key, including the user.
        for signer in [&stranger, &chain.user] {
            let forged_child = sign(signer, CHILD_GRANT_JWS_TYP, &chain.child);
            assert!(matches!(
                verify_chain(&chain.parent_jws(), &forged_child),
                Err(Error::InvalidSignature)
            ));
        }
    }

    #[test]
    fn token_types_cannot_stand_in_for_each_other() {
        let chain = ChainFixture::new();

        assert!(matches!(
            verify_grant(&chain.parent_jws()),
            Err(Error::InvalidHeaderType(GRANT_JWS_TYP))
        ));

        let direct_as_parent = sign(&chain.user, GRANT_JWS_TYP, &chain.parent);
        assert!(matches!(
            verify_chain(&direct_as_parent, &chain.child_jws()),
            Err(Error::InvalidHeaderType(PARENT_GRANT_JWS_TYP))
        ));

        // Further delegation: a child in the parent's place, even when signed
        // by the user it names, and a parent in the child's place.
        let child_as_parent = sign(&chain.user, CHILD_GRANT_JWS_TYP, &chain.child.grant);
        assert!(matches!(
            verify_chain(&child_as_parent, &chain.child_jws()),
            Err(Error::InvalidHeaderType(PARENT_GRANT_JWS_TYP))
        ));
        let parent_as_child = sign(&chain.accounts, PARENT_GRANT_JWS_TYP, &chain.child);
        assert!(matches!(
            verify_chain(&chain.parent_jws(), &parent_as_child),
            Err(Error::InvalidHeaderType(CHILD_GRANT_JWS_TYP))
        ));

        assert!(is_parent_grant(&chain.parent_jws()));
        assert!(!is_parent_grant(&chain.child_jws()));
    }

    #[test]
    fn rejects_children_of_another_user_or_parent() {
        let mut chain = ChainFixture::new();
        chain.child.grant.iss = Keypair::random().public_key();
        assert!(matches!(chain.verify(), Err(Error::ParentMismatch)));

        let mut chain = ChainFixture::new();
        chain.child.parent_jti = GrantId::generate();
        assert!(matches!(chain.verify(), Err(Error::ParentMismatch)));
    }

    #[test]
    fn rejects_invalid_chain_times() {
        type Edit = fn(&mut ChainFixture);
        let cases: [Edit; 4] = [
            |chain| chain.child.grant.iat = chain.parent.iat - 1,
            |chain| chain.child.grant.exp = chain.parent.exp + 1,
            |chain| chain.child.grant.exp = chain.child.grant.iat,
            |chain| chain.parent.exp = chain.parent.iat,
        ];
        for edit in cases {
            let mut chain = ChainFixture::new();
            edit(&mut chain);
            assert!(matches!(chain.verify(), Err(Error::InvalidTimestamps)));
        }
    }

    #[test]
    fn parent_lifetime_is_capped_for_use_but_not_revocation() {
        let mut chain = ChainFixture::new();
        let max_exp = chain.parent.iat + 2 * 365 * 24 * 3600;
        chain.parent.exp = max_exp;
        chain.child.grant.exp = max_exp;
        verify_parent(&chain.parent_jws()).unwrap();
        chain.verify().unwrap();

        // A short-lived child doesn't exempt its parent from the limit.
        chain.child.grant.exp = chain.child.grant.iat + 3600;
        for exp in [max_exp + 1, u64::MAX] {
            chain.parent.exp = exp;
            assert!(matches!(
                verify_parent(&chain.parent_jws()),
                Err(Error::InvalidTimestamps)
            ));
            assert!(matches!(chain.verify(), Err(Error::InvalidTimestamps)));
            verify_parent_for_revocation(&chain.parent_jws()).unwrap();
            verify_chain_for_revocation(&chain.parent_jws(), &chain.child_jws()).unwrap();

            // The parent limit doesn't change direct grants.
            verify_grant(&sign(&chain.user, GRANT_JWS_TYP, &chain.parent)).unwrap();
        }
    }

    #[test]
    fn expired_overlong_parents_can_still_be_revoked() {
        let mut chain = ChainFixture::new();
        let now = Utc::now().timestamp() as u64;
        chain.parent.iat = now - 2 * 365 * 24 * 3600 - 60;
        chain.parent.exp = now - 1;
        chain.child.grant.iat = chain.parent.iat;
        chain.child.grant.exp = chain.parent.exp;

        assert!(matches!(chain.verify(), Err(Error::Expired)));
        verify_parent_for_revocation(&chain.parent_jws()).unwrap();
        verify_chain_for_revocation(&chain.parent_jws(), &chain.child_jws()).unwrap();
    }

    #[test]
    fn expiry_and_future_issuance_block_use_but_not_revocation() {
        let mut expired = ChainFixture::new();
        expired.parent.iat = 1000;
        expired.parent.exp = 2000;
        expired.child.grant.iat = 1000;
        expired.child.grant.exp = 2000;
        assert!(matches!(expired.verify(), Err(Error::Expired)));
        verify_chain_for_revocation(&expired.parent_jws(), &expired.child_jws()).unwrap();

        // Only the child has expired.
        let mut expired_child = ChainFixture::new();
        let now = Utc::now().timestamp() as u64;
        expired_child.parent.iat = now - 120;
        expired_child.child.grant.iat = now - 120;
        expired_child.child.grant.exp = now - 60;
        assert!(matches!(expired_child.verify(), Err(Error::Expired)));

        let mut future = ChainFixture::new();
        future.parent.iat += POP_MAX_AGE_SECS + 60;
        future.child.grant.iat = future.parent.iat;
        assert!(matches!(future.verify(), Err(Error::IssuedInFuture)));
    }

    #[test]
    fn rejects_rights_beyond_the_parent_or_ceiling() {
        for caps in ["/:rw", "/pub/:rwe,/:r", "/dav/:r"] {
            let mut chain = ChainFixture::new();
            chain.parent.caps = caps.parse::<Capabilities>().unwrap().to_vec();
            assert!(
                matches!(chain.verify(), Err(Error::CapabilitiesExceeded)),
                "parent accepted {caps}"
            );
        }

        // The parent grants `/priv/chat/:r` and `/pub/chat/:e`.
        for caps in [
            "/priv/chat/:w",
            "/priv/chat/:e",
            "/priv/:r",
            "/priv/chat:r",
            "/priv/chat-evil/:r",
            "/pub/chat/:r",
            "/priv/chat/:r,/pub/:e",
        ] {
            let mut chain = ChainFixture::new();
            chain.parent.caps = "/priv/chat/:r,/pub/chat/:e"
                .parse::<Capabilities>()
                .unwrap()
                .to_vec();
            chain.child.grant.caps = caps.parse::<Capabilities>().unwrap().to_vec();
            assert!(
                matches!(chain.verify(), Err(Error::CapabilitiesExceeded)),
                "child accepted {caps}"
            );
        }
    }

    #[test]
    fn delegated_grants_require_exact_https_callbacks() {
        for client_id in [
            "chat.example",
            "http://chat.example/cb",
            "HTTPS://chat.example/cb",
            "https://chat.example",
            "https://user@chat.example/cb",
            "https://chat.example/cb#fragment",
        ] {
            let mut chain = ChainFixture::new();
            chain.child.grant.client_id = ClientId::new(client_id).unwrap();
            assert!(
                matches!(chain.verify(), Err(Error::InvalidCallback)),
                "child accepted {client_id}"
            );

            let mut chain = ChainFixture::new();
            chain.parent.client_id = ClientId::new(client_id).unwrap();
            assert!(
                matches!(chain.verify(), Err(Error::InvalidCallback)),
                "parent accepted {client_id}"
            );
        }
    }
}
