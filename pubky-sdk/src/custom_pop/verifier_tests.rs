use super::*;
use crate::{ClientId, GrantId, Keypair};
use pubky_common::auth::jws::{finish_jws, jws_signing_input, sign_jws};
use serde_json::json;

const NOW: u64 = 1_800_000_000;
const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAA";

/// Proof claims signed at `iat` for the given grant ID.
fn claims_at(gid: &GrantId, iat: u64, data: serde_json::Value) -> serde_json::Value {
    json!({"gid": gid, "iat": iat, "nonce": NONCE, "data": data})
}

fn claims(gid: &GrantId, data: serde_json::Value) -> serde_json::Value {
    claims_at(gid, NOW, data)
}

fn fixture() -> (Keypair, Keypair, GrantClaims, CustomPop) {
    let root = Keypair::random();
    let client = Keypair::random();
    let grant = GrantClaims {
        iss: root.public_key(),
        client_id: ClientId::new("custom-pop.test").unwrap(),
        caps: vec![],
        cnf: client.public_key(),
        jti: GrantId::generate(),
        iat: NOW - 10,
        exp: NOW + 60,
    };
    let credentials = CustomPop {
        grant: grant.sign(&root, GRANT_JWS_TYP),
        pop: sign_jws(
            &client,
            CUSTOM_POP_JWS_TYP,
            &claims(&grant.jti, json!({"challenge": "abc"})),
        ),
    };
    (root, client, grant, credentials)
}

#[test]
fn returns_verified_identity_and_data_and_allows_repeated_verification() {
    let (root, _, grant, credentials) = fixture();
    for _ in 0..2 {
        let verified = verify_at(&credentials, NOW, 0).unwrap();
        assert_eq!(verified.identity(), &root.public_key());
        assert_eq!(verified.grant_claims(), &grant);
        assert_eq!(verified.data(), &json!({"challenge": "abc"}));
        assert_eq!(verified.iat(), NOW);
        assert_eq!(verified.nonce().to_string(), NONCE);
    }
}

#[test]
fn rejects_forged_grants_and_proofs_and_tampered_data() {
    let (_, _, grant, mut credentials) = fixture();
    let original = credentials.clone();
    credentials.grant = grant.sign(&Keypair::random(), GRANT_JWS_TYP);
    assert!(matches!(
        verify_at(&credentials, NOW, 0),
        Err(CustomPopVerificationError::InvalidGrantSignature)
    ));
    credentials = original.clone();
    credentials.pop = sign_jws(
        &Keypair::random(),
        CUSTOM_POP_JWS_TYP,
        &claims(&grant.jti, json!(null)),
    );
    assert!(matches!(
        verify_at(&credentials, NOW, 0),
        Err(CustomPopVerificationError::InvalidProofSignature)
    ));
    let signature = original.pop.rsplit('.').next().unwrap();
    credentials.pop = format!(
        "{}.{}",
        jws_signing_input(CUSTOM_POP_JWS_TYP, &claims(&grant.jti, json!("tampered"))),
        signature
    );
    assert!(matches!(
        verify_at(&credentials, NOW, 0),
        Err(CustomPopVerificationError::InvalidProofSignature)
    ));
}

#[test]
fn rejects_substitution_of_another_grant_for_the_same_client_key() {
    let (root, _, mut grant, mut credentials) = fixture();
    grant.jti = GrantId::generate();
    credentials.grant = grant.sign(&root, GRANT_JWS_TYP);
    assert!(matches!(
        verify_at(&credentials, NOW, 0),
        Err(CustomPopVerificationError::GrantMismatch)
    ));
}

#[test]
fn enforces_grant_time_boundaries_without_grace() {
    let (root, client, mut grant, mut credentials) = fixture();
    credentials.pop = sign_jws(
        &client,
        CUSTOM_POP_JWS_TYP,
        &claims_at(&grant.jti, grant.iat, json!(null)),
    );
    assert!(verify_at(&credentials, grant.iat, 0).is_ok());
    assert!(verify_at(&credentials, grant.exp - 1, 0).is_ok());
    assert!(matches!(
        verify_at(&credentials, grant.iat - 1, 0),
        Err(CustomPopVerificationError::GrantNotYetValid)
    ));
    assert!(matches!(
        verify_at(&credentials, grant.exp, 0),
        Err(CustomPopVerificationError::GrantExpired)
    ));
    grant.exp = grant.iat;
    credentials.grant = grant.sign(&root, GRANT_JWS_TYP);
    assert!(matches!(
        verify_at(&credentials, NOW, 0),
        Err(CustomPopVerificationError::InvalidGrant)
    ));
}

#[test]
fn rejects_other_protocols_and_unsupported_header_extensions() {
    let (_, client, grant, mut credentials) = fixture();
    for typ in ["pubky-pop", "pubky-service-pop-v1", "pubky-grant"] {
        credentials.pop = sign_jws(&client, typ, &claims(&grant.jti, json!(null)));
        assert!(matches!(
            verify_at(&credentials, NOW, 0),
            Err(CustomPopVerificationError::UnsupportedHeader)
        ));
    }
    for header in [
        json!({"alg": "none", "typ": CUSTOM_POP_JWS_TYP}),
        json!({"alg": "EdDSA", "typ": CUSTOM_POP_JWS_TYP, "crit": ["extra"]}),
    ] {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims(&grant.jti, json!(null))).unwrap())
        );
        credentials.pop = finish_jws(input.clone(), client.sign(input.as_bytes()).to_bytes());
        assert!(matches!(
            verify_at(&credentials, NOW, 0),
            Err(CustomPopVerificationError::UnsupportedHeader)
        ));
    }
}

#[test]
fn clock_skew_is_inclusive_configurable_and_never_extends_expiry() {
    let (root, _, mut grant, mut credentials) = fixture();
    grant.iat = NOW + 30;
    credentials.grant = grant.sign(&root, GRANT_JWS_TYP);
    assert!(verify_at(&credentials, NOW, DEFAULT_CUSTOM_POP_CLOCK_SKEW.as_secs()).is_ok());
    assert!(matches!(
        verify_at(&credentials, NOW - 1, 30),
        Err(CustomPopVerificationError::GrantNotYetValid)
    ));
    assert!(matches!(
        verify_at(&credentials, NOW, 0),
        Err(CustomPopVerificationError::GrantNotYetValid)
    ));
    assert!(verify_at(&credentials, NOW - 30, 60).is_ok());
    assert!(matches!(
        verify_at(&credentials, NOW - 31, 60),
        Err(CustomPopVerificationError::GrantNotYetValid)
    ));
    // Saturation avoids overflow even for the largest supported Rust allowance.
    assert!(verify_at(&credentials, NOW, u64::MAX).is_ok());
    for skew in [0, 30, 60, u64::MAX] {
        assert!(matches!(
            verify_at(&credentials, grant.exp, skew),
            Err(CustomPopVerificationError::GrantExpired)
        ));
    }
    grant.iat = grant.exp;
    credentials.grant = grant.sign(&root, GRANT_JWS_TYP);
    assert!(matches!(
        verify_at(&credentials, NOW, u64::MAX),
        Err(CustomPopVerificationError::InvalidGrant)
    ));
}

#[test]
fn rejects_malformed_framing_and_duplicate_or_missing_envelope_fields() {
    let (_, client, grant, mut credentials) = fixture();
    for compact in [
        "".to_owned(),
        "a.b.c".into(),
        format!("{}.extra", credentials.pop),
    ] {
        let invalid = CustomPop {
            grant: credentials.grant.clone(),
            pop: compact,
        };
        assert!(matches!(
            verify_at(&invalid, NOW, 0),
            Err(CustomPopVerificationError::MalformedCredential)
        ));
    }
    for payload in [
        format!(
            r#"{{"gid":"{0}","gid":"{0}","iat":{NOW},"nonce":"{NONCE}","data":null}}"#,
            grant.jti
        ),
        format!(
            r#"{{"gid":"{}","iat":{NOW},"nonce":"{NONCE}","data":null,"data":1}}"#,
            grant.jti
        ),
        format!(r#"{{"iat":{NOW},"nonce":"{NONCE}","data":null}}"#),
        format!(r#"{{"gid":"{}","nonce":"{NONCE}","data":null}}"#, grant.jti),
        format!(r#"{{"gid":"{}","iat":{NOW},"data":null}}"#, grant.jti),
        format!(
            r#"{{"gid":"{}","iat":{NOW},"nonce":"not/base64url","data":null}}"#,
            grant.jti
        ),
        format!(
            r#"{{"gid":"{}","iat":{NOW},"nonce":"{NONCE}","data":null,"extra":1}}"#,
            grant.jti
        ),
    ] {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"EdDSA","typ":"{CUSTOM_POP_JWS_TYP}"}}"#)),
            URL_SAFE_NO_PAD.encode(payload)
        );
        credentials.pop = finish_jws(input.clone(), client.sign(input.as_bytes()).to_bytes());
        assert!(matches!(
            verify_at(&credentials, NOW, 0),
            Err(CustomPopVerificationError::MalformedCredential)
        ));
    }
}

#[test]
fn proof_issue_time_respects_clock_skew_and_grant_validity() {
    let (_, client, grant, mut credentials) = fixture();
    let mut verify_proof_at = |proof_iat: u64, now: u64, skew: u64| {
        credentials.pop = sign_jws(
            &client,
            CUSTOM_POP_JWS_TYP,
            &claims_at(&grant.jti, proof_iat, json!(null)),
        );
        verify_at(&credentials, now, skew)
    };
    // Future proof issue times are bounded by the allowance, inclusively.
    assert!(verify_proof_at(NOW + 30, NOW, 30).is_ok());
    assert!(matches!(
        verify_proof_at(NOW + 31, NOW, 30),
        Err(CustomPopVerificationError::ProofNotYetValid)
    ));
    assert!(matches!(
        verify_proof_at(NOW + 1, NOW, 0),
        Err(CustomPopVerificationError::ProofNotYetValid)
    ));
    // Old proofs are accepted; applications own the maximum age.
    assert!(verify_proof_at(grant.iat, grant.exp - 1, 0).is_ok());
    // Proofs must be issued within the grant's validity period, allowing skew before `iat`.
    assert!(verify_proof_at(grant.iat - 30, NOW, 30).is_ok());
    assert!(matches!(
        verify_proof_at(grant.iat - 31, NOW, 30),
        Err(CustomPopVerificationError::ProofOutsideGrantValidity)
    ));
    assert!(matches!(
        verify_proof_at(grant.iat - 1, NOW, 0),
        Err(CustomPopVerificationError::ProofOutsideGrantValidity)
    ));
    assert!(matches!(
        verify_proof_at(grant.exp, NOW, u64::MAX),
        Err(CustomPopVerificationError::ProofOutsideGrantValidity)
    ));
}

#[test]
fn transport_bundle_ignores_unknown_fields() {
    let (_, _, _, credentials) = fixture();
    let mut bundle = serde_json::to_value(&credentials).unwrap();
    bundle["future"] = json!("field");
    let received: CustomPop = serde_json::from_value(bundle).unwrap();
    assert!(verify_at(&received, NOW, 0).is_ok());
}
