use super::*;
use crate::{Keypair, service_auth::MemoryReplayStore};
use pubky_common::auth::jws::{finish_jws, sign_jws};
use serde_json::json;

#[tokio::test]
async fn signed_malformed_claims_do_not_consume_replay_capacity() {
    let fixture = Fixture::new();
    let verifier = ServiceAuthVerifier::new(
        "inbox",
        VerificationPolicy::default(),
        MemoryReplayStore::new(1).unwrap(),
    )
    .unwrap();
    for is_grant in [true, false] {
        let claims = if is_grant {
            serde_json::to_value(&fixture.grant).unwrap()
        } else {
            serde_json::to_value(&fixture.proof).unwrap()
        };
        let fields: Vec<_> = claims.as_object().unwrap().keys().cloned().collect();
        for field in fields {
            for replacement in [None, Some(json!(null)), Some(json!({})), Some(json!(true))] {
                let mut changed = claims.clone();
                if let Some(value) = replacement {
                    changed[&field] = value;
                } else {
                    changed.as_object_mut().unwrap().remove(&field);
                }
                let mut credentials = fixture.credentials();
                if is_grant {
                    credentials.grant = sign_jws(&fixture.root, GRANT_JWS_TYP, &changed);
                } else {
                    credentials.pop = sign_jws(&fixture.client, SERVICE_POP_JWS_TYP, &changed);
                }
                assert!(
                    verifier.verify_and_consume(&credentials).await.is_err(),
                    "accepted malformed {field}"
                );
            }
        }
    }
    verifier
        .verify_and_consume(&fixture.credentials())
        .await
        .unwrap();
}

#[tokio::test]
async fn exact_size_limits_and_noncanonical_nonce() {
    let mut fixture = Fixture::new();
    let credentials = fixture.credentials();
    for (grant_delta, proof_delta, accepted) in [(0, 0, true), (1, 0, false), (0, 1, false)] {
        let verifier = ServiceAuthVerifier::new(
            "inbox",
            VerificationPolicy {
                max_grant_bytes: credentials.grant.len() - grant_delta,
                max_proof_bytes: credentials.pop.len() - proof_delta,
                ..VerificationPolicy::default()
            },
            MemoryReplayStore::new(1).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verifier.verify_and_consume(&credentials).await.is_ok(),
            accepted
        );
    }
    // A zero nonce ends in A; B differs only in unused base64 pad bits.
    fixture.proof.nonce = format!("{}B", "A".repeat(42));
    assert!(matches!(
        verifier().verify_and_consume(&fixture.credentials()).await,
        Err(ServiceAuthVerificationError::InvalidNonce)
    ));
}

#[tokio::test]
async fn audience_is_not_unicode_or_url_normalized() {
    let mut fixture = Fixture::new();
    for (expected, supplied) in [
        ("é", "e\u{301}"),
        ("https://inbox", "https://inbox/"),
        ("inbox", " inbox"),
        ("inbox", "Inbox"),
    ] {
        fixture.proof.aud = supplied.into();
        let verifier = ServiceAuthVerifier::new(
            expected,
            VerificationPolicy::default(),
            MemoryReplayStore::new(1).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verifier.verify_and_consume(&fixture.credentials()).await,
            Err(ServiceAuthVerificationError::AudienceMismatch)
        ));
        fixture.proof.aud = expected.into();
        verifier
            .verify_and_consume(&fixture.credentials())
            .await
            .unwrap();
    }
}

struct Fixture {
    root: Keypair,
    client: Keypair,
    grant: GrantClaims,
    proof: ServiceProofClaims,
}

impl Fixture {
    fn new() -> Self {
        let now = now_unix().unwrap();
        let root = Keypair::from_secret(&[1; 32]);
        let client = Keypair::from_secret(&[2; 32]);
        let grant = GrantClaims {
            iss: root.public_key(),
            client_id: ClientId::new("service.test").unwrap(),
            caps: vec![],
            cnf: client.public_key(),
            jti: GrantId::generate(),
            iat: now - 60,
            exp: now + 3600,
        };
        let proof = ServiceProofClaims {
            aud: "inbox".into(),
            gid: grant.jti.clone(),
            nonce: URL_SAFE_NO_PAD.encode([3; 32]),
            iat: now,
        };
        Self {
            root,
            client,
            grant,
            proof,
        }
    }
    fn credentials(&self) -> ServiceAuthProof {
        ServiceAuthProof {
            grant: sign_jws(&self.root, GRANT_JWS_TYP, &self.grant),
            pop: sign_jws(&self.client, SERVICE_POP_JWS_TYP, &self.proof),
        }
    }
}

fn verifier() -> ServiceAuthVerifier<MemoryReplayStore> {
    ServiceAuthVerifier::new(
        "inbox",
        VerificationPolicy::default(),
        MemoryReplayStore::new(10).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn valid_credentials_return_verified_identity_and_cannot_be_replayed() {
    let mut fixture = Fixture::new();
    fixture.grant.caps = vec![crate::Capability::root()];
    let verifier = verifier();
    let credentials = fixture.credentials();
    let verified = verifier.verify_and_consume(&credentials).await.unwrap();
    assert_eq!(verified.identity(), &fixture.root.public_key());
    assert_eq!(verified.client_id(), &fixture.grant.client_id);
    assert_eq!(verified.grant_id(), &fixture.grant.jti);
    assert_eq!(verified.grant_expires_at(), fixture.grant.exp);
    assert_eq!(verified.grant_claims(), &fixture.grant);
    assert_eq!(
        serde_json::to_value(verified.proof_claims()).unwrap(),
        serde_json::to_value(&fixture.proof).unwrap(),
    );
    assert!(matches!(
        verifier.verify_and_consume(&credentials).await,
        Err(ServiceAuthVerificationError::Replay)
    ));
}

#[tokio::test]
async fn concurrent_exchanges_have_exactly_one_success() {
    let verifier = verifier();
    let credentials = Fixture::new().credentials();
    let results =
        futures_util::future::join_all((0..32).map(|_| verifier.verify_and_consume(&credentials)))
            .await;
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(ServiceAuthVerificationError::Replay)))
            .count(),
        31
    );
}

#[tokio::test]
async fn rejects_wrong_signatures_without_consuming_the_nonce() {
    let fixture = Fixture::new();
    let verifier = verifier();
    let mut credentials = fixture.credentials();
    credentials.grant = sign_jws(&fixture.client, GRANT_JWS_TYP, &fixture.grant);
    assert!(matches!(
        verifier.verify_and_consume(&credentials).await,
        Err(ServiceAuthVerificationError::InvalidGrantSignature)
    ));
    credentials = fixture.credentials();
    credentials.pop = sign_jws(&fixture.root, SERVICE_POP_JWS_TYP, &fixture.proof);
    assert!(matches!(
        verifier.verify_and_consume(&credentials).await,
        Err(ServiceAuthVerificationError::InvalidProofSignature)
    ));
    credentials = fixture.credentials();
    let mut changed_claims = fixture.proof.clone();
    changed_claims.aud = "another-service".into();
    let (original_input, signature) = credentials.pop.rsplit_once('.').unwrap();
    let header = original_input.split('.').next().unwrap();
    let changed_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed_claims).unwrap());
    credentials.pop = format!("{header}.{changed_payload}.{signature}");
    assert!(matches!(
        verifier.verify_and_consume(&credentials).await,
        Err(ServiceAuthVerificationError::InvalidProofSignature)
    ));
    verifier
        .verify_and_consume(&fixture.credentials())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_slow_durable_consumption_cannot_return_an_expired_identity() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    #[derive(Debug)]
    struct SlowStore(Arc<AtomicBool>);
    #[async_trait::async_trait]
    impl ReplayStore for SlowStore {
        async fn consume_once(
            &self,
            request: ReplayRequest,
        ) -> Result<ConsumeOutcome, ReplayStoreError> {
            self.0.store(true, Ordering::SeqCst);
            while now_unix()? < request.expires_at() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Ok(ConsumeOutcome::Consumed)
        }
    }
    let consumed = Arc::new(AtomicBool::new(false));
    let verifier = ServiceAuthVerifier::new(
        "inbox",
        VerificationPolicy::default(),
        SlowStore(Arc::clone(&consumed)),
    )
    .unwrap();
    let mut fixture = Fixture::new();
    fixture.grant.exp = now_unix().unwrap() + 2;
    assert!(matches!(
        verifier.verify_and_consume(&fixture.credentials()).await,
        Err(ServiceAuthVerificationError::GrantExpired)
    ));
    assert!(
        consumed.load(Ordering::SeqCst),
        "test must reach the persistence step"
    );
}

#[tokio::test]
async fn validates_audience_grant_binding_nonce_and_expiration() {
    let mut fixture = Fixture::new();
    let verifier = verifier();
    fixture.proof.aud = "Inbox".into();
    assert!(matches!(
        verifier.verify_and_consume(&fixture.credentials()).await,
        Err(ServiceAuthVerificationError::AudienceMismatch)
    ));
    fixture.proof.aud = "inbox".into();
    fixture.proof.gid = GrantId::generate();
    assert!(matches!(
        verifier.verify_and_consume(&fixture.credentials()).await,
        Err(ServiceAuthVerificationError::GrantMismatch)
    ));
    fixture.proof.gid = fixture.grant.jti.clone();
    for nonce in [
        "".into(),
        URL_SAFE_NO_PAD.encode([0; 16]),
        format!("{}=", fixture.proof.nonce),
        "!".repeat(43),
    ] {
        fixture.proof.nonce = nonce;
        assert!(matches!(
            verifier.verify_and_consume(&fixture.credentials()).await,
            Err(ServiceAuthVerificationError::InvalidNonce)
        ));
    }
    fixture.proof.nonce = URL_SAFE_NO_PAD.encode([0; 32]);
    fixture.grant.exp = now_unix().unwrap();
    assert!(matches!(
        verifier.verify_and_consume(&fixture.credentials()).await,
        Err(ServiceAuthVerificationError::GrantExpired)
    ));
}

#[test]
fn timestamp_boundaries_are_explicit_and_overflow_is_rejected() {
    let mut fixture = Fixture::new();
    let verifier = verifier();
    fixture.grant.iat = 900;
    fixture.grant.exp = 2000;
    fixture.proof.iat = 1000;
    assert_eq!(
        verifier
            .time_bounds(&fixture.grant, &fixture.proof, 970)
            .unwrap(),
        (970, 1180)
    );
    assert!(
        verifier
            .time_bounds(&fixture.grant, &fixture.proof, 969)
            .is_err()
    );
    assert!(
        verifier
            .time_bounds(&fixture.grant, &fixture.proof, 1179)
            .is_ok()
    );
    assert!(
        verifier
            .time_bounds(&fixture.grant, &fixture.proof, 1180)
            .is_err()
    );
    fixture.grant.exp = 1100;
    assert!(
        verifier
            .time_bounds(&fixture.grant, &fixture.proof, 1099)
            .is_ok()
    );
    assert!(matches!(
        verifier.time_bounds(&fixture.grant, &fixture.proof, 1100),
        Err(ServiceAuthVerificationError::GrantExpired)
    ));
    fixture.grant.exp = u64::MAX;
    fixture.proof.iat = u64::MAX - 10;
    assert!(matches!(
        verifier.time_bounds(&fixture.grant, &fixture.proof, 1000),
        Err(ServiceAuthVerificationError::InvalidTimestamp)
    ));
}

fn raw_jws(key: &Keypair, header: &str, payload: &str) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = key.sign(input.as_bytes());
    finish_jws(input, signature.to_bytes())
}

#[tokio::test]
async fn strict_jws_parser_rejects_extensions_duplicates_and_invalid_framing() {
    let fixture = Fixture::new();
    let payload = serde_json::to_string(&fixture.proof).unwrap();
    for header in [
        r#"{"alg":"none","typ":"pubky-service-pop-v1"}"#,
        r#"{"alg":"EdDSA","typ":"pubky-pop"}"#,
        r#"{"alg":"EdDSA","alg":"EdDSA","typ":"pubky-service-pop-v1"}"#,
        r#"{"alg":"EdDSA","typ":"pubky-service-pop-v1","crit":["b64"],"b64":false}"#,
        r#"{"alg":"EdDSA","typ":"pubky-service-pop-v1","jwk":{}}"#,
    ] {
        let mut credentials = fixture.credentials();
        credentials.pop = raw_jws(&fixture.client, header, &payload);
        assert!(matches!(
            verifier().verify_and_consume(&credentials).await,
            Err(ServiceAuthVerificationError::UnsupportedHeader)
        ));
    }
    let header = r#"{"alg":"EdDSA","typ":"pubky-service-pop-v1"}"#;
    for invalid in [
        format!("{{\"aud\":\"inbox\",{}", &payload[1..]),
        format!("{{\"unknown\":1,{}", &payload[1..]),
        r#"{"aud":"inbox"}"#.into(),
    ] {
        let mut credentials = fixture.credentials();
        credentials.pop = raw_jws(&fixture.client, header, &invalid);
        assert!(matches!(
            verifier().verify_and_consume(&credentials).await,
            Err(ServiceAuthVerificationError::MalformedCredential)
        ));
    }
    let valid = fixture.credentials();
    for invalid in [
        "..".into(),
        format!("{}.extra", valid.pop),
        format!("{}=", valid.pop),
        valid.pop.replace('.', ".="),
    ] {
        let credentials = ServiceAuthProof {
            grant: valid.grant.clone(),
            pop: invalid,
        };
        assert!(verifier().verify_and_consume(&credentials).await.is_err());
    }
}

#[tokio::test]
async fn size_limits_and_policy_binding_fail_closed() {
    let fixture = Fixture::new();
    let store = MemoryReplayStore::new(10).unwrap();
    let short_policy = VerificationPolicy {
        max_grant_bytes: 10,
        ..VerificationPolicy::default()
    };
    let small = ServiceAuthVerifier::new("inbox", short_policy, store.clone()).unwrap();
    assert!(matches!(
        small.verify_and_consume(&fixture.credentials()).await,
        Err(ServiceAuthVerificationError::InputTooLarge)
    ));
    let verifier =
        ServiceAuthVerifier::new("inbox", VerificationPolicy::default(), store.clone()).unwrap();
    verifier
        .verify_and_consume(&fixture.credentials())
        .await
        .unwrap();
    let changed = ServiceAuthVerifier::new(
        "inbox",
        VerificationPolicy {
            max_proof_age_seconds: 360,
            ..VerificationPolicy::default()
        },
        store,
    )
    .unwrap();
    assert!(matches!(
        changed.verify_and_consume(&fixture.credentials()).await,
        Err(ServiceAuthVerificationError::Storage(
            ReplayStoreError::PolicyMismatch
        ))
    ));
}

#[tokio::test]
async fn sdk_generated_credentials_verify_with_a_restored_delegated_signer() {
    let fixture = Fixture::new();
    let client = fixture.client.clone();
    let credential = crate::GrantCredential::from_shared_delegated_state(
        crate::DelegatedGrantCredentialState {
            grant_jws: fixture.credentials().grant,
            homeserver_pk: Keypair::random().public_key(),
            key_id: "test-key".into(),
            client_pk: client.public_key(),
        },
        crate::delegated_sign_callback(move |input| {
            let signature = client.sign(input.as_bytes()).to_bytes().to_vec();
            async move { Ok(signature) }
        }),
    )
    .unwrap();
    let credentials = credential.create_service_auth_proof("inbox").await.unwrap();
    let encoded = serde_json::to_string(&credentials).unwrap();
    let decoded: ServiceAuthProof = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        verifier()
            .verify_and_consume(&decoded)
            .await
            .unwrap()
            .identity(),
        &fixture.root.public_key()
    );
}

#[test]
fn node_crypto_vector_matches_sdk_signing_and_verification() {
    #[derive(Deserialize)]
    struct Vector {
        now: u64,
        grant_claims: GrantClaims,
        proof_claims: ServiceProofClaims,
        credentials: ServiceAuthProof,
    }
    let vector: Vector =
        serde_json::from_str(include_str!("../../tests/fixtures/service-auth-v1.json")).unwrap();
    assert_eq!(
        sign_jws(
            &Keypair::from_secret(&[1; 32]),
            GRANT_JWS_TYP,
            &vector.grant_claims
        ),
        vector.credentials.grant
    );
    assert_eq!(
        sign_jws(
            &Keypair::from_secret(&[2; 32]),
            SERVICE_POP_JWS_TYP,
            &vector.proof_claims
        ),
        vector.credentials.pop
    );
    for (compact, typ, key) in [
        (
            &vector.credentials.grant,
            GRANT_JWS_TYP,
            &vector.grant_claims.iss,
        ),
        (
            &vector.credentials.pop,
            SERVICE_POP_JWS_TYP,
            &vector.grant_claims.cnf,
        ),
    ] {
        let parsed = ParsedJws::parse(compact, typ).unwrap();
        key.verify(parsed.signing_input.as_bytes(), &parsed.signature)
            .unwrap();
    }
    assert_eq!(
        verifier()
            .time_bounds(&vector.grant_claims, &vector.proof_claims, vector.now)
            .unwrap(),
        (1_700_000_030, 1_700_000_240)
    );
}

#[test]
fn claim_decoding_never_accepts_duplicate_grant_fields() {
    let fixture = Fixture::new();
    let grant = serde_json::to_string(&fixture.grant).unwrap();
    let duplicate = format!("{{\"exp\":0,{}", &grant[1..]);
    let raw = raw_jws(
        &fixture.root,
        r#"{"alg":"EdDSA","typ":"pubky-grant"}"#,
        &duplicate,
    );
    assert!(
        ParsedJws::parse(&raw, GRANT_JWS_TYP)
            .unwrap()
            .claims::<GrantClaims>(&["iss", "client_id", "caps", "cnf", "jti", "iat", "exp"])
            .is_err()
    );
    assert_eq!(
        serde_json::to_value(&fixture.proof).unwrap()["aud"],
        json!("inbox")
    );
}
