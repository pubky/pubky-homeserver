//! Network-free, audience-bound authentication credentials for external services.

use crate::service_auth::{
    SERVICE_POP_JWS_TYP, ServiceAuthProof, ServiceProofClaims, valid_audience,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::crypto::random_bytes;

use super::{
    credential::{GrantCredential, now_unix},
    pop_signer::GrantSigningError,
    shared_session::active_session,
};

/// Failures when creating external-service credentials from a grant session.
#[derive(Debug, thiserror::Error)]
pub enum ServiceAuthProofError {
    /// The audience must contain between 1 and 1024 UTF-8 bytes.
    #[error("Service audience must contain between 1 and 1024 UTF-8 bytes")]
    InvalidAudience,

    /// The grant expired before proof generation completed.
    #[error("Grant has expired")]
    GrantExpired,

    /// The grant's validity period or signing key binding is invalid.
    #[error("Invalid grant: {0}")]
    InvalidGrant(String),

    /// The bound signing key could not be loaded or accessed.
    #[error("Signing key unavailable: {0}")]
    SigningKeyUnavailable(String),

    /// The signing operation failed after accessing the key.
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Browser session coordination or local lifecycle validation failed.
    #[error("Session state unavailable: {0}")]
    SessionState(#[source] Box<crate::Error>),
}

impl ServiceAuthProofError {
    fn session_state(error: crate::Error) -> Self {
        Self::SessionState(Box::new(error))
    }
}

impl From<GrantSigningError> for ServiceAuthProofError {
    fn from(error: GrantSigningError) -> Self {
        match error {
            GrantSigningError::KeyUnavailable(message) => Self::SigningKeyUnavailable(message),
            GrantSigningError::SigningFailed(message) => Self::SigningFailed(message),
        }
    }
}

impl GrantCredential {
    pub(crate) async fn create_service_auth_proof(
        &self,
        audience: &str,
    ) -> Result<ServiceAuthProof, ServiceAuthProofError> {
        if !valid_audience(audience) {
            return Err(ServiceAuthProofError::InvalidAudience);
        }
        // Follow browser lock ordering and prevent removal/logout during signing.
        // Only local lifecycle state is read; bearer freshness is irrelevant.
        let coordinator = self.coordinator().await;
        let _lease = if let Some(coordinator) = &coordinator {
            let lease = coordinator
                .acquire(false)
                .await
                .map_err(ServiceAuthProofError::session_state)?;
            active_session(lease.as_ref())
                .await
                .map_err(ServiceAuthProofError::session_state)?;
            Some(lease)
        } else {
            None
        };
        let (grant, claims, signer) = {
            let state = self.state.lock().await;
            (
                state.grant_jws.clone(),
                state.grant_claims.clone(),
                state.client_signer.clone(),
            )
        };
        let now = now_unix();
        if claims.exp <= now {
            return Err(ServiceAuthProofError::GrantExpired);
        }
        if claims.iat >= claims.exp {
            return Err(ServiceAuthProofError::InvalidGrant(
                "issue time must precede expiry".into(),
            ));
        }
        if signer.public_key() != claims.cnf {
            return Err(ServiceAuthProofError::InvalidGrant(
                "signing key does not match the grant cnf".into(),
            ));
        }
        let proof = ServiceProofClaims {
            aud: audience.to_owned(),
            gid: claims.jti,
            nonce: URL_SAFE_NO_PAD.encode(random_bytes::<32>()),
            iat: now,
        };
        let pop = signer.sign_jws(SERVICE_POP_JWS_TYP, &proof).await?;
        if claims.exp <= now_unix() {
            return Err(ServiceAuthProofError::GrantExpired);
        }
        Ok(ServiceAuthProof { grant, pop })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actors::auth::grant::{
        DelegatedGrantCredentialState,
        pop_signer::{GrantPopSigner, delegated_sign_callback},
    };
    use pubky_common::{
        auth::{
            grant::GrantClaims,
            jws::{ClientId, GRANT_JWS_TYP, GrantId, decode_jws_payload},
        },
        crypto::{Keypair, PublicKey, Signature},
    };
    use serde_json::Value;

    fn credential() -> (GrantCredential, Keypair) {
        let root = Keypair::random();
        let key = Keypair::random();
        let now = now_unix();
        let claims = GrantClaims {
            iss: root.public_key(),
            client_id: ClientId::new("service-auth.test").unwrap(),
            caps: vec![],
            cnf: key.public_key(),
            jti: GrantId::generate(),
            iat: now,
            exp: now + 3600,
        };
        let signing_key = key.clone();
        let credential = GrantCredential::from_shared_delegated_state(
            DelegatedGrantCredentialState {
                grant_jws: claims.sign(&root, GRANT_JWS_TYP),
                homeserver_pk: Keypair::random().public_key(),
                key_id: "test-key".into(),
                client_pk: key.public_key(),
            },
            delegated_sign_callback(move |input| {
                let signature = signing_key.sign(input.as_bytes()).to_bytes().to_vec();
                async move { Ok(signature) }
            }),
        )
        .unwrap();
        (credential, key)
    }

    fn verify(jws: &str, key: &PublicKey) -> Value {
        let (input, signature) = jws.rsplit_once('.').unwrap();
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();
        key.verify(input.as_bytes(), &signature).unwrap();
        decode_jws_payload(jws).unwrap()
    }

    #[tokio::test]
    async fn local_and_delegated_proofs_preserve_audience_without_a_bearer() {
        let (credential, key) = credential();
        for local in [false, true] {
            if local {
                credential.state.lock().await.client_signer = GrantPopSigner::local(key.clone());
            }
            for audience in [
                "pubky-inbox",
                " Inbox:é/生产 ",
                "HTTPS://Example.com/path?q=1",
            ] {
                let proof = credential
                    .create_service_auth_proof(audience)
                    .await
                    .unwrap();
                let claims = verify(&proof.pop, &key.public_key());
                assert_eq!(claims["aud"], audience);
                assert_eq!(
                    claims["gid"],
                    credential.state.lock().await.grant_claims.jti.as_str()
                );
                assert_eq!(
                    URL_SAFE_NO_PAD
                        .decode(claims["nonce"].as_str().unwrap())
                        .unwrap()
                        .len(),
                    32
                );
                assert!(claims["iat"].as_u64().unwrap() <= now_unix());
                assert_eq!(proof.grant, credential.state.lock().await.grant_jws);
                let header: Value = serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(proof.pop.split('.').next().unwrap())
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    header,
                    serde_json::json!({"alg": "EdDSA", "typ": SERVICE_POP_JWS_TYP})
                );
            }
        }
        assert!(credential.current_bearer().await.is_empty());
    }

    #[tokio::test]
    async fn audience_limits_count_utf8_bytes() {
        let (credential, _) = credential();
        for audience in [String::new(), "x".repeat(1025), "é".repeat(513)] {
            assert!(matches!(
                credential.create_service_auth_proof(&audience).await,
                Err(ServiceAuthProofError::InvalidAudience)
            ));
        }
        credential
            .create_service_auth_proof(&"é".repeat(512))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn replacement_during_signing_keeps_the_original_grant_and_key() {
        let (credential, key) = credential();
        let original = credential.state.lock().await.grant_jws.clone();
        let (replacement, _) = self::credential();
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let resume = std::sync::Arc::new(tokio::sync::Notify::new());
        let signing_key = key.clone();
        let signal = std::sync::Arc::clone(&started);
        let wait = std::sync::Arc::clone(&resume);
        credential.state.lock().await.client_signer = GrantPopSigner::delegated(
            "slow-key".into(),
            key.public_key(),
            delegated_sign_callback(move |input| {
                let signature = signing_key.sign(input.as_bytes()).to_bytes().to_vec();
                let signal = std::sync::Arc::clone(&signal);
                let wait = std::sync::Arc::clone(&wait);
                async move {
                    signal.notify_one();
                    wait.notified().await;
                    Ok(signature)
                }
            }),
        );
        let pending = credential.clone();
        let task = tokio::spawn(async move { pending.create_service_auth_proof("inbox").await });
        started.notified().await;
        {
            let mut state = credential.state.lock().await;
            let replacement = replacement.state.lock().await;
            state.grant_jws.clone_from(&replacement.grant_jws);
            state.grant_claims.clone_from(&replacement.grant_claims);
            state.client_signer = replacement.client_signer.clone();
        }
        resume.notify_one();
        let proof = task.await.unwrap().unwrap();
        assert_eq!(proof.grant, original);
        verify(&proof.pop, &key.public_key());
    }

    #[tokio::test]
    async fn expiration_during_signing_is_rejected() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let (credential, key) = credential();
        let signing_started = Arc::new(AtomicBool::new(false));
        let entered = Arc::clone(&signing_started);
        let expiry = now_unix() + 2;
        let mut state = credential.state.lock().await;
        state.grant_claims.exp = expiry;
        state.client_signer = GrantPopSigner::delegated(
            "slow-key".into(),
            key.public_key(),
            delegated_sign_callback(move |input| {
                entered.store(true, Ordering::SeqCst);
                let signature = key.sign(input.as_bytes()).to_bytes().to_vec();
                async move {
                    while now_unix() < expiry {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    Ok(signature)
                }
            }),
        );
        drop(state);
        assert!(matches!(
            credential.create_service_auth_proof("inbox").await,
            Err(ServiceAuthProofError::GrantExpired)
        ));
        assert!(
            signing_started.load(Ordering::SeqCst),
            "expiry must occur after signing starts"
        );
    }

    #[tokio::test]
    async fn concurrent_proofs_have_distinct_nonces() {
        let (credential, key) = credential();
        let proofs = futures_util::future::join_all(
            (0..32).map(|_| credential.create_service_auth_proof("inbox")),
        )
        .await;
        let nonces: std::collections::HashSet<_> = proofs
            .into_iter()
            .map(|proof| {
                verify(&proof.unwrap().pop, &key.public_key())["nonce"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(nonces.len(), 32);
    }

    #[tokio::test]
    async fn rejects_expired_grants_and_mismatched_keys() {
        let (credential, _) = credential();
        credential.state.lock().await.client_signer = GrantPopSigner::local(Keypair::random());
        assert!(matches!(
            credential.create_service_auth_proof("inbox").await,
            Err(ServiceAuthProofError::InvalidGrant(_))
        ));
        credential.state.lock().await.grant_claims.exp = now_unix();
        assert!(matches!(
            credential.create_service_auth_proof("inbox").await,
            Err(ServiceAuthProofError::GrantExpired)
        ));
    }

    #[tokio::test]
    async fn signing_failure_and_missing_key_are_distinct() {
        let (credential, key) = credential();
        for missing in [false, true] {
            credential.state.lock().await.client_signer = GrantPopSigner::delegated(
                "test-key".into(),
                key.public_key(),
                delegated_sign_callback(move |_| async move {
                    Err(if missing {
                        GrantSigningError::KeyUnavailable("deleted".into())
                    } else {
                        GrantSigningError::SigningFailed("WebCrypto rejected signing".into())
                    })
                }),
            );
            let error = credential
                .create_service_auth_proof("inbox")
                .await
                .unwrap_err();
            if missing {
                assert!(matches!(
                    error,
                    ServiceAuthProofError::SigningKeyUnavailable(_)
                ));
            } else {
                assert!(matches!(error, ServiceAuthProofError::SigningFailed(_)));
            }
        }
    }

    #[tokio::test]
    async fn session_coordination_failure_retains_its_source() {
        use crate::{GrantSessionCoordinator, GrantSessionLease, errors::AuthError};

        #[derive(Debug)]
        struct UnavailableStore;

        #[async_trait::async_trait]
        impl GrantSessionCoordinator for UnavailableStore {
            async fn acquire(&self, _: bool) -> crate::Result<Box<dyn GrantSessionLease>> {
                Err(AuthError::Validation("IndexedDB access denied".into()).into())
            }
        }

        let (credential, _) = credential();
        credential.state.lock().await.coordinator = Some(std::sync::Arc::new(UnavailableStore));
        let error = credential
            .create_service_auth_proof("inbox")
            .await
            .unwrap_err();
        let source = std::error::Error::source(&error).unwrap();
        assert!(source.to_string().contains("IndexedDB access denied"));
        let ServiceAuthProofError::SessionState(source) = error else {
            panic!("expected a session-state error");
        };
        assert!(matches!(*source,
            crate::Error::Authentication(AuthError::Validation(message))
                if message == "IndexedDB access denied"));
    }
}
