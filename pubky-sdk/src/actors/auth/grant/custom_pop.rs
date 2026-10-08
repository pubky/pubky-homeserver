//! Network-free custom proofs using the grant's existing signing key.

use super::{
    credential::{GrantCredential, now_unix},
    pop_signer::GrantSigningError,
    shared_session::active_session,
};
use crate::custom_pop::{CUSTOM_POP_JWS_TYP, CustomPop, CustomPopClaims};

/// Failures when signing custom data with a grant session.
#[derive(Debug, thiserror::Error)]
pub enum CustomPopError {
    /// The grant expired before proof generation completed.
    #[error("Grant has expired")]
    GrantExpired,
    /// The grant's validity period or signing key binding is invalid.
    #[error("Invalid grant: {0}")]
    InvalidGrant(String),
    /// The bound signing key could not be accessed.
    #[error("Signing key unavailable: {0}")]
    SigningKeyUnavailable(String),
    /// The signing operation failed after accessing the key.
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    /// Browser coordination or local lifecycle validation failed.
    #[error("Session state unavailable: {0}")]
    SessionState(#[source] Box<crate::Error>),
}

impl CustomPopError {
    fn session_state(error: crate::Error) -> Self {
        Self::SessionState(Box::new(error))
    }
}

impl From<GrantSigningError> for CustomPopError {
    fn from(error: GrantSigningError) -> Self {
        match error {
            GrantSigningError::KeyUnavailable(message) => Self::SigningKeyUnavailable(message),
            GrantSigningError::SigningFailed(message) => Self::SigningFailed(message),
        }
    }
}

impl GrantCredential {
    pub(crate) async fn create_custom_pop(
        &self,
        data: serde_json::Value,
    ) -> Result<CustomPop, CustomPopError> {
        // Follow browser lock ordering and prevent removal/logout during signing.
        // Only local lifecycle state is read; bearer freshness is irrelevant.
        let coordinator = self.coordinator().await;
        let _lease = if let Some(coordinator) = &coordinator {
            let lease = coordinator
                .acquire(false)
                .await
                .map_err(CustomPopError::session_state)?;
            active_session(lease.as_ref())
                .await
                .map_err(CustomPopError::session_state)?;
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
            return Err(CustomPopError::GrantExpired);
        }
        // Future issue times are evaluated using the recipient's clock-skew policy.
        if claims.iat >= claims.exp {
            return Err(CustomPopError::InvalidGrant(
                "invalid validity period".into(),
            ));
        }
        if signer.public_key() != claims.cnf {
            return Err(CustomPopError::InvalidGrant(
                "signing key does not match the grant cnf".into(),
            ));
        }
        let proof = CustomPopClaims {
            gid: claims.jti,
            data,
        };
        let pop = signer.sign_jws(CUSTOM_POP_JWS_TYP, &proof).await?;
        if claims.exp <= now_unix() {
            return Err(CustomPopError::GrantExpired);
        }
        Ok(CustomPop { grant, pop })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CUSTOM_POP_CLOCK_SKEW;
    use crate::{
        ClientId, DelegatedGrantCredentialState, GRANT_JWS_TYP, GrantClaims, GrantId,
        actors::auth::grant::pop_signer::{GrantPopSigner, delegated_sign_callback},
    };
    use pubky_common::crypto::Keypair;
    use serde_json::json;

    fn credential() -> (GrantCredential, Keypair) {
        credential_with_issue_offset(0)
    }

    fn credential_with_issue_offset(issue_offset_seconds: u64) -> (GrantCredential, Keypair) {
        let root = Keypair::random();
        let key = Keypair::random();
        let now = now_unix();
        let claims = GrantClaims {
            iss: root.public_key(),
            client_id: ClientId::new("custom-pop.test").unwrap(),
            caps: vec![],
            cnf: key.public_key(),
            jti: GrantId::generate(),
            iat: now + issue_offset_seconds,
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

    #[tokio::test]
    async fn local_and_delegated_proofs_bundle_the_grant_and_arbitrary_json_without_a_bearer() {
        let (credential, key) = credential();
        for local in [false, true] {
            if local {
                credential.state.lock().await.client_signer = GrantPopSigner::local(key.clone());
            }
            for data in [
                json!(null),
                json!(true),
                json!(42),
                json!("é/生产"),
                json!([1, "two"]),
                json!({"gid": "application-owned", "nested": {"challenge": "abc"}}),
            ] {
                let proof = credential.create_custom_pop(data.clone()).await.unwrap();
                assert_eq!(proof.grant, credential.state.lock().await.grant_jws);
                let verified =
                    crate::verify_custom_grant_pop(&proof, DEFAULT_CUSTOM_POP_CLOCK_SKEW).unwrap();
                assert_eq!(verified.data(), &data);
                assert_eq!(verified.grant_claims().cnf, key.public_key());
            }
        }
        assert!(credential.current_bearer().await.is_empty());
    }

    #[tokio::test]
    async fn rejects_expired_grants_and_mismatched_keys() {
        let (credential, _) = credential();
        credential.state.lock().await.client_signer = GrantPopSigner::local(Keypair::random());
        assert!(matches!(
            credential.create_custom_pop(json!(null)).await,
            Err(CustomPopError::InvalidGrant(_))
        ));
        credential.state.lock().await.grant_claims.exp = now_unix();
        assert!(matches!(
            credential.create_custom_pop(json!(null)).await,
            Err(CustomPopError::GrantExpired)
        ));
    }

    #[tokio::test]
    async fn future_issue_times_use_the_verifiers_policy_instead_of_blocking_creation() {
        use crate::custom_pop::CustomPopVerificationError;
        use crate::verify_custom_grant_pop;
        use std::time::Duration;

        let (credential, _) = credential_with_issue_offset(20);
        let proof = credential.create_custom_pop(json!(null)).await.unwrap();
        assert!(verify_custom_grant_pop(&proof, DEFAULT_CUSTOM_POP_CLOCK_SKEW).is_ok());
        assert!(matches!(
            verify_custom_grant_pop(&proof, Duration::ZERO),
            Err(CustomPopVerificationError::GrantNotYetValid)
        ));

        let (credential, _) = credential_with_issue_offset(120);
        let proof = credential.create_custom_pop(json!(null)).await.unwrap();
        assert!(matches!(
            verify_custom_grant_pop(&proof, DEFAULT_CUSTOM_POP_CLOCK_SKEW),
            Err(CustomPopVerificationError::GrantNotYetValid)
        ));
        assert!(verify_custom_grant_pop(&proof, Duration::from_secs(120)).is_ok());
    }

    #[tokio::test]
    async fn replacement_during_signing_keeps_the_original_grant_and_key() {
        let (credential, key) = credential();
        let original = credential.state.lock().await.grant_jws.clone();
        let (replacement, _) = self::credential();
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let resume = std::sync::Arc::new(tokio::sync::Notify::new());
        let signal = std::sync::Arc::clone(&started);
        let wait = std::sync::Arc::clone(&resume);
        credential.state.lock().await.client_signer = GrantPopSigner::delegated(
            "slow-key".into(),
            key.public_key(),
            delegated_sign_callback(move |input| {
                let signature = key.sign(input.as_bytes()).to_bytes().to_vec();
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
        let task =
            tokio::spawn(
                async move { pending.create_custom_pop(json!({"challenge": "abc"})).await },
            );
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
        assert_eq!(
            crate::verify_custom_grant_pop(&proof, DEFAULT_CUSTOM_POP_CLOCK_SKEW)
                .unwrap()
                .data(),
            &json!({"challenge": "abc"})
        );
    }

    #[tokio::test]
    async fn expiration_during_signing_is_rejected() {
        let (credential, key) = credential();
        let expiry = now_unix() + 2;
        let mut state = credential.state.lock().await;
        state.grant_claims.exp = expiry;
        state.client_signer = GrantPopSigner::delegated(
            "slow-key".into(),
            key.public_key(),
            delegated_sign_callback(move |input| {
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
            credential.create_custom_pop(json!(null)).await,
            Err(CustomPopError::GrantExpired)
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
            let error = credential.create_custom_pop(json!(null)).await.unwrap_err();
            if missing {
                assert!(matches!(error, CustomPopError::SigningKeyUnavailable(_)));
            } else {
                assert!(matches!(error, CustomPopError::SigningFailed(_)));
            }
        }
    }
}
