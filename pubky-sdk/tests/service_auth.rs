#![cfg(all(feature = "service-auth-verifier", not(target_arch = "wasm32")))]

use pubky::{
    ClientId, Keypair, ServiceAuthProof,
    service_auth::{
        MemoryReplayStore, ServiceAuthVerificationError, ServiceAuthVerifier, VerificationPolicy,
    },
};

#[tokio::test]
#[pubky_testnet::test]
async fn restored_native_session_authenticates_to_an_external_verifier() {
    let testnet = pubky_testnet::EphemeralTestnet::builder()
        .build()
        .await
        .unwrap();
    let sdk = testnet.sdk().unwrap();
    let user = Keypair::random();
    let signer = sdk.signer(user.clone());
    signer
        .signup(&testnet.homeserver_app().public_key(), None)
        .await
        .unwrap();
    let session = signer
        .signin(ClientId::new("external-service.test").unwrap())
        .await
        .unwrap();
    let secret = session
        .as_grant()
        .unwrap()
        .export_local_secret()
        .await
        .unwrap();
    let restored = sdk.restore_session(&secret).await.unwrap();
    let credentials = restored
        .as_grant()
        .unwrap()
        .create_service_auth_proof("inbox")
        .await
        .unwrap();
    let body = serde_json::to_string(&credentials).unwrap();
    let received: ServiceAuthProof = serde_json::from_str(&body).unwrap();
    let verifier = ServiceAuthVerifier::new(
        "inbox",
        VerificationPolicy::default(),
        MemoryReplayStore::new(100).unwrap(),
    )
    .unwrap();
    let identity = verifier.verify_and_consume(&received).await.unwrap();
    assert_eq!(identity.identity(), &user.public_key());
    assert_eq!(
        identity.grant_id(),
        &restored.as_grant().unwrap().grant_id().await
    );
    assert!(matches!(
        verifier.verify_and_consume(&received).await,
        Err(ServiceAuthVerificationError::Replay)
    ));
}
