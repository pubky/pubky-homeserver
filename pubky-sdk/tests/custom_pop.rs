#![cfg(not(target_arch = "wasm32"))]

use pubky::custom_pop::{CustomPop, DEFAULT_CUSTOM_POP_CLOCK_SKEW, verify_custom_grant_pop};
use pubky::{ClientId, Keypair};
use serde_json::json;

#[tokio::test]
#[pubky_testnet::test]
async fn restored_session_creates_a_self_contained_custom_proof() {
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
        .signin(ClientId::new("custom-pop.test").unwrap())
        .await
        .unwrap();
    let secret = session
        .as_grant()
        .unwrap()
        .export_local_secret()
        .await
        .unwrap();
    let restored = sdk.restore_session(&secret).await.unwrap();
    let data =
        json!({"audience": "inbox", "challenge": "server-challenge", "nested": [true, null]});
    let credentials = restored
        .as_grant()
        .unwrap()
        .create_custom_pop(data.clone())
        .await
        .unwrap();
    let body = serde_json::to_string(&credentials).unwrap();
    let received: CustomPop = serde_json::from_str(&body).unwrap();
    let verified = verify_custom_grant_pop(&received, DEFAULT_CUSTOM_POP_CLOCK_SKEW).unwrap();
    assert_eq!(verified.identity(), &user.public_key());
    assert_eq!(
        verified.grant_claims().jti,
        restored.as_grant().unwrap().grant_id().await
    );
    assert_eq!(verified.data(), &data);
}
