use super::*;
use pubky_testnet::pubky_common::auth::{
    grant_revocation::{
        ConditionalGrantRevocation, GrantRevocationDisposition, GrantRevocationReceipt,
    },
    grant_session_responses::GrantSessionInfo,
    jws::{GrantId, RandomId},
};

#[tokio::test]
#[pubky_testnet::test]
async fn conditional_revocation_http_receipt_and_rejections() {
    let testnet = build_full_testnet().await;
    let sdk = testnet.sdk().unwrap();
    let signer = sdk.signer(Keypair::random());
    signer
        .signup(&testnet.homeserver_app().public_key(), None)
        .await
        .unwrap();
    let session = grant_session(
        &testnet,
        &signer,
        Capabilities::builder()
            .read("/pub/conditional/")
            .unwrap()
            .finish(),
        "conditional.test",
    )
    .await;
    let bearer = session.as_grant().unwrap().current_bearer().await;
    let session_url = format!(
        "https://_pubky.{}/auth/grant/session",
        signer.public_key().z32()
    );
    let url = format!("{session_url}-revocation");
    let info: GrantSessionInfo = sdk
        .client()
        .request(Method::GET, &session_url)
        .bearer_auth(&bearer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request = ConditionalGrantRevocation {
        operation_id: RandomId::generate(),
        grant_id: info.grant_id.clone(),
        pubky: info.pubky.clone(),
        client_id: info.client_id.clone(),
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    let missing = sdk
        .client()
        .request(Method::POST, &url)
        .header("Content-Type", "application/json")
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let proof_only = sdk
        .client()
        .request(Method::POST, &url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&serde_json::json!({"grant":"ignored", "pop":"ignored"})).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(proof_only.status(), StatusCode::UNAUTHORIZED);
    let legacy = sdk
        .client()
        .request(Method::DELETE, &session_url)
        .bearer_auth("x".repeat(43))
        .send()
        .await
        .unwrap();
    assert_eq!(legacy.status(), StatusCode::OK);
    assert!(legacy.bytes().await.unwrap().is_empty());

    for field in ["grant_id", "pubky", "client_id"] {
        let mut wrong = request.clone();
        match field {
            "grant_id" => wrong.grant_id = GrantId::generate(),
            "pubky" => wrong.pubky = Keypair::random().public_key(),
            _ => wrong.client_id = ClientId::new("other.test").unwrap(),
        }
        let response = sdk
            .client()
            .request(Method::POST, &url)
            .bearer_auth(&bearer)
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&wrong).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    }
    let oversized = serde_json::json!({"padding":"x".repeat(4096)});
    let response = sdk
        .client()
        .request(Method::POST, &url)
        .bearer_auth(&bearer)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&oversized).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let mut unknown = serde_json::to_value(&request).unwrap();
    unknown["proof"] = serde_json::json!("not accepted as another authority");
    let response = sdk
        .client()
        .request(Method::POST, &url)
        .bearer_auth(&bearer)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&unknown).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let response = sdk
        .client()
        .request(Method::POST, &url)
        .bearer_auth(&bearer)
        .header("Content-Type", "application/json")
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let receipt: GrantRevocationReceipt = response.json().await.unwrap();
    assert_eq!(
        receipt.disposition,
        GrantRevocationDisposition::OriginalBearerRevoked
    );
    assert_eq!(receipt.operation_id, request.operation_id);
    assert_eq!(receipt.grant_id, request.grant_id);
    assert_eq!(receipt.pubky, request.pubky);
    assert_eq!(receipt.client_id, request.client_id);
    assert_eq!(receipt.homeserver, testnet.homeserver_app().public_key());
    // A caller that lost the receipt must not treat a duplicate as committed success.
    let repeated = sdk
        .client()
        .request(Method::POST, &url)
        .bearer_auth(&bearer)
        .header("Content-Type", "application/json")
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(repeated.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[pubky_testnet::test]
async fn conditional_revocation_http_rejects_rotation_and_discarded_receipt_replay() {
    let testnet = build_full_testnet().await;
    let sdk = testnet.sdk().unwrap();
    let signer = sdk.signer(Keypair::random());
    signer
        .signup(&testnet.homeserver_app().public_key(), None)
        .await
        .unwrap();
    let session = signer
        .signin(ClientId::new("conditional.test").unwrap())
        .await
        .unwrap();
    let bearer = session.as_grant().unwrap().current_bearer().await;
    let session_url = format!(
        "https://_pubky.{}/auth/grant/session",
        signer.public_key().z32()
    );
    let info: GrantSessionInfo = sdk
        .client()
        .request(Method::GET, &session_url)
        .bearer_auth(&bearer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let request = ConditionalGrantRevocation {
        operation_id: RandomId::generate(),
        grant_id: info.grant_id,
        pubky: info.pubky,
        client_id: info.client_id,
    };
    let secret = session
        .as_grant()
        .unwrap()
        .export_local_secret()
        .await
        .unwrap();
    let replacement = sdk.restore_session(&secret).await.unwrap();
    let response = sdk
        .client()
        .request(Method::POST, &format!("{session_url}-revocation"))
        .bearer_auth(&bearer)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&request).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // Read with the replacement without using a session helper that could refresh it.
    let current = replacement.as_grant().unwrap().current_bearer().await;
    assert_ne!(current, bearer);
    let still_active = sdk
        .client()
        .request(Method::GET, &session_url)
        .bearer_auth(&current)
        .send()
        .await
        .unwrap();
    assert_eq!(still_active.status(), StatusCode::OK);

    // Commit using the actual replacement, then discard the receipt body. This
    // covers an acknowledgement that was not retained, not a safe remote retry.
    let url = format!("{session_url}-revocation");
    let committed = sdk
        .client()
        .request(Method::POST, &url)
        .bearer_auth(&current)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&request).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(committed.status(), StatusCode::OK);
    drop(committed);
    let repeated = sdk
        .client()
        .request(Method::POST, &url)
        .bearer_auth(&current)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&request).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(repeated.status(), StatusCode::UNAUTHORIZED);
    // Prove revocation, rather than a refreshable bearer timeout, without
    // accepting the failed duplicate as an affirmative receipt.
    let error = sdk.restore_session(&secret).await.unwrap_err();
    assert!(
        matches!(error, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::UNAUTHORIZED),
        "restoring the revoked grant must return 401, got {error:?}"
    );
}
