use super::*;

#[tokio::test]
#[pubky_testnet::test]
async fn unauthorized_put_delete() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    // Owner user
    let owner = pubky.signer(Keypair::random());
    let owner_session = owner
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    let path = "/pub/foo.txt";

    // Someone tries to write to owner's namespace -> 401 Unauthorized
    let owner_url = format!(
        "{}/{}",
        owner_session.info().public_key(),
        path.trim_start_matches('/')
    );

    let owner_transport_url = owner_url
        .clone()
        .into_pubky_resource()
        .unwrap()
        .to_transport_url()
        .unwrap();

    let response = pubky
        .client()
        .request(Method::PUT, &owner_transport_url)
        .body(vec![0, 1, 2, 3, 4])
        .send()
        .await
        .unwrap();

    assert!(matches!(response.status(), StatusCode::UNAUTHORIZED));

    // Owner writes successfully
    let resp = owner_session
        .storage()
        .put(path, vec![0, 1, 2, 3, 4])
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Other tries to delete owner's file → 401 Unauthorized
    let response = pubky
        .client()
        .request(Method::DELETE, &owner_transport_url)
        .send()
        .await
        .unwrap();

    assert!(matches!(response.status(), StatusCode::UNAUTHORIZED));

    // Owner can read contents
    let body = owner_session
        .storage()
        .get(path)
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(body, bytes::Bytes::from(vec![0, 1, 2, 3, 4]));
}

#[tokio::test]
#[pubky_testnet::test]
async fn priv_owner_with_cap_is_authorized() {
    // The owner exercises the full read/write surface on their own `/priv/` data,
    // and gets a real 404 (not 401/403) for an absent private path. Denial for the
    // other actor tiers is covered by the `private_data` matrix.
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let owner = pubky.signer(Keypair::random());
    let session = owner
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    let path = "/priv/app/secret.txt";
    let content = vec![1, 2, 3];

    // Write, then read back the same bytes.
    let resp = session.storage().put(path, content.clone()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = session
        .storage()
        .get(path)
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(body, bytes::Bytes::from(content));

    // The private directory lists for the owner.
    let listing = session
        .storage()
        .list("/priv/app/")
        .unwrap()
        .send()
        .await
        .unwrap();
    assert!(
        !listing.is_empty(),
        "owner should see their private listing"
    );

    // Delete succeeds.
    let resp = session.storage().delete(path).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // An absent private path is a real 404 for the authorized owner.
    let err = session
        .storage()
        .get("/priv/app/absent.txt")
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::NOT_FOUND)
    );
}
