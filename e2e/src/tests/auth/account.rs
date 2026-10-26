use super::*;

/// `GET /account` on the homeserver's ICANN URL with an optional bearer.
async fn get_account(
    client: &PubkyHttpClient,
    url: &str,
    bearer: Option<&str>,
) -> reqwest::Response {
    let mut rb = client.request(Method::GET, &url);
    if let Some(bearer) = bearer {
        rb = rb.header("Authorization", format!("Bearer {bearer}"));
    }
    rb.send().await.unwrap()
}

#[tokio::test]
#[pubky_testnet::test]
async fn account_requires_root_grant_and_survives_disable() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let http_relay_url = testnet.http_relay().local_link_url();

    let keypair = Keypair::random();
    let signer = pubky.signer(keypair.clone());
    signer.signup(&server.public_key(), None).await.unwrap();
    let root_session = signer
        .signin(ClientId::new("app.root").unwrap())
        .await
        .unwrap();

    let scoped_caps = Capabilities::builder()
        .read_write("/pub/scoped.app/")
        .unwrap()
        .finish();
    let auth = PubkyGrantAuthFlow::builder(
        &scoped_caps,
        AuthFlowKind::signin(),
        ClientId::new("scoped.app").unwrap(),
    )
    .relay(http_relay_url)
    .client(pubky.client().clone())
    .start()
    .unwrap();
    signer
        .approve_auth(&auth.authorization_url())
        .await
        .unwrap();
    let scoped_session = auth.await_approval().await.unwrap();

    let url = format!("{}account", server.icann_http_url());

    // Root grant session: the caller's own account.
    let root_bearer = root_session.as_grant().unwrap().current_bearer().await;
    let response = get_account(pubky.client(), &url, Some(&root_bearer)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["pubky"], keypair.public_key().z32());
    assert_eq!(body["disabled"], false);
    assert_eq!(body["used_bytes"], 0);
    assert!(body["quota"]["effective"].is_object());
    assert!(body["quota"]["overrides"].is_object());

    // The SDK reads the same item.
    let account = root_session.account().await.unwrap();
    assert_eq!(account.pubky, keypair.public_key());
    assert!(!account.disabled);
    assert_eq!(account.used_bytes, 0);
    assert_eq!(serde_json::to_value(&account).unwrap(), body);
    let err = scoped_session.account().await.unwrap_err();
    assert!(
        matches!(err, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::FORBIDDEN),
        "scoped session.account() must be forbidden, got {err:?}"
    );

    // Scoped grant session: forbidden.
    let scoped_bearer = scoped_session.as_grant().unwrap().current_bearer().await;
    let response = get_account(pubky.client(), &url, Some(&scoped_bearer)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // No session: unauthorized.
    let response = get_account(pubky.client(), &url, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // A disabled user can still read their account, and sees why writes fail.
    admin_disable_user(server, &keypair.public_key()).await;
    let response = get_account(pubky.client(), &url, Some(&root_bearer)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["disabled"], true);
}
