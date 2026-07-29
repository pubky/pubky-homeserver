use super::*;

#[tokio::test]
#[pubky_testnet::test]
async fn signup_with_token() {
    // 1. Start a test homeserver with closed signups (i.e. signup tokens required)
    let mut config = ConfigToml::default_test_config();
    config.general.signup_mode = SignupMode::TokenRequired;

    let testnet = EphemeralTestnet::builder()
        .config(config)
        .build()
        .await
        .unwrap();

    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer = pubky.signer(Keypair::random());
    let signer2 = pubky.signer(Keypair::random());

    // 2. Try to signup with an invalid token "AAAAA" and expect failure.
    let invalid_signup = signer
        .signup(&server.public_key(), Some("AAAA-BBBB-CCCC"))
        .await;
    assert!(
        invalid_signup.is_err(),
        "Signup should fail with an invalid signup token"
    );
    let err = invalid_signup.unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("401"),
        "Signup should fail with a 401 status code"
    );

    // 3. Call the admin endpoint to generate a valid signup token.
    let valid_token = server
        .admin_server()
        .expect("admin server should be enabled")
        .create_signup_token()
        .await
        .unwrap();

    // 4. Now signup with the valid token. Expect account creation success.
    signer
        .signup(&server.public_key(), Some(&valid_token))
        .await
        .unwrap();

    // 5. Finally, sign in with the same keypair and verify that a session is returned.
    let pubky = signer.public_key();
    let session = signer
        .signin(ClientId::new("signup.token.test").unwrap())
        .await
        .unwrap();
    assert_eq!(
        session.info().public_key(),
        &pubky,
        "Signed-in session pubky should correspond to the signer's public key"
    );

    // 6. Signup with the same token again and expect failure.
    let signup_again = signer2
        .signup(&server.public_key(), Some(&valid_token))
        .await;
    let err = signup_again.expect_err("Signup with an already used token should fail");
    assert!(err.to_string().contains("401"));
    assert!(err.to_string().contains("Token already used"));
}

#[tokio::test]
#[pubky_testnet::test]
async fn get_signup_token() {
    // 1. Start a test homeserver with closed signups (i.e. signup tokens required)
    let mut config = ConfigToml::default_test_config();
    config.general.signup_mode = SignupMode::TokenRequired;

    let testnet = EphemeralTestnet::builder()
        .config(config)
        .build()
        .await
        .unwrap();

    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let client = PubkyHttpClient::new().unwrap();
    let base_url = server.icann_http_url();

    // 2. GET /signup_tokens/invalid-format → 400
    let response = client
        .request(Method::GET, &format!("{}signup_tokens/invalid", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Invalid token format should return 400"
    );

    // 3. GET /signup_tokens/AAAA-BBBB-CCCC (nonexistent) → 404
    let response = client
        .request(
            Method::GET,
            &format!("{}signup_tokens/AAAA-BBBB-CCCC", base_url),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "Nonexistent token should return 404"
    );

    // 4. Generate valid token via admin API
    let valid_token = server
        .admin_server()
        .expect("admin server should be enabled")
        .create_signup_token()
        .await
        .unwrap();

    // 5. GET /signup_tokens/<valid> → 200 with status: "valid"
    let response = client
        .request(
            Method::GET,
            &format!("{}signup_tokens/{}", base_url, valid_token),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Valid token should return 200"
    );
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "Response should have Cache-Control: no-store header"
    );
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body["status"], "valid",
        "Unused token should have status 'valid'"
    );
    assert!(
        body["created_at"].is_string(),
        "Response should have created_at field"
    );

    // 6. Use token with POST /signup
    let signer = pubky.signer(Keypair::random());
    let _session = signer
        .signup_cookie(&server.public_key(), Some(&valid_token))
        .await
        .unwrap();

    // 7. GET /signup_tokens/<used> → 200 with status: "used"
    let response = client
        .request(
            Method::GET,
            &format!("{}signup_tokens/{}", base_url, valid_token),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Used token should still return 200"
    );
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body["status"], "used",
        "Used token should have status 'used'"
    );
    assert!(
        body["created_at"].is_string(),
        "Response should have created_at field"
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn signup_via_direct_deeplink() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer = pubky.signer(Keypair::random());
    let deeplink = format!("pubkyauth://direct_signup?hs={}", server.public_key().z32());

    signer.handle_deeplink(&deeplink).await.unwrap();

    let session = signer
        .signin(ClientId::new("direct.signup.test").unwrap())
        .await
        .unwrap();
    assert_eq!(
        session.info().public_key(),
        &signer.public_key(),
        "Signed-in session should belong to the signer"
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn signup_via_direct_deeplink_with_token() {
    // The direct deep link must carry a valid token.
    let mut config = ConfigToml::default_test_config();
    config.general.signup_mode = SignupMode::TokenRequired;

    let testnet = EphemeralTestnet::builder()
        .config(config)
        .build()
        .await
        .unwrap();

    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let token = server
        .admin_server()
        .expect("admin server should be enabled")
        .create_signup_token()
        .await
        .unwrap();

    let signer = pubky.signer(Keypair::random());
    let deeplink = DirectSignupDeepLink::new(
        DeepLinkScheme::PubkyAuth,
        DirectSignupParams {
            homeserver: server.public_key(),
            signup_token: Some(token),
        },
    )
    .to_string();

    signer.handle_deeplink(&deeplink).await.unwrap();

    let session = signer
        .signin(ClientId::new("direct.signup.token.test").unwrap())
        .await
        .unwrap();
    assert_eq!(
        session.info().public_key(),
        &signer.public_key(),
        "Signed-in session should belong to the signer"
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn direct_signup_deeplink_rejects_missing_or_invalid_token() {
    let mut config = ConfigToml::default_test_config();
    config.general.signup_mode = SignupMode::TokenRequired;

    let testnet = EphemeralTestnet::builder()
        .config(config)
        .build()
        .await
        .unwrap();

    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let missing_token_link = DirectSignupDeepLink::new(
        DeepLinkScheme::PubkyAuth,
        DirectSignupParams {
            homeserver: server.public_key(),
            signup_token: None,
        },
    )
    .to_string();
    let missing_token_error = pubky
        .signer(Keypair::random())
        .handle_deeplink(&missing_token_link)
        .await
        .expect_err("direct signup without a token should fail");
    assert_signup_rejected(
        missing_token_error,
        StatusCode::BAD_REQUEST,
        "Token required",
    );

    let invalid_token_link = DirectSignupDeepLink::new(
        DeepLinkScheme::PubkyAuth,
        DirectSignupParams {
            homeserver: server.public_key(),
            signup_token: Some("AAAA-BBBB-CCCC".into()),
        },
    )
    .to_string();
    let invalid_token_error = pubky
        .signer(Keypair::random())
        .handle_deeplink(&invalid_token_link)
        .await
        .expect_err("direct signup with an invalid token should fail");
    assert_signup_rejected(
        invalid_token_error,
        StatusCode::UNAUTHORIZED,
        "Invalid token",
    );
}

fn assert_signup_rejected(error: Error, expected_status: StatusCode, expected_message: &str) {
    match error {
        Error::Request(RequestError::Server { status, message }) => {
            assert_eq!(status, expected_status);
            assert_eq!(message, expected_message);
        }
        error => panic!("expected a homeserver signup error, got {error:?}"),
    }
}
