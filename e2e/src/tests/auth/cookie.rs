use super::*;

#[tokio::test]
#[pubky_testnet::test]
#[allow(deprecated, reason = "Test exercises the deprecated cookie auth flow")]
async fn basic_signer_signup() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let keypair = Keypair::random();
    let signer = pubky.signer(keypair.clone());
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    assert_eq!(session.info().public_key(), &keypair.public_key());
    assert_eq!(
        session.info().capabilities().first().unwrap(),
        &Capability::root()
    ); // Gets root caps by default on signup

    // Write sample file to verify the session works.
    let response = session
        .storage()
        .put("/pub/test.app/hello.txt", b"world".to_vec())
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "file upload should succeed"
    );
}

#[tokio::test]
#[pubky_testnet::test]
#[allow(deprecated, reason = "Test exercises the deprecated cookie auth flow")]
async fn basic_signer_signin() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let keypair = Keypair::random();
    let signer = pubky.signer(keypair.clone());
    signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    let signer = pubky.signer(keypair.clone()); // Construct a new signer to ensure we're not reusing any in-memory state from signup
    let session = signer.signin_cookie().await.unwrap();

    assert_eq!(session.info().public_key(), &keypair.public_key());
    assert_eq!(
        session.info().capabilities().first().unwrap(),
        &Capability::root()
    ); // Gets root caps by default on signup
}

#[tokio::test]
#[pubky_testnet::test]
#[allow(deprecated, reason = "Test exercises the deprecated cookie auth flow")]
async fn cookie_auth_flow() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let http_relay_url = testnet.http_relay().local_link_url();

    // Third-party app (keyless)
    let caps = Capabilities::builder()
        .read_write("/pub/pubky.app/")
        .unwrap()
        .read("/pub/foo.bar/file")
        .unwrap()
        .finish();
    let auth = PubkyCookieAuthFlow::builder(&caps, AuthFlowKind::signin())
        .relay(http_relay_url)
        .client(pubky.client().clone())
        .start()
        .unwrap();
    let raw_deep_link = auth.authorization_url().to_string();

    // raw_deep_link is handed over via QR code to the signer
    // Signer continues with the deep link:
    let deep_link = DeepLink::from_str(&raw_deep_link).unwrap();
    let signin_deep_link = match deep_link {
        DeepLink::Signin(signin) => signin,
        _ => panic!("Expected a signin deep link"),
    };
    assert_eq!(&signin_deep_link.params().capabilities, &caps);
    assert_eq!(
        signin_deep_link.params().relay.as_str(),
        testnet.http_relay().local_link_url().as_str()
    );

    // Signer creates a new user, signs it up and approves the auth request.
    let signer = pubky.signer(Keypair::random());
    signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    signer
        .approve_auth(&auth.authorization_url())
        .await
        .unwrap();

    // Third-party app waits for the signers response
    // Retrieve the session-bound agent
    let user = auth.await_approval().await.unwrap();

    assert_eq!(user.info().public_key(), &signer.public_key());
    assert_scoped_write_access(&user).await;
}

#[tokio::test]
#[pubky_testnet::test]
#[allow(deprecated, reason = "Test exercises the deprecated cookie auth flow")]
async fn auth_flow_signup_preserves_deep_link_fields() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let http_relay_url = testnet.http_relay().local_link_url();

    // Third-party app (keyless)
    let caps = Capabilities::builder()
        .read_write("/pub/pubky.app/")
        .unwrap()
        .read("/pub/foo.bar/file")
        .unwrap()
        .finish();

    // Third-party app (keyless)
    let auth = PubkyCookieAuthFlow::builder(
        &caps,
        AuthFlowKind::signup(server.public_key(), Some("1234567890".to_string())),
    )
    .relay(http_relay_url)
    .client(pubky.client().clone())
    .start()
    .unwrap();

    let raw_deep_link = auth.authorization_url().to_string();
    let deep_link = DeepLink::from_str(&raw_deep_link).unwrap();

    let signup_deep_link = match deep_link {
        DeepLink::Signup(signup) => signup,
        _ => panic!("Expected a signup deep link"),
    };
    assert_eq!(&signup_deep_link.params().capabilities, &caps);
    assert_eq!(
        signup_deep_link.params().relay.as_str(),
        testnet.http_relay().local_link_url().as_str()
    );
    assert_eq!(&signup_deep_link.params().homeserver, &server.public_key());
    assert_eq!(
        signup_deep_link.params().signup_token.as_deref(),
        Some("1234567890")
    );

    // Signer authenticator
    let signer = pubky.signer(Keypair::random());
    signer
        .signup_cookie(&signup_deep_link.params().homeserver, None)
        .await
        .unwrap();
    signer
        .approve_auth(&auth.authorization_url())
        .await
        .unwrap();

    // Retrieve the session-bound agent (third party app)
    let user = auth.await_approval().await.unwrap();

    assert_eq!(user.info().public_key(), &signer.public_key());

    assert_scoped_write_access(&user).await;
}

#[tokio::test]
#[pubky_testnet::test]
#[allow(deprecated, reason = "Test exercises the deprecated cookie auth flow")]
async fn auth_flow_survives_long_poll_timeout() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let http_relay_url = testnet.http_relay().local_link_url();

    // Third-party app (keyless) with a short HTTP timeout to force long-poll retries
    let capabilities = Capabilities::builder()
        .read_write("/pub/pubky.app/")
        .unwrap()
        .read("/pub/foo.bar/file")
        .unwrap()
        .finish();

    let client = testnet
        .client_builder()
        .request_timeout(Duration::from_millis(1_000))
        .build()
        .unwrap();

    let auth = PubkyCookieAuthFlow::builder(&capabilities, AuthFlowKind::signin())
        .client(client)
        .relay(http_relay_url)
        .start()
        .unwrap();

    // Signer side: sign up, then approve after a delay (to exercise timeout/retry)
    let signer = pubky.signer(Keypair::random());
    let signer_pubky = signer.public_key();
    signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    let url_clone = auth.authorization_url().clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        signer.approve_auth(&url_clone).await.unwrap();
    });

    // The long-poll should survive timeouts and eventually yield a session.
    let session = auth.await_approval().await.unwrap();
    assert_eq!(session.info().public_key(), &signer_pubky);

    assert_scoped_write_access(&session).await;
}

#[tokio::test]
#[pubky_testnet::test]
async fn disabled_user() {
    // This test requires the admin server to disable users
    let testnet = EphemeralTestnet::builder()
        .config(ConfigToml::default_test_config())
        .build()
        .await
        .unwrap();

    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    // Create a brand-new user and session
    let signer = pubky.signer(Keypair::random());
    let user_pubky = signer.public_key().clone();
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    // Create a test file to ensure the user can write to their account
    let file_path = "/pub/pubky.app/foo";
    session
        .storage()
        .put(file_path, Vec::<u8>::new())
        .await
        .unwrap();

    // Make sure the user can read their own file
    let response = session.storage().get(file_path).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "User should be able to read their own file"
    );

    // Disable the user via admin API
    let admin_socket = server
        .admin_server()
        .expect("admin server should be enabled")
        .listen_socket();
    let admin_client = PubkyHttpClient::new().unwrap();
    let response = admin_client
        .request(
            Method::POST,
            &format!("http://{admin_socket}/users/{}/disable", user_pubky.z32()),
        )
        .header("X-Admin-Password", "admin")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // User can still read their own file
    let response = session.storage().get(file_path).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // User can no longer write
    let err = session
        .storage()
        .put(file_path, Vec::<u8>::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::FORBIDDEN),
        "Disabled user must get 403 on write"
    );

    // User can delete their file (deletes should still be allowed to enable cleanup by the user or test)
    let response = session.storage().delete(file_path).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "User should be able to delete their own file even when disabled"
    );

    // Fresh sign-in should still succeed (disabled means no writes, not no login)
    session.signout().await.unwrap();

    let session2 = signer
        .signin_cookie()
        .await
        .expect("Signin should succeed for disabled users");
    assert_eq!(session2.info().public_key(), &user_pubky);
}

#[tokio::test]
#[pubky_testnet::test]
#[allow(
    deprecated,
    reason = "Test exercises legacy cookie-session restore API"
)]
async fn session_secret_export_import_restores_session() {
    let testnet = build_full_testnet().await;
    let homeserver = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    // Create user and session-bound agent
    let signer = pubky.signer(Keypair::random());
    let session = signer
        .signup_cookie(&homeserver.public_key(), None)
        .await
        .unwrap();

    // Write something with the live agent
    session
        .storage()
        .put("/pub/app/persist.txt", "hello")
        .await
        .unwrap();

    // Export session's secret and drop the session (simulate restart).
    // On native the cookie secret is always captured, so unwrap is safe.
    let secret_token = session.as_cookie().unwrap().export_secret().unwrap();
    drop(session);

    // Rehydrate from the exported secret (validates the session)
    let restored = pubky.restore_session(&secret_token).await.unwrap();

    assert_eq!(restored.info().public_key(), &signer.public_key());

    // Still authorized to write
    restored
        .storage()
        .put("/pub/app/persist.txt", "hello2")
        .await
        .unwrap();
}

#[tokio::test]
#[pubky_testnet::test]
async fn multiple_users() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    // Two independent users
    let alice = pubky.signer(Keypair::random());
    let bob = pubky.signer(Keypair::random());

    let alice_session = alice
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let bob_session = bob.signup_cookie(&server.public_key(), None).await.unwrap();

    // Each session is bound to its own pubkey and has root caps
    let a_sess = alice_session.info();
    assert_eq!(a_sess.public_key(), &alice.public_key());
    assert!(a_sess.capabilities().contains(&Capability::root()));

    let b_sess = bob_session.info();
    assert_eq!(b_sess.public_key(), &bob.public_key());
    assert!(b_sess.capabilities().contains(&Capability::root()));
}

#[tokio::test]
#[pubky_testnet::test]
async fn signout_is_idempotent() {
    let testnet = build_full_testnet().await;
    let homeserver = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer = pubky.signer(Keypair::random());
    let session = signer
        .signup_cookie(&homeserver.public_key(), None)
        .await
        .unwrap();

    // First signout succeeds and invalidates the cookie server-side.
    session.clone().signout().await.unwrap();

    // A second signout with the now-stale cookie must be a 200 no-op.
    session
        .signout()
        .await
        .expect("second signout must be idempotent");
}
