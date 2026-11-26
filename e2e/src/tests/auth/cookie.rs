use super::*;
use crate::tests::legacy_cookie_session;

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
    signer.signup(&server.public_key(), None).await.unwrap();
    let session = legacy_cookie_session(&pubky, &signer).await;

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
    admin_disable_user(server, &user_pubky).await;

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

    let session2 = legacy_cookie_session(&pubky, &signer).await;
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
    signer.signup(&homeserver.public_key(), None).await.unwrap();
    let session = legacy_cookie_session(&pubky, &signer).await;

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

    alice.signup(&server.public_key(), None).await.unwrap();
    let alice_session = legacy_cookie_session(&pubky, &alice).await;
    bob.signup(&server.public_key(), None).await.unwrap();
    let bob_session = legacy_cookie_session(&pubky, &bob).await;

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
    signer.signup(&homeserver.public_key(), None).await.unwrap();
    let session = legacy_cookie_session(&pubky, &signer).await;

    // First signout succeeds and invalidates the cookie server-side.
    session.clone().signout().await.unwrap();

    // A second signout with the now-stale cookie must be a 200 no-op.
    session
        .signout()
        .await
        .expect("second signout must be idempotent");
}
