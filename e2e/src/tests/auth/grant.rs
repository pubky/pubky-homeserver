use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pubky_testnet::pubky::deep_links::GrantApprovalFormat;
use pubky_testnet::pubky_common::{
    auth::{
        grant::GrantClaims,
        jws::{GrantId, GRANT_JWS_TYP},
    },
    crypto::PublicKey,
    encryption_keys::ScopedEncryptionKeyBundle,
    StoragePath,
};
use std::time::{SystemTime, UNIX_EPOCH};
// =====================================================================
// Grant + Proof-of-Possession auth flow tests
// =====================================================================
//
// These exercise the full client_id / cpk pipeline: PubkyGrantAuthFlow generates a client keypair, the signer
// (Ring) signs a `pubky-grant` JWS, the homeserver mints an opaque bearer, and
// the SDK transparently attaches `Authorization: Bearer ...` on every
// subsequent request.

#[tokio::test]
#[pubky_testnet::test]
async fn signed_approval_storage_and_encryption_permissions_are_independent() {
    let testnet = build_full_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let signer = pubky.signer(Keypair::random());
    signer
        .signup(&testnet.homeserver_app().public_key(), None)
        .await
        .unwrap();
    let path = StoragePath::new("/priv/chat/keys/message").unwrap();

    for (requested, key_scope, storage_allowed) in [
        ("/:rw", None, true),
        ("/:rw,/priv/chat/keys/:e", Some("/priv/chat/keys/"), true),
        ("/priv/chat/keys/:e", Some("/priv/chat/keys/"), false),
        ("/:rwe", Some("/"), true),
    ] {
        let caps = requested.parse().unwrap();
        let flow = PubkyGrantAuthFlow::builder(
            &caps,
            AuthFlowKind::signin(),
            ClientId::new("backup.test").unwrap(),
        )
        .approval_format(GrantApprovalFormat::SignedApprovalV1)
        .relay(testnet.http_relay().local_link_url())
        .client(pubky.client().clone())
        .start()
        .unwrap();
        signer.approve_auth(flow.authorization_url()).await.unwrap();
        let credential = flow.await_credential().await.unwrap();
        let keys = credential.encryption_keys().unwrap();
        assert_eq!(
            keys.scopes().map(ToString::to_string).collect::<Vec<_>>(),
            key_scope.into_iter().collect::<Vec<_>>()
        );
        assert_eq!(keys.derive_for_path(&path).is_ok(), key_scope.is_some());
        if key_scope == Some("/priv/chat/keys/") {
            assert!(keys
                .derive_for_path(&StoragePath::new("/priv/chat/archive").unwrap())
                .is_err());
        }
        let exported = credential.export_local_secret().await.unwrap();
        let session = PubkySession::from_grant_credential(pubky.client().clone(), credential);
        let write = session
            .storage()
            .put(path.as_str(), b"opaque ciphertext".to_vec())
            .await;
        let read = session.storage().get(path.as_str()).await;
        if storage_allowed {
            write.unwrap();
            assert_eq!(
                read.unwrap().bytes().await.unwrap().as_ref(),
                b"opaque ciphertext"
            );
        } else {
            for error in [write.unwrap_err(), read.unwrap_err()] {
                assert!(
                    matches!(error, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::FORBIDDEN)
                );
            }
        }
        session.signout().await.unwrap();
        let (_, recovered) =
            pubky_testnet::pubky::GrantCredential::restore_encryption_keys(&exported)
                .unwrap()
                .unwrap();
        assert_eq!(
            recovered.derive_for_path(&path).is_ok(),
            key_scope.is_some()
        );
    }
}

#[tokio::test]
#[pubky_testnet::test]
async fn signer_signup_signin_write_file() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    // Signer creates the user.
    let signer = pubky.signer(Keypair::random());
    signer.signup(&server.public_key(), None).await.unwrap();

    // Signin
    let client_id = ClientId::new("test.app").unwrap();
    let session = signer.signin(client_id).await.unwrap();

    assert_eq!(session.info().public_key(), &signer.public_key());
    assert!(session
        .info()
        .capabilities()
        .iter()
        .any(Capability::is_root));

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
async fn auth_flow() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let http_relay_url = testnet.http_relay().local_link_url();

    // 1. Signer (Ring) creates the user.
    let identity = Keypair::random();
    let signer = pubky.signer(identity.clone());
    signer.signup(&server.public_key(), None).await.unwrap();

    // 2. Third-party app starts an auth flow with a `client_id` — this
    //    uses PubkyGrantAuthFlow (grant mode) which emits a deep link
    //    with `cid` and `cpk` query params.
    let caps = Capabilities::builder()
        .read_write("/pub/pubky.app/")
        .unwrap()
        .encryption_keys("/pub/pubky.app/")
        .unwrap()
        .read("/pub/foo.bar/file")
        .unwrap()
        .encryption_keys("/pub/foo.bar/file")
        .unwrap()
        .finish();
    let app_kp = Keypair::random();
    let auth = PubkyGrantAuthFlow::builder(
        &caps,
        AuthFlowKind::signin(),
        ClientId::new("test.app").unwrap(),
    )
    .approval_format(GrantApprovalFormat::SignedApprovalV1)
    .relay(http_relay_url)
    .client(pubky.client().clone())
    .client_keypair(app_kp.clone())
    .start()
    .unwrap();

    // The deep link should advertise both `cid` and `cpk`.
    let url = auth.authorization_url();
    let query_string = url.query().unwrap_or_default();
    assert!(
        query_string.contains("cid=test.app"),
        "deep link must contain cid: {query_string}"
    );
    assert!(
        query_string.contains(&format!("cpk={}", app_kp.public_key().z32())),
        "deep link must contain cpk: {query_string}"
    );

    let state = auth.save_local().unwrap();
    drop(auth);
    let auth = PubkyGrantAuthFlow::restore(state, pubky.client().clone()).unwrap();

    // 3. Signer approves — delivers a signed envelope with the grant and keys.
    signer
        .approve_auth(&auth.authorization_url())
        .await
        .unwrap();

    // 4. App verifies the envelope, retains keys, and exchanges only the grant.
    let credential = auth.await_credential().await.unwrap();
    let path = StoragePath::new("/pub/pubky.app/message").unwrap();
    let expected = ScopedEncryptionKeyBundle::from_identity_secret(&identity.secret(), [&path]);
    let derived = credential
        .encryption_keys()
        .unwrap()
        .derive_for_path(&path)
        .unwrap();
    assert_eq!(*derived, *expected.derive_for_path(&path).unwrap());
    let session = PubkySession::from_grant_credential(pubky.client().clone(), credential);
    assert_eq!(session.info().public_key(), &signer.public_key());

    let cloned = session.clone();
    session.as_grant().unwrap().force_refresh().await.unwrap();
    assert_eq!(
        *cloned
            .as_grant()
            .unwrap()
            .encryption_keys()
            .unwrap()
            .derive_for_path(&path)
            .unwrap(),
        *derived,
        "session cloning and bearer refresh must retain the approved keys",
    );
    assert!(cloned
        .as_grant()
        .unwrap()
        .encryption_keys()
        .unwrap()
        .derive_for_path(&StoragePath::root())
        .is_err());
    let exported = session
        .as_grant()
        .unwrap()
        .export_local_secret()
        .await
        .unwrap();
    let restored = pubky.restore_session(&exported).await.unwrap();
    assert_eq!(
        *restored
            .as_grant()
            .unwrap()
            .encryption_keys()
            .unwrap()
            .derive_for_path(&path)
            .unwrap(),
        *derived,
    );
    assert!(restored
        .as_grant()
        .unwrap()
        .encryption_keys()
        .unwrap()
        .derive_for_path(&StoragePath::root())
        .is_err());
    assert_scoped_write_access(&restored).await;
    restored.signout().await.unwrap();
    let (_, recovered) = pubky_testnet::pubky::GrantCredential::restore_encryption_keys(&exported)
        .unwrap()
        .unwrap();
    assert_eq!(*recovered.derive_for_path(&path).unwrap(), *derived);
    let error = pubky.restore_session(&exported).await.unwrap_err();
    assert!(
        matches!(error, Error::Request(RequestError::Server { status, .. })
        if status == StatusCode::UNAUTHORIZED)
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn multi_scope_key_approvals_use_the_default_relay_limit() {
    let testnet = build_full_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let identity = Keypair::random();
    let signer = pubky.signer(identity.clone());
    signer
        .signup(&testnet.homeserver_app().public_key(), None)
        .await
        .unwrap();
    let mut capabilities = Capabilities::builder();
    for index in 0..5 {
        capabilities = capabilities
            .read_write(format!("/pub/app{index}.example/"))
            .unwrap()
            .encryption_keys(format!("/pub/app{index}.example/"))
            .unwrap();
    }
    let capabilities = capabilities.finish();
    for relay_path in ["/link", "/inbox"] {
        let mut relay = testnet.http_relay().local_link_url();
        relay.set_path(relay_path);
        let flow = PubkyGrantAuthFlow::builder(
            &capabilities,
            AuthFlowKind::signin(),
            ClientId::new("shop.example").unwrap(),
        )
        .approval_format(GrantApprovalFormat::SignedApprovalV1)
        .relay(relay)
        .client(pubky.client().clone())
        .start()
        .unwrap();
        signer
            .approve_auth(&flow.authorization_url())
            .await
            .unwrap();
        let credential = flow.await_credential().await.unwrap();
        let keys = credential.encryption_keys().unwrap();
        assert_eq!(keys.scopes().len(), 5);
        for index in 0..5 {
            let path = StoragePath::new(&format!("/pub/app{index}.example/file")).unwrap();
            let expected =
                ScopedEncryptionKeyBundle::from_identity_secret(&identity.secret(), [&path]);
            assert_eq!(
                *keys.derive_for_path(&path).unwrap(),
                *expected.derive_for_path(&path).unwrap(),
            );
        }
    }
}

#[tokio::test]
#[pubky_testnet::test]
async fn delegated_restore_keeps_keys_separate_from_public_metadata() {
    let testnet = build_full_testnet().await;
    let pubky = testnet.sdk().unwrap();
    let signer = pubky.signer(Keypair::random());
    signer
        .signup(&testnet.homeserver_app().public_key(), None)
        .await
        .unwrap();
    let client_key = Keypair::random();
    let client_pk = client_key.public_key();
    let sign = pubky_testnet::pubky::delegated_sign_callback(move |input| {
        let key = client_key.clone();
        async move { Ok(key.sign(input.as_bytes()).to_bytes().to_vec()) }
    });
    let caps = Capabilities::builder()
        .read("/pub/chat/")
        .unwrap()
        .encryption_keys("/pub/chat/")
        .unwrap()
        .finish();
    let auth = PubkyGrantAuthFlow::builder(
        &caps,
        AuthFlowKind::signin(),
        ClientId::new("delegated-keys.test").unwrap(),
    )
    .approval_format(GrantApprovalFormat::SignedApprovalV1)
    .delegated_client_signer("test-key".into(), client_pk, sign.clone())
    .client(pubky.client().clone())
    .relay(testnet.http_relay().local_link_url())
    .start()
    .unwrap();
    let saved = auth.save_delegated().unwrap();
    drop(auth);
    let auth =
        PubkyGrantAuthFlow::restore_delegated(saved, pubky.client().clone(), sign.clone()).unwrap();
    signer
        .approve_auth(&auth.authorization_url())
        .await
        .unwrap();
    let credential = auth.await_credential().await.unwrap();
    assert!(credential.export_local_secret().await.is_none());
    let state = credential.export_delegated_restore_state().await.unwrap();
    let path = StoragePath::new("/pub/chat/message").unwrap();
    let key = credential
        .encryption_keys()
        .unwrap()
        .derive_for_path(&path)
        .unwrap();
    let approval = credential.signed_approval().unwrap();
    let restored = pubky_testnet::pubky::GrantCredential::import_delegated_state(
        state.clone(),
        pubky.client(),
        sign.clone(),
        Some(approval),
    )
    .await
    .unwrap();
    assert_eq!(
        *restored
            .encryption_keys()
            .unwrap()
            .derive_for_path(&path)
            .unwrap(),
        *key
    );
    assert!(restored
        .encryption_keys()
        .unwrap()
        .derive_for_path(&StoragePath::root())
        .is_err());
    let legacy = pubky_testnet::pubky::GrantCredential::import_delegated_state(
        state,
        pubky.client(),
        sign,
        None,
    )
    .await
    .unwrap();
    assert!(legacy.encryption_keys().is_none());
}

#[tokio::test]
#[pubky_testnet::test]
async fn grant_secret_restore_mints_fresh_bearer() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let identity = Keypair::random();
    let signer = pubky.signer(identity.clone());
    signer.signup(&server.public_key(), None).await.unwrap();
    let session = signer
        .signin_blocking(ClientId::new("restore-bearer.test").unwrap())
        .await
        .unwrap();

    let original_bearer = session.as_grant().unwrap().current_bearer().await;
    let secret_token = session
        .as_grant()
        .unwrap()
        .export_local_secret()
        .await
        .unwrap();

    let restored = pubky.restore_session(&secret_token).await.unwrap();
    let restored_bearer = restored.as_grant().unwrap().current_bearer().await;
    assert!(secret_token.starts_with("pubky-grant-credential-v1:"));
    for candidate in [&session, &restored] {
        let grant = candidate.as_grant().unwrap();
        assert!(grant.encryption_keys().is_none());
        assert!(grant.signed_approval().is_none());
        assert_eq!(
            candidate.info().capabilities(),
            &[pubky_testnet::pubky::Capability::root()]
        );
    }
    assert!(
        pubky_testnet::pubky::GrantCredential::restore_encryption_keys(&secret_token)
            .unwrap()
            .is_none()
    );

    assert_ne!(
        original_bearer, restored_bearer,
        "restoring a grant secret must mint a fresh bearer"
    );
    assert!(
        session.revalidate().await.unwrap().is_none(),
        "minting the restored bearer replaces the old grant session"
    );
    restored
        .storage()
        .put("/pub/restore-bearer.test/hello", b"world".to_vec())
        .await
        .unwrap();
}

#[tokio::test]
#[pubky_testnet::test]
async fn grant_secret_restore_rejects_revoked_grant() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer = pubky.signer(Keypair::random());
    signer.signup(&server.public_key(), None).await.unwrap();
    let session = signer
        .signin(ClientId::new("revoked-restore.test").unwrap())
        .await
        .unwrap();

    let secret_token = session
        .as_grant()
        .unwrap()
        .export_local_secret()
        .await
        .unwrap();
    assert!(secret_token.starts_with("pubky-grant-credential-v1:"));
    assert!(session.as_grant().unwrap().encryption_keys().is_none());
    assert_eq!(
        session.info().capabilities(),
        &[pubky_testnet::pubky::Capability::root()]
    );
    session.signout().await.unwrap();
    assert!(
        pubky_testnet::pubky::GrantCredential::restore_encryption_keys(&secret_token)
            .unwrap()
            .is_none()
    );

    let err = pubky.restore_session(&secret_token).await.unwrap_err();

    assert!(
        matches!(err, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::UNAUTHORIZED),
        "restoring a revoked grant must fail with 401, got {err:?}"
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn grant_secret_restore_rejects_expired_grant() {
    const STORED_GRANT_CREDENTIAL_PREFIX: &str = "pubky-grant-credential-v1";

    fn grant_secret_token(
        grant_jws: String,
        client_keypair: &Keypair,
        homeserver_pk: &PublicKey,
    ) -> String {
        let client_secret = URL_SAFE_NO_PAD.encode(client_keypair.secret());
        format!(
            "{STORED_GRANT_CREDENTIAL_PREFIX}:{}:{client_secret}:{grant_jws}",
            homeserver_pk.z32()
        )
    }

    fn current_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }

    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let user_keypair = Keypair::random();
    let signer = pubky.signer(user_keypair.clone());
    signer.signup(&server.public_key(), None).await.unwrap();

    let client_keypair = Keypair::random();
    let now = current_unix();
    let claims = GrantClaims {
        iss: user_keypair.public_key(),
        client_id: ClientId::new("expired-restore.test").unwrap(),
        caps: vec![Capability::root()],
        cnf: client_keypair.public_key(),
        jti: GrantId::generate(),
        iat: now.saturating_sub(120),
        exp: now.saturating_sub(1),
    };
    let grant_jws = claims.sign(&user_keypair, GRANT_JWS_TYP);
    let secret_token = grant_secret_token(grant_jws, &client_keypair, &server.public_key());

    let err = pubky.restore_session(&secret_token).await.unwrap_err();

    assert!(
        matches!(err, Error::Authentication(_)) && err.to_string().contains("has expired"),
        "restoring an expired grant must fail before minting a bearer, got {err:?}"
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn auth_flow_survives_long_poll_timeout() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let http_relay_url = testnet.http_relay().local_link_url();

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

    let auth = PubkyGrantAuthFlow::builder(
        &capabilities,
        AuthFlowKind::signin(),
        ClientId::new("timeout.test").unwrap(),
    )
    .client(client)
    .relay(http_relay_url)
    .start()
    .unwrap();

    let signer = pubky.signer(Keypair::random());
    let signer_pubky = signer.public_key();
    signer.signup(&server.public_key(), None).await.unwrap();

    let url_clone = auth.authorization_url().clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        signer.approve_auth(&url_clone).await.unwrap();
    });

    let session = auth.await_approval().await.unwrap();
    assert_eq!(session.info().public_key(), &signer_pubky);
    assert!(session.as_grant().unwrap().encryption_keys().is_none());

    assert_scoped_write_access(&session).await;
}

#[tokio::test]
#[pubky_testnet::test]
async fn session_refresh_rotates_short_lived_bearer() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    // Sign up + obtain a grant-backed session.
    let signer = pubky.signer(Keypair::random());
    signer.signup(&server.public_key(), None).await.unwrap();
    let session = signer
        .signin(ClientId::new("refresh.test").unwrap())
        .await
        .unwrap();

    let token_before = session.as_grant().unwrap().current_bearer().await;

    // Grants are long-lived, but the opaque bearer is short-lived and replaced on refresh.
    session.as_grant().unwrap().force_refresh().await.unwrap();
    let token_after = session.as_grant().unwrap().current_bearer().await;

    assert_ne!(
        token_before, token_after,
        "force_refresh must mint a new bearer token"
    );

    // The refreshed session continues to work for storage ops.
    session
        .storage()
        .put("/pub/refresh.test/hello", b"world".to_vec())
        .await
        .unwrap();

    let old_token_url = (signer.public_key(), "/pub/refresh.test/old-token")
        .into_pubky_resource()
        .unwrap()
        .to_transport_url()
        .unwrap();
    let response = session
        .client()
        .request(Method::PUT, &old_token_url)
        .bearer_auth(token_before)
        .body(Vec::<u8>::new())
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[pubky_testnet::test]
async fn signout_revokes_current_grant_only() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    // Sign up so the user exists.
    let signer = pubky.signer(Keypair::random());
    signer.signup(&server.public_key(), None).await.unwrap();

    // Authorise app A with root caps so we can use it to inspect grants below.
    let session_a = signer
        .signin(ClientId::new("app.a").unwrap())
        .await
        .unwrap();

    // Authorise app B with a scoped capability — distinct grant on the server.
    let session_b = signer
        .signin(ClientId::new("app.b").unwrap())
        .await
        .unwrap();

    // Both sessions should appear in the root session's grant list.
    let grants_before = GrantManager::new(&session_a).list().await.unwrap();
    assert!(
        grants_before.len() >= 2,
        "expected at least 2 grants, got {}",
        grants_before.len()
    );

    // Sign out app B — this revokes its grant.
    session_b.signout().await.unwrap();

    // App A is unaffected.
    session_a
        .storage()
        .put("/pub/app.a/keepalive", Vec::<u8>::new())
        .await
        .unwrap();

    // The revoked grant no longer shows up in the active list.
    let grants_after = GrantManager::new(&session_a).list().await.unwrap();
    assert!(
        grants_after.len() < grants_before.len(),
        "signout should drop the revoked grant from GrantManager::list()"
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn signout_is_idempotent() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer = pubky.signer(Keypair::random());
    signer.signup(&server.public_key(), None).await.unwrap();

    let session = signer
        .signin(ClientId::new("test.signout").unwrap())
        .await
        .unwrap();

    // First signout revokes the grant.
    session.clone().signout().await.unwrap();

    // A second signout with the now-revoked bearer must be a 200 no-op.
    session
        .clone()
        .signout()
        .await
        .expect("second grant signout must be idempotent");

    // The session should be revoked on the server side too so any write operation should fail.
    let err = session
        .storage()
        .put("/pub/app.idempotent/hello", b"world".to_vec())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::UNAUTHORIZED)
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn disabled_user() {
    let testnet = EphemeralTestnet::builder()
        .config(ConfigToml::default_test_config())
        .build()
        .await
        .unwrap();

    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer = pubky.signer(Keypair::random());
    let user_pubky = signer.public_key();
    signer.signup(&server.public_key(), None).await.unwrap();
    let session = signer
        .signin(ClientId::new("disabled.test").unwrap())
        .await
        .unwrap();

    let file_path = "/pub/pubky.app/foo";
    session
        .storage()
        .put(file_path, Vec::<u8>::new())
        .await
        .unwrap();

    let response = session.storage().get(file_path).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "User should be able to read their own file"
    );

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

    let response = session.storage().get(file_path).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let err = session
        .storage()
        .put(file_path, Vec::<u8>::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::FORBIDDEN),
        "Disabled user must get 403 on write"
    );

    let response = session.storage().delete(file_path).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "User should be able to delete their own file even when disabled"
    );

    session.signout().await.unwrap();

    let session2 = signer
        .signin(ClientId::new("disabled.test").unwrap())
        .await
        .expect("Signin should succeed for disabled users");
    assert_eq!(session2.info().public_key(), &user_pubky);
}

#[tokio::test]
#[pubky_testnet::test]
async fn non_root_session_cannot_list_revoke_grants() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let http_relay_url = testnet.http_relay().local_link_url();

    let signer = pubky.signer(Keypair::random());
    signer.signup(&server.public_key(), None).await.unwrap();

    // Root session — used as the management surface.
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

    // The scoped session can write inside its scope before revocation.
    scoped_session
        .storage()
        .put("/pub/scoped.app/before", Vec::<u8>::new())
        .await
        .unwrap();

    // The scoped session can NOT write outside its scope.
    scoped_session
        .storage()
        .put("/pub/other-scope.app/test", Vec::<u8>::new())
        .await
        .unwrap_err();

    // Non-root sessions cannot enumerate grants — homeserver returns 403.
    let err = GrantManager::new(&scoped_session).list().await.unwrap_err();
    assert!(
        matches!(err, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::FORBIDDEN),
        "non-root GrantManager::list must be forbidden, got {err:?}"
    );

    let root_grant_id = root_session.as_grant().unwrap().grant_id().await;

    // Scoped session cannot revoke root grant — homeserver returns 403.
    GrantManager::new(&scoped_session)
        .revoke(&root_grant_id)
        .await
        .unwrap_err();
}

#[tokio::test]
#[pubky_testnet::test]
async fn root_session_can_list_and_revoke_scoped_grant() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let http_relay_url = testnet.http_relay().local_link_url();

    let signer = pubky.signer(Keypair::random());
    signer.signup(&server.public_key(), None).await.unwrap();

    // Root session — used as the management surface.
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

    // Root can list grants — both sessions appear.
    let grants = GrantManager::new(&root_session).list().await.unwrap();
    assert!(
        grants.len() >= 2,
        "expected ≥2 grants, got {}",
        grants.len()
    );

    let scoped_gid = scoped_session.as_grant().unwrap().grant_id().await;
    assert!(
        grants.iter().any(|g| g.grant_id == scoped_gid),
        "scoped grant id should be present in list"
    );

    // Root revokes the scoped grant.
    GrantManager::new(&root_session)
        .revoke(&scoped_gid)
        .await
        .unwrap();

    // Scoped session's bearer token is now invalid — the next request gets 401.
    let err = scoped_session
        .storage()
        .put("/pub/scoped.app/after", Vec::<u8>::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::UNAUTHORIZED),
        "revoked grant must yield 401, got {err:?}"
    );

    // Even a revalidation attempt fails with 401.
    let err = scoped_session
        .as_grant()
        .unwrap()
        .force_refresh()
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::UNAUTHORIZED),
        "revoked grant must fail to refresh with 401, got {err:?}"
    );

    // Root keeps working.
    root_session
        .storage()
        .put("/pub/root.app/still-here", Vec::<u8>::new())
        .await
        .unwrap();

    // List shows only one grant now.
    let grants_after = GrantManager::new(&root_session).list().await.unwrap();
    assert!(
        grants_after.len() < grants.len(),
        "expected fewer grants after revocation, got {}",
        grants_after.len()
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn auth_flow_signup_creates_scoped_session() {
    // Open signups make this test self-contained.
    let mut config = ConfigToml::default_test_config();
    config.general.signup_mode = SignupMode::Open;
    let testnet = EphemeralTestnet::builder()
        .with_http_relay()
        .config(config)
        .build()
        .await
        .unwrap();
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let http_relay_url = testnet.http_relay().local_link_url();

    // App initiates a signup-shaped flow with grant binding.
    let caps = Capabilities::builder()
        .read_write("/pub/signup.app/")
        .unwrap()
        .encryption_keys("/pub/signup.app/")
        .unwrap()
        .finish();
    let auth = PubkyGrantAuthFlow::builder(
        &caps,
        AuthFlowKind::signup(server.public_key(), None),
        ClientId::new("signup.app").unwrap(),
    )
    .approval_format(GrantApprovalFormat::SignedApprovalV1)
    .relay(http_relay_url)
    .client(pubky.client().clone())
    .start()
    .unwrap();

    // The signer owns account creation, then approves the app grant.
    let signer = pubky.signer(Keypair::random());
    signer.signup(&server.public_key(), None).await.unwrap();
    signer
        .approve_auth(&auth.authorization_url())
        .await
        .unwrap();

    let session = auth.await_approval().await.unwrap();
    assert_eq!(session.info().public_key(), &signer.public_key());
    assert!(session.as_grant().unwrap().encryption_keys().is_some());

    // The freshly created user can write inside the grant's scope.
    session
        .storage()
        .put("/pub/signup.app/welcome", b"hello".to_vec())
        .await
        .unwrap();

    // It can not write outside the scope.
    session
        .storage()
        .put("/pub/other.app/test", b"hello".to_vec())
        .await
        .unwrap_err();
}
