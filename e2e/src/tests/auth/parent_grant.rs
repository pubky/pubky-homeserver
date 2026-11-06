//! A signer approves a parent grant, and its holder manages it through the SDK.
//!
//! The last test plays an app's side from the documented formats, so the child
//! grants the SDK issues are checked against the homeserver. `child_grant` covers
//! the homeserver's rules.

use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open,
    Deserializable, Kem, OpModeR, Serializable,
};
use pubky_testnet::pubky::{
    deep_links::ChildGrantRequest, errors::RequestError, FeatureSupport, ParentGrantCredential,
    PubkySigner,
};
use pubky_testnet::pubky_common::{
    auth::{
        grant::ChildGrantClaims,
        grant_session_responses::GrantSessionResponse,
        jws::{decode_jws_payload, sign_jws, PopNonce, POP_JWS_TYP},
        pop::PopProofClaims,
    },
    crypto::random_bytes,
    encryption_keys::ScopedEncryptionKeyBundle,
    StoragePath,
};
use std::time::{SystemTime, UNIX_EPOCH};

const ACCOUNTS: &str = "https://accounts.example/auth/callback";
const CHAT: &str = "https://chat.example/auth/callback";

async fn signed_up_user(testnet: &EphemeralTestnet) -> (Keypair, PubkySigner) {
    let user = Keypair::random();
    let signer = testnet.sdk().unwrap().signer(user.clone());
    signer
        .signup(&testnet.homeserver_app().public_key(), None)
        .await
        .unwrap();
    (user, signer)
}

fn parent_flow(testnet: &EphemeralTestnet) -> PubkyGrantAuthFlow {
    PubkyGrantAuthFlow::builder(
        &"/pub/:rwe,/priv/:rwe".parse().unwrap(),
        AuthFlowKind::signin(),
        ClientId::new(ACCOUNTS).unwrap(),
    )
    .parent_grant()
    .relay(testnet.http_relay().local_link_url())
    .client(testnet.sdk().unwrap().client().clone())
    .start()
    .unwrap()
}

async fn parent_for(testnet: &EphemeralTestnet, signer: &PubkySigner) -> ParentGrantCredential {
    let flow = parent_flow(testnet);
    signer.approve_auth(flow.authorization_url()).await.unwrap();
    flow.await_parent_credential().await.unwrap()
}

fn has_status(error: &Error, expected: StatusCode) -> bool {
    matches!(error, Error::Request(RequestError::Server { status, .. }) if *status == expected)
}

#[tokio::test]
#[pubky_testnet::test]
async fn signer_approval_gives_the_holder_a_parent_and_its_keys() {
    let testnet = build_full_testnet().await;
    let (user, signer) = signed_up_user(&testnet).await;
    let pubky = testnet.sdk().unwrap();
    assert_eq!(
        pubky.grant_delegation_support(&user.public_key()).await,
        FeatureSupport::Supported
    );

    let parent = parent_for(&testnet, &signer).await;
    assert_eq!(parent.claims().iss, user.public_key());
    assert_eq!(parent.claims().client_id.as_str(), ACCOUNTS);
    let scopes = ["/pub/", "/priv/"].map(|scope| StoragePath::new(scope).unwrap());
    assert!(parent.encryption_keys().scopes().eq(&scopes));

    // The holder's keys match the ones the signer derives from the identity secret.
    let direct = ScopedEncryptionKeyBundle::from_identity_secret(&user.secret(), &scopes);
    for file in ["/pub/chat/message", "/priv/shop/order"] {
        let file = StoragePath::new(file).unwrap();
        assert_eq!(
            *parent.encryption_keys().derive_for_path(&file).unwrap(),
            *direct.derive_for_path(&file).unwrap()
        );
    }
}

#[tokio::test]
#[pubky_testnet::test]
async fn declining_keys_still_approves_storage() {
    let testnet = build_full_testnet().await;
    let (_, signer) = signed_up_user(&testnet).await;
    let flow = parent_flow(&testnet);
    signer
        .approve_auth_with_capabilities(
            flow.authorization_url(),
            &"/pub/:rw,/priv/:rw".parse().unwrap(),
        )
        .await
        .unwrap();

    let parent = flow.await_parent_credential().await.unwrap();
    assert_eq!(parent.claims().caps.len(), 2);
    assert_eq!(parent.encryption_keys().scopes().len(), 0);
}

#[tokio::test]
#[pubky_testnet::test]
async fn parent_and_session_flows_cannot_be_mixed_up() {
    let testnet = build_full_testnet().await;
    let (user, signer) = signed_up_user(&testnet).await;

    // A parent request can't complete as a session.
    let flow = parent_flow(&testnet);
    signer.approve_auth(flow.authorization_url()).await.unwrap();
    flow.await_credential().await.unwrap_err();

    // A session request can't complete as a parent.
    let flow = PubkyGrantAuthFlow::builder(
        &"/pub/chat/:rw".parse().unwrap(),
        AuthFlowKind::signin(),
        ClientId::new("chat.example").unwrap(),
    )
    .relay(testnet.http_relay().local_link_url())
    .client(testnet.sdk().unwrap().client().clone())
    .start()
    .unwrap();
    signer.approve_auth(flow.authorization_url()).await.unwrap();
    flow.await_parent_credential().await.unwrap_err();

    // A parent request can't exceed the ceiling, use an inexact client or name a signer.
    let builder = |caps: &str, client_id: &str| {
        PubkyGrantAuthFlow::builder(
            &caps.parse().unwrap(),
            AuthFlowKind::signin(),
            ClientId::new(client_id).unwrap(),
        )
        .parent_grant()
        .relay(testnet.http_relay().local_link_url())
        .client(testnet.sdk().unwrap().client().clone())
    };
    builder("/:rw", ACCOUNTS).start().unwrap_err();
    builder("/pub/:rw", "accounts.example").start().unwrap_err();
    builder("/pub/:rw", ACCOUNTS)
        .expected_signer(user.public_key())
        .start()
        .unwrap_err();
}

#[tokio::test]
#[pubky_testnet::test]
async fn the_homeserver_accepts_reconnects_and_sign_outs_from_the_holder() {
    let testnet = build_full_testnet().await;
    let (_, signer) = signed_up_user(&testnet).await;
    let parent = parent_for(&testnet, &signer).await;
    let client = testnet.sdk().unwrap().client().clone();
    let chat = ClientId::new(CHAT).unwrap();

    // Clearing a block that doesn't exist succeeds, so callers can retry.
    parent.reconnect_app(&client, &chat).await.unwrap();
    parent.reconnect_app(&client, &chat).await.unwrap();

    // Signing out can be repeated, and ends the parent's authority.
    parent.signout(&client).await.unwrap();
    parent.signout(&client).await.unwrap();
    let error = parent.reconnect_app(&client, &chat).await.unwrap_err();
    assert!(has_status(&error, StatusCode::UNAUTHORIZED), "{error:?}");
}

#[tokio::test]
#[pubky_testnet::test]
async fn delegation_support_is_unknown_without_a_homeserver() {
    let testnet = build_full_testnet().await;
    let pubky = testnet.sdk().unwrap();
    assert_eq!(
        pubky
            .grant_delegation_support(&Keypair::random().public_key())
            .await,
        FeatureSupport::Unknown
    );
}

/// Open an approval from a callback URL the way an app does, following the
/// HPKE format in `docs/scoped-encryption-keys.md`.
fn open_approval(
    private_key: &<X25519HkdfSha256 as Kem>::PrivateKey,
    callback: &reqwest::Url,
) -> String {
    let sealed = callback
        .fragment()
        .unwrap()
        .split('&')
        .find_map(|pair| pair.strip_prefix("approval="))
        .unwrap();
    let message = URL_SAFE_NO_PAD.decode(sealed).unwrap();
    let body = message.strip_prefix(b"pubky-hpke-v1\0").unwrap();
    let (encapped_key, ciphertext) = body.split_at(32);
    let encapped_key = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(encapped_key).unwrap();
    let approval = single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        private_key,
        &encapped_key,
        b"pubky-grant-approval-hpke-v1",
        ciphertext,
        b"",
    )
    .unwrap();
    String::from_utf8(approval).unwrap()
}

#[tokio::test]
#[pubky_testnet::test]
async fn an_app_signs_in_with_a_child_the_holder_issued() {
    let testnet = build_full_testnet().await;
    let (user, signer) = signed_up_user(&testnet).await;
    let parent = parent_for(&testnet, &signer).await;
    let server = testnet.homeserver_app();
    let client = testnet.sdk().unwrap().client().clone();
    let base_url = server.icann_http_url();

    // The app builds its request from the documented URL format.
    let app_key = Keypair::random();
    let (hpke_secret, hpke_public) = X25519HkdfSha256::derive_keypair(&random_bytes::<32>());
    let epk = URL_SAFE_NO_PAD.encode(hpke_public.to_bytes());
    let request_url = reqwest::Url::parse_with_params(
        "https://accounts.example/authorize",
        [
            ("cid", CHAT),
            ("caps", "/pub/chat/:rw,/priv/chat/:rwe"),
            ("cpk", app_key.public_key().z32().as_str()),
            ("epk", epk.as_str()),
            ("state", "state-1"),
        ],
    )
    .unwrap();
    let request = ChildGrantRequest::parse(&request_url).unwrap();

    // The holder issues the child, and the app opens the approval it gets back.
    let callback = parent.issue_child(&request, None).await.unwrap();
    assert_eq!(callback.as_str().split('#').next(), Some(CHAT));
    let approval = open_approval(&hpke_secret, &callback);
    let payload: serde_json::Value = decode_jws_payload(&approval).unwrap();
    assert_eq!(payload["state"], "state-1");
    assert_eq!(payload["recipient"], epk);
    let child_jws = payload["child"].as_str().unwrap();
    let child: ChildGrantClaims = decode_jws_payload(child_jws).unwrap();
    assert_eq!(child.grant.cnf, app_key.public_key());

    // The homeserver accepts the chain the SDK issued.
    let pop = PopProofClaims {
        aud: server.public_key(),
        gid: child.grant.jti.clone(),
        nonce: PopNonce::generate(),
        iat: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let response = client
        .request(Method::POST, &format!("{base_url}auth/grant/session"))
        .json(&serde_json::json!({
            "parent": payload["parent"],
            "grant": child_jws,
            "pop": sign_jws(&app_key, POP_JWS_TYP, &pop),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session: GrantSessionResponse = response.json().await.unwrap();
    assert_eq!(session.session.client_id.as_str(), CHAT);
    assert_eq!(session.session.grant_id, child.grant.jti);

    // The session is limited to the child's capabilities.
    let put = |path: &'static str| {
        let url = format!("{base_url}storage/{}{path}", user.public_key().z32());
        let request = client
            .request(Method::PUT, &url)
            .bearer_auth(&session.token)
            .body(vec![1]);
        async move { request.send().await.unwrap().status() }
    };
    assert_eq!(put("/pub/chat/message").await, StatusCode::CREATED);
    assert_eq!(put("/pub/other/message").await, StatusCode::FORBIDDEN);

    // The app's keys are the ones the signer derives for the child's `e` scope.
    let keys: ScopedEncryptionKeyBundle =
        serde_json::from_value(payload["encryption_keys"].clone()).unwrap();
    let scope = StoragePath::new("/priv/chat/").unwrap();
    assert!(keys.scopes().eq([&scope]));
    let file = StoragePath::new("/priv/chat/message").unwrap();
    let direct = ScopedEncryptionKeyBundle::from_identity_secret(
        &user.secret(),
        std::slice::from_ref(&scope),
    );
    assert_eq!(
        *keys.derive_for_path(&file).unwrap(),
        *direct.derive_for_path(&file).unwrap()
    );
}
