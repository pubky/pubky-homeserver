//! A signer approves a parent grant, and its holder manages it through the SDK.
//!
//! Issuing child grants and signing apps in with them is covered by the SDK's
//! unit tests and by Pubky Accounts. `child_grant` covers the homeserver's rules.

use super::*;
use pubky_testnet::pubky::{
    errors::RequestError, FeatureSupport, ParentGrantCredential, PubkySigner,
};
use pubky_testnet::pubky_common::{encryption_keys::ScopedEncryptionKeyBundle, StoragePath};

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
