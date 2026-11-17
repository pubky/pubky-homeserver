//! Apps sign in through a parent grant holder with the SDK's redirect flow.
//!
//! One Ring approval gives Accounts a parent. Each app then redirects to Accounts,
//! receives a child grant and exchanges it through the SDK, which sends the parent
//! with every exchange, refresh and sign-out.

use super::*;
use pubky_testnet::pubky::{
    deep_links::ChildGrantRequest, errors::AuthError, ParentGrantCredential, PubkyRedirectAuthFlow,
    PubkySigner, RedirectCallback,
};
use pubky_testnet::pubky_common::{
    auth::grant_session_responses::GrantKind, encryption_keys::ScopedEncryptionKeyBundle,
    StoragePath,
};
use reqwest::Url;

const ACCOUNTS: &str = "https://accounts.example/auth/callback";
const CHAT: &str = "https://chat.example/auth/callback";
const SHOP: &str = "https://shop.example/auth/callback";
const AUTHORIZE: &str = "https://accounts.example/authorize";

struct Suite {
    testnet: EphemeralTestnet,
    user: Keypair,
    signer: PubkySigner,
    parent: ParentGrantCredential,
}

impl Suite {
    /// A signed-up user whose Accounts holds a parent after one Ring approval.
    async fn new(parent_caps: &str) -> Self {
        let testnet = build_full_testnet().await;
        let user = Keypair::random();
        let signer = testnet.sdk().unwrap().signer(user.clone());
        signer
            .signup(&testnet.homeserver_app().public_key(), None)
            .await
            .unwrap();
        let flow = PubkyGrantAuthFlow::builder(
            &"/pub/:rwe,/priv/:rwe".parse().unwrap(),
            AuthFlowKind::signin(),
            ClientId::new(ACCOUNTS).unwrap(),
        )
        .parent_grant()
        .relay(testnet.http_relay().local_link_url())
        .client(testnet.sdk().unwrap().client().clone())
        .start()
        .unwrap();
        signer
            .approve_auth_with_capabilities(flow.authorization_url(), &parent_caps.parse().unwrap())
            .await
            .unwrap();
        let parent = flow.await_parent_credential().await.unwrap();
        Self {
            testnet,
            user,
            signer,
            parent,
        }
    }

    fn client(&self) -> PubkyHttpClient {
        self.testnet.sdk().unwrap().client().clone()
    }

    fn flow(&self, callback: &str, caps: &str) -> PubkyRedirectAuthFlow {
        PubkyRedirectAuthFlow::builder(
            &caps.parse().unwrap(),
            ClientId::new(callback).unwrap(),
            Url::parse(AUTHORIZE).unwrap(),
        )
        .client(self.client())
        .start()
        .unwrap()
    }

    /// What Accounts does with the request: issue a child and redirect back.
    async fn accounts_redirect(&self, flow: &PubkyRedirectAuthFlow) -> Url {
        let request = ChildGrantRequest::parse(flow.authorization_url()).unwrap();
        self.parent.issue_child(&request, None).await.unwrap()
    }

    /// Run a whole sign-in for an app and return its session.
    async fn sign_in(&self, callback: &str, caps: &str) -> PubkySession {
        let flow = self.flow(callback, caps);
        let callback = self.accounts_redirect(&flow).await;
        flow.complete(&callback).await.unwrap()
    }

    async fn grants(&self) -> Vec<pubky_testnet::pubky::GrantInfo> {
        let root = self
            .signer
            .signin(ClientId::new("root.test").unwrap())
            .await
            .unwrap();
        GrantManager::new(&root).list().await.unwrap()
    }
}

fn key(session: &PubkySession, path: &str) -> [u8; 32] {
    *session
        .as_grant()
        .unwrap()
        .encryption_keys()
        .unwrap()
        .derive_for_path(&StoragePath::new(path).unwrap())
        .unwrap()
}

fn is_status(error: &Error, expected: StatusCode) -> bool {
    matches!(error, Error::Request(RequestError::Server { status, .. }) if *status == expected)
}

#[tokio::test]
#[pubky_testnet::test]
async fn apps_sign_in_through_one_parent_approval_with_isolated_keys() {
    let suite = Suite::new("/pub/:rwe,/priv/:rwe").await;
    let chat = suite.sign_in(CHAT, "/pub/chat/:rw,/priv/chat/:rwe").await;
    let shop = suite.sign_in(SHOP, "/pub/shop/:rw,/priv/shop/:rwe").await;

    // Each session describes its own child and is limited to its capabilities.
    let info = chat.as_grant().unwrap().session_info().await;
    assert_eq!(info.client_id.as_str(), CHAT);
    assert_eq!(info.pubky, suite.user.public_key());
    chat.storage().put("/pub/chat/hello", "hi").await.unwrap();
    let error = chat
        .storage()
        .put("/pub/shop/hello", "hi")
        .await
        .unwrap_err();
    assert!(is_status(&error, StatusCode::FORBIDDEN), "{error:?}");
    shop.storage().put("/pub/shop/hello", "hi").await.unwrap();

    // Each app holds exactly its keys, equal to what the identity derives.
    for (session, scope) in [(&chat, "/priv/chat/"), (&shop, "/priv/shop/")] {
        let grant = session.as_grant().unwrap();
        let keys = grant.encryption_keys().unwrap();
        let scope = StoragePath::new(scope).unwrap();
        assert!(keys.scopes().eq([&scope]));
        let file = StoragePath::new(&format!("{scope}message")).unwrap();
        let direct = ScopedEncryptionKeyBundle::from_identity_secret(
            &suite.user.secret(),
            std::slice::from_ref(&scope),
        );
        assert_eq!(
            *keys.derive_for_path(&file).unwrap(),
            *direct.derive_for_path(&file).unwrap()
        );
    }
    // Neither app can derive the other's keys, nor a key for their common ancestor.
    let chat_grant = chat.as_grant().unwrap();
    let chat_keys = chat_grant.encryption_keys().unwrap();
    for path in ["/priv/shop/message", "/priv/other"] {
        chat_keys
            .derive_for_path(&StoragePath::new(path).unwrap())
            .unwrap_err();
    }

    // The homeserver lists both children under the one parent.
    let grants = suite.grants().await;
    let children: Vec<_> = grants
        .iter()
        .filter(|grant| grant.kind == GrantKind::Child)
        .collect();
    assert_eq!(children.len(), 2);
    assert!(children
        .iter()
        .all(|child| child.parent_id.as_ref() == Some(&suite.parent.claims().jti)));
}

#[tokio::test]
#[pubky_testnet::test]
async fn refresh_and_restore_send_the_parent() {
    let suite = Suite::new("/pub/:rwe,/priv/:rwe").await;
    let chat = suite.sign_in(CHAT, "/pub/chat/:rw,/priv/chat/:rwe").await;
    let grant = chat.as_grant().unwrap();
    let before = grant.current_bearer().await;
    let after = grant.force_refresh().await.unwrap();
    assert_ne!(before, after);
    chat.storage()
        .put("/pub/chat/after-refresh", "hi")
        .await
        .unwrap();

    // The exported child token restores the chain and its keys.
    let token = grant.export_local_secret().await.unwrap();
    assert!(token.starts_with("pubky-grant-credential-v3:"));
    let restored = suite
        .testnet
        .sdk()
        .unwrap()
        .restore_session(&token)
        .await
        .unwrap();
    restored
        .storage()
        .put("/pub/chat/after-restore", "hi")
        .await
        .unwrap();
    assert_eq!(key(&restored, "/priv/chat/m"), key(&chat, "/priv/chat/m"));
    assert!(restored.as_grant().unwrap().signed_approval().is_some());
    let (claims, _) = pubky_testnet::pubky::GrantCredential::restore_encryption_keys(&token)
        .unwrap()
        .unwrap();
    assert_eq!(claims.client_id.as_str(), CHAT);
}

#[tokio::test]
#[pubky_testnet::test]
async fn an_interrupted_exchange_resumes_with_the_same_child() {
    let suite = Suite::new("/pub/:rwe,/priv/:rwe").await;
    let flow = suite.flow(CHAT, "/pub/chat/:rw");
    let callback = suite.accounts_redirect(&flow).await;
    let approval = flow
        .accept(&RedirectCallback::parse(&callback).unwrap())
        .unwrap();

    // The app saved the flow and approval before exchanging, then lost the response.
    let saved_flow = flow.save_local().unwrap();
    let saved_approval = approval.signed_approval().to_owned();
    let lost = flow.exchange(&approval).await.unwrap();

    let resumed = PubkyRedirectAuthFlow::restore(saved_flow, suite.client()).unwrap();
    let approval = resumed.accept_signed_approval(&saved_approval).unwrap();
    let credential = resumed.exchange(&approval).await.unwrap();
    let session = PubkySession::from_grant_credential(suite.client(), credential);
    session
        .storage()
        .put("/pub/chat/resumed", "hi")
        .await
        .unwrap();

    // Both exchanges used one child: the homeserver lists one, and replaced the
    // first bearer instead of creating a second session.
    let children = suite
        .grants()
        .await
        .into_iter()
        .filter(|grant| grant.kind == GrantKind::Child)
        .count();
    assert_eq!(children, 1);
    let lost = PubkySession::from_grant_credential(suite.client(), lost);
    let lost_bearer = lost.as_grant().unwrap().current_bearer().await;
    assert_ne!(
        lost_bearer,
        session.as_grant().unwrap().current_bearer().await
    );
    let url = format!(
        "{}auth/grant/session",
        suite.testnet.homeserver_app().icann_http_url()
    );
    let response = suite
        .client()
        .request(Method::GET, &url)
        .bearer_auth(&lost_bearer)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[pubky_testnet::test]
async fn signing_out_revokes_only_the_child_and_a_new_sign_in_restores_the_keys() {
    let suite = Suite::new("/pub/:rwe,/priv/:rwe").await;
    let chat = suite.sign_in(CHAT, "/pub/chat/:rw,/priv/chat/:rwe").await;
    let shop = suite.sign_in(SHOP, "/pub/shop/:rw").await;
    let chat_key = key(&chat, "/priv/chat/message");
    let chat_grant = chat.as_grant().unwrap().grant_id().await;

    chat.clone()
        .signout()
        .await
        .map_err(|(error, _)| error)
        .unwrap();
    let error = chat
        .storage()
        .put("/pub/chat/after", "hi")
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::CredentialRefresh(_)) || is_status(&error, StatusCode::UNAUTHORIZED),
        "{error:?}"
    );

    // The parent and the sibling keep working.
    shop.storage().put("/pub/shop/after", "hi").await.unwrap();
    assert!(suite
        .grants()
        .await
        .iter()
        .all(|grant| grant.grant_id != chat_grant));

    // Signing in again issues a new child with the same keys.
    let again = suite.sign_in(CHAT, "/pub/chat/:rw,/priv/chat/:rwe").await;
    assert_ne!(again.as_grant().unwrap().grant_id().await, chat_grant);
    assert_eq!(key(&again, "/priv/chat/message"), chat_key);
    again.storage().put("/pub/chat/again", "hi").await.unwrap();
}

#[tokio::test]
#[pubky_testnet::test]
async fn a_parent_without_keys_still_signs_in_storage_only_apps() {
    let suite = Suite::new("/pub/:rw,/priv/:rw").await;
    let chat = suite.sign_in(CHAT, "/pub/chat/:rw").await;
    assert_eq!(
        chat.as_grant()
            .unwrap()
            .encryption_keys()
            .unwrap()
            .scopes()
            .len(),
        0
    );
    chat.storage().put("/pub/chat/hello", "hi").await.unwrap();

    // A key request gets an explicit denial instead of another Ring approval.
    let flow = suite.flow(SHOP, "/priv/shop/:rwe");
    let request = ChildGrantRequest::parse(flow.authorization_url()).unwrap();
    let denial = match suite.parent.issue_child(&request, None).await.unwrap_err() {
        Error::Authentication(AuthError::RedirectDeclined(denial)) => denial,
        other => panic!("{other:?}"),
    };
    let error = flow
        .complete(&request.declined_url(denial))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Authentication(AuthError::RedirectDeclined(_))
    ));
}
