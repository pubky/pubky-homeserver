//! End-to-end coverage for parent/child grants over HTTP.
//!
//! The SDK can't issue child grants yet, so these tests sign the chain themselves
//! and call the homeserver API directly.

use super::*;
use pubky_testnet::pubky_common::auth::{
    grant::{ChildGrantClaims, GrantClaims},
    grant_session_responses::{GrantKind, GrantSessionResponse},
    jws::{
        sign_jws, GrantId, PopNonce, CHILD_GRANT_JWS_TYP, PARENT_GRANT_JWS_TYP, POP_JWS_TYP,
        RECONNECT_JWS_TYP,
    },
    pop::{PopProofClaims, ReconnectProofClaims},
};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

const CHAT: &str = "https://chat.example/auth/callback";
const SHOP: &str = "https://shop.example/auth/callback";

/// A signed-up user with a parent grant held by an Accounts key.
pub(in crate::tests) struct ParentGrant {
    pub signer: pubky_testnet::pubky::PubkySigner,
    client: PubkyHttpClient,
    base_url: String,
    homeserver: PublicKey,
    user: Keypair,
    accounts: Keypair,
    pub parent: GrantClaims,
}

/// A child grant with the app key that holds it.
pub(in crate::tests) struct App {
    key: Keypair,
    pub child: ChildGrantClaims,
}

impl ParentGrant {
    pub async fn new(testnet: &EphemeralTestnet) -> Self {
        let server = testnet.homeserver_app();
        let pubky = testnet.sdk().unwrap();
        let user = Keypair::random();
        let signer = pubky.signer(user.clone());
        signer.signup(&server.public_key(), None).await.unwrap();
        let accounts = Keypair::random();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let parent = GrantClaims {
            iss: user.public_key(),
            client_id: ClientId::new("https://accounts.example/auth/callback").unwrap(),
            caps: vec!["/pub/:rwe".parse().unwrap(), "/priv/:rwe".parse().unwrap()],
            cnf: accounts.public_key(),
            jti: GrantId::generate(),
            iat: now,
            exp: now + 7200,
        };
        Self {
            signer,
            client: pubky.client().clone(),
            base_url: server.icann_http_url().to_string(),
            homeserver: server.public_key(),
            user,
            accounts,
            parent,
        }
    }

    pub fn app(&self, callback: &str, caps: &str) -> App {
        let key = Keypair::random();
        let child = ChildGrantClaims {
            grant: GrantClaims {
                iss: self.user.public_key(),
                client_id: ClientId::new(callback).unwrap(),
                caps: caps.parse::<Capabilities>().unwrap().to_vec(),
                cnf: key.public_key(),
                jti: GrantId::generate(),
                iat: self.parent.iat,
                exp: self.parent.exp,
            },
            parent_jti: self.parent.jti.clone(),
        };
        App { key, child }
    }

    fn parent_jws(&self) -> String {
        sign_jws(&self.user, PARENT_GRANT_JWS_TYP, &self.parent)
    }

    fn child_jws(&self, app: &App) -> String {
        sign_jws(&self.accounts, CHILD_GRANT_JWS_TYP, &app.child)
    }

    fn pop_claims(&self, grant_id: &GrantId) -> PopProofClaims {
        PopProofClaims {
            aud: self.homeserver.clone(),
            gid: grant_id.clone(),
            nonce: PopNonce::generate(),
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    fn pop(&self, key: &Keypair, grant_id: &GrantId) -> String {
        sign_jws(key, POP_JWS_TYP, &self.pop_claims(grant_id))
    }

    fn chain_body(&self, app: &App) -> serde_json::Value {
        json!({
            "parent": self.parent_jws(),
            "grant": self.child_jws(app),
            "pop": self.pop(&app.key, &app.child.grant.jti),
        })
    }

    async fn post(&self, path: &str, body: &serde_json::Value) -> reqwest::Response {
        self.client
            .request(Method::POST, &format!("{}{path}", self.base_url))
            .json(body)
            .send()
            .await
            .unwrap()
    }

    async fn exchange_status(&self, app: &App) -> StatusCode {
        self.post("auth/grant/session", &self.chain_body(app))
            .await
            .status()
    }

    /// Exchange a valid chain for a session.
    pub async fn exchange(&self, app: &App) -> GrantSessionResponse {
        let response = self.post("auth/grant/session", &self.chain_body(app)).await;
        assert_eq!(response.status(), StatusCode::OK);
        response.json().await.unwrap()
    }

    /// Revoke the parent and all its children with the parent's key.
    pub async fn parent_signout(&self) -> Result<(), String> {
        let body = json!({
            "grant": self.parent_jws(),
            "pop": self.pop(&self.accounts, &self.parent.jti),
        });
        let response = self.delete_session(&body).await;
        match response.status() {
            StatusCode::OK => Ok(()),
            status => Err(status.to_string()),
        }
    }

    async fn delete_session(&self, body: &serde_json::Value) -> reqwest::Response {
        self.client
            .request(
                Method::DELETE,
                &format!("{}auth/grant/session", self.base_url),
            )
            .json(body)
            .send()
            .await
            .unwrap()
    }

    async fn reconnect_status(&self, callback: &str) -> StatusCode {
        let proof = ReconnectProofClaims {
            pop: self.pop_claims(&self.parent.jti),
            client_id: ClientId::new(callback).unwrap(),
        };
        let body = json!({
            "parent": self.parent_jws(),
            "proof": sign_jws(&self.accounts, RECONNECT_JWS_TYP, &proof),
        });
        self.post("auth/grant/reconnect", &body).await.status()
    }

    async fn storage_status(&self, method: Method, path: &str, bearer: &str) -> StatusCode {
        let url = format!(
            "{}storage/{}{path}",
            self.base_url,
            self.user.public_key().z32()
        );
        self.client
            .request(method, &url)
            .bearer_auth(bearer)
            .body(vec![1])
            .send()
            .await
            .unwrap()
            .status()
    }
}

#[tokio::test]
#[pubky_testnet::test]
async fn child_session_is_limited_to_the_childs_capabilities() {
    let testnet = build_full_testnet().await;
    let d = ParentGrant::new(&testnet).await;
    let app = d.app(CHAT, "/pub/chat/:rw,/priv/chat/keys/:e");

    let session = d.exchange(&app).await;
    assert_eq!(session.session.client_id.as_str(), CHAT);
    assert_eq!(session.session.grant_id, app.child.grant.jti);
    let bearer = &session.token;

    let put = |path| d.storage_status(Method::PUT, path, bearer);
    assert_eq!(put("/pub/chat/message").await, StatusCode::CREATED);
    assert_eq!(put("/pub/other/message").await, StatusCode::FORBIDDEN);
    // `e` is for encryption keys and gives no storage access.
    assert_eq!(put("/priv/chat/keys/message").await, StatusCode::FORBIDDEN);

    // A delegated session can't manage grants.
    let sessions = d
        .client
        .request(Method::GET, &format!("{}auth/grant/sessions", d.base_url))
        .bearer_auth(bearer)
        .send()
        .await
        .unwrap();
    assert_eq!(sessions.status(), StatusCode::FORBIDDEN);

    let info = d
        .client
        .request(Method::GET, &format!("{}auth/grant/session", d.base_url))
        .bearer_auth(bearer)
        .send()
        .await
        .unwrap();
    assert_eq!(info.status(), StatusCode::OK);
}

#[tokio::test]
#[pubky_testnet::test]
async fn rejected_chains_return_their_documented_statuses() {
    let testnet = build_full_testnet().await;
    let d = ParentGrant::new(&testnet).await;
    let app = d.app(CHAT, "/priv/chat/:rw");

    // A child signed by someone other than the parent's key.
    let mut body = d.chain_body(&app);
    body["grant"] = json!(sign_jws(
        &Keypair::random(),
        CHILD_GRANT_JWS_TYP,
        &app.child
    ));
    let response = d.post("auth/grant/session", &body).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // A wrong parent reference.
    let mut other_parent = d.app(CHAT, "/priv/chat/:rw");
    other_parent.child.parent_jti = GrantId::generate();
    assert_eq!(
        d.exchange_status(&other_parent).await,
        StatusCode::BAD_REQUEST
    );

    // Rights beyond the parent's ceiling.
    assert_eq!(
        d.exchange_status(&d.app(CHAT, "/:rw")).await,
        StatusCode::FORBIDDEN
    );

    // A callback that isn't an HTTPS URL.
    assert_eq!(
        d.exchange_status(&d.app("chat.example", "/priv/chat/:r"))
            .await,
        StatusCode::BAD_REQUEST
    );

    // A parent can't be exchanged for storage access.
    let parent_only = json!({
        "grant": d.parent_jws(),
        "pop": d.pop(&d.accounts, &d.parent.jti),
    });
    assert_eq!(
        d.post("auth/grant/session", &parent_only).await.status(),
        StatusCode::BAD_REQUEST
    );

    // A changed child under an ID that is already recorded.
    d.exchange(&app).await;
    let mut changed = d.app(CHAT, "/priv/chat/:r");
    changed.child.grant.jti = app.child.grant.jti.clone();
    assert_eq!(d.exchange_status(&changed).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[pubky_testnet::test]
async fn signup_accepts_direct_grants_only() {
    let testnet = build_full_testnet().await;
    let d = ParentGrant::new(&testnet).await;
    let app = d.app(CHAT, "/priv/chat/:rw");

    assert_eq!(
        d.post("auth/grant/signup", &d.chain_body(&app))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn info_advertises_grant_delegation() {
    let testnet = build_full_testnet().await;
    let d = ParentGrant::new(&testnet).await;

    let info: serde_json::Value = d
        .client
        .request(Method::GET, &format!("{}info", d.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(info["features"]
        .as_array()
        .unwrap()
        .contains(&json!("grant-delegation")));
}

#[tokio::test]
#[pubky_testnet::test]
async fn listing_groups_children_under_their_parent_and_direct_grants_stay_direct() {
    let testnet = build_full_testnet().await;
    let d = ParentGrant::new(&testnet).await;
    let root = d
        .signer
        .signin(ClientId::new("root.test").unwrap())
        .await
        .unwrap();
    let app = d.app(CHAT, "/priv/chat/:rw");
    d.exchange(&app).await;

    let grants = GrantManager::new(&root).list().await.unwrap();
    assert_eq!(grants.len(), 3);
    let find = |id: &GrantId| grants.iter().find(|grant| &grant.grant_id == id).unwrap();
    let root_id = root.as_grant().unwrap().grant_id().await;
    assert_eq!(find(&root_id).kind, GrantKind::Direct);
    assert_eq!(find(&root_id).parent_id, None);
    assert_eq!(find(&d.parent.jti).kind, GrantKind::Parent);
    assert_eq!(find(&d.parent.jti).parent_id, None);
    let child = find(&app.child.grant.jti);
    assert_eq!(child.kind, GrantKind::Child);
    assert_eq!(child.parent_id.as_ref(), Some(&d.parent.jti));
    assert_eq!(child.client_id, CHAT);

    d.parent_signout().await.unwrap();

    let grants = GrantManager::new(&root).list().await.unwrap();
    assert_eq!(
        grants.iter().map(|g| &g.grant_id).collect::<Vec<_>>(),
        vec![&root_id]
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn deliberate_revocation_blocks_the_app_until_it_is_reconnected() {
    let testnet = build_full_testnet().await;
    let d = ParentGrant::new(&testnet).await;
    let root = d
        .signer
        .signin(ClientId::new("root.test").unwrap())
        .await
        .unwrap();
    let (chat, shop) = (d.app(CHAT, "/pub/chat/:rw"), d.app(SHOP, "/pub/shop/:rw"));
    let chat_session = d.exchange(&chat).await;
    let shop_session = d.exchange(&shop).await;

    GrantManager::new(&root)
        .revoke(&chat.child.grant.jti)
        .await
        .unwrap();

    assert_eq!(
        d.storage_status(Method::PUT, "/pub/chat/a", &chat_session.token)
            .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        d.storage_status(Method::PUT, "/pub/shop/a", &shop_session.token)
            .await,
        StatusCode::CREATED
    );
    let fresh = d.app(CHAT, "/pub/chat/:rw");
    assert_eq!(d.exchange_status(&fresh).await, StatusCode::FORBIDDEN);

    assert_eq!(d.reconnect_status(CHAT).await, StatusCode::NO_CONTENT);

    assert_eq!(d.exchange_status(&chat).await, StatusCode::UNAUTHORIZED);
    let fresh_session = d.exchange(&fresh).await;
    assert_eq!(
        d.storage_status(Method::PUT, "/pub/chat/b", &fresh_session.token)
            .await,
        StatusCode::CREATED
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn app_signout_keeps_the_parent_and_other_apps() {
    let testnet = build_full_testnet().await;
    let d = ParentGrant::new(&testnet).await;
    let (chat, shop) = (d.app(CHAT, "/pub/chat/:rw"), d.app(SHOP, "/pub/shop/:rw"));
    let chat_session = d.exchange(&chat).await;
    let shop_session = d.exchange(&shop).await;

    let response = d.delete_session(&d.chain_body(&chat)).await;
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        d.storage_status(Method::PUT, "/pub/chat/a", &chat_session.token)
            .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        d.storage_status(Method::PUT, "/pub/shop/a", &shop_session.token)
            .await,
        StatusCode::CREATED
    );
    // Signing out creates no block, so a new child can sign in without a reconnect.
    d.exchange(&d.app(CHAT, "/pub/chat/:rw")).await;
}

#[tokio::test]
#[pubky_testnet::test]
async fn parent_signout_ends_every_child_and_future_exchanges() {
    let testnet = build_full_testnet().await;
    let d = ParentGrant::new(&testnet).await;
    let chat = d.app(CHAT, "/pub/chat/:rw");
    let session = d.exchange(&chat).await;
    let unexchanged = d.app(SHOP, "/pub/shop/:rw");

    d.parent_signout().await.unwrap();

    assert_eq!(
        d.storage_status(Method::PUT, "/pub/chat/a", &session.token)
            .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(d.exchange_status(&chat).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        d.exchange_status(&unexchanged).await,
        StatusCode::UNAUTHORIZED
    );
}
