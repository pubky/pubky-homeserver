mod admin;
mod auth;
mod cli;
mod events;
mod http;
mod metrics;
mod private_data;
mod rate_limiting;
mod storage;
mod website;

use pubky_testnet::pubky::{
    AuthFlowKind, ClientId, Method, Pubky, PubkyGrantAuthFlow, PubkySession, PubkySigner, PublicKey,
};
use pubky_testnet::pubky_common::{
    auth::AuthToken,
    capabilities::{Capabilities, Capability},
};
use pubky_testnet::EphemeralTestnet;

async fn build_full_testnet() -> EphemeralTestnet {
    EphemeralTestnet::builder()
        .with_http_relay()
        .config(pubky_testnet::pubky_homeserver::ConfigToml::default_test_config())
        .build()
        .await
        .unwrap()
}

async fn signup_and_signin(signer: &PubkySigner, homeserver: &PublicKey) -> PubkySession {
    signer.signup(homeserver, None).await.unwrap();
    signer
        .signin(ClientId::new("e2e.test").unwrap())
        .await
        .unwrap()
}

/// Exchange an older client's approval at the homeserver's cookie endpoint.
async fn exchange_cookie_token(pubky: &Pubky, token: &AuthToken) -> reqwest::Response {
    let url = format!("https://_pubky.{}/session", token.public_key().z32());
    pubky
        .client()
        .request(Method::POST, &url)
        .body(token.serialize())
        .send()
        .await
        .unwrap()
}

async fn legacy_cookie_session(pubky: &Pubky, signer: &PubkySigner) -> PubkySession {
    let token = AuthToken::sign(signer.keypair(), vec![Capability::root()]);
    let response = exchange_cookie_token(pubky, &token)
        .await
        .error_for_status()
        .unwrap();
    let cookie = response.cookies().next().unwrap();
    let secret = format!("{}:{}", cookie.name(), cookie.value());
    pubky.restore_session(&secret).await.unwrap()
}

/// Approve a grant with `caps` for `signer` as `client_id` and return the
/// resulting session.
async fn grant_session(
    testnet: &EphemeralTestnet,
    signer: &PubkySigner,
    caps: Capabilities,
    client_id: &str,
) -> PubkySession {
    let pubky = testnet.sdk().unwrap();
    let auth = PubkyGrantAuthFlow::builder(
        &caps,
        AuthFlowKind::signin(),
        ClientId::new(client_id).unwrap(),
    )
    .relay(testnet.http_relay().local_link_url())
    .client(pubky.client().clone())
    .start()
    .unwrap();
    signer
        .approve_auth(&auth.authorization_url())
        .await
        .unwrap();
    auth.await_approval().await.unwrap()
}
