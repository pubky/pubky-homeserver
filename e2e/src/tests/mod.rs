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

use pubky_testnet::pubky::{AuthFlowKind, ClientId, PubkyGrantAuthFlow, PubkySession, PubkySigner};
use pubky_testnet::pubky_common::capabilities::Capabilities;
use pubky_testnet::EphemeralTestnet;

async fn build_full_testnet() -> EphemeralTestnet {
    EphemeralTestnet::builder()
        .with_http_relay()
        .config(pubky_testnet::pubky_homeserver::ConfigToml::default_test_config())
        .build()
        .await
        .unwrap()
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
