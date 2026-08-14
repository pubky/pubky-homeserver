mod admin;
mod auth;
mod events;
mod http;
mod metrics;
mod private_data;
mod rate_limiting;
mod storage;

async fn build_full_testnet() -> pubky_testnet::EphemeralTestnet {
    pubky_testnet::EphemeralTestnet::builder()
        .with_http_relay()
        .config(pubky_testnet::pubky_homeserver::ConfigToml::default_test_config())
        .build()
        .await
        .unwrap()
}
