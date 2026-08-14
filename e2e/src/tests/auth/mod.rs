mod cookie;
mod grant;
mod pkdns;
mod signup_tokens;

use super::build_full_testnet;
use pubky_testnet::pubky::deep_links::{
    DeepLink, DeepLinkScheme, DirectSignupDeepLink, DirectSignupParams,
};
use pubky_testnet::pubky::errors::{Error, RequestError};
use pubky_testnet::pubky::pkarr;
use pubky_testnet::pubky::IntoPubkyResource;
#[allow(deprecated, reason = "E2E tests cover the deprecated cookie flow")]
use pubky_testnet::pubky::PubkyCookieAuthFlow;
use pubky_testnet::pubky::{
    AuthFlowKind, ClientId, GrantManager, Keypair, Method, PubkyGrantAuthFlow, PubkyHttpClient,
    PubkySession, StatusCode,
};
use pubky_testnet::pubky_common::capabilities::{Capabilities, Capability};
use pubky_testnet::{
    pubky_homeserver::{ConfigToml, SignupMode},
    EphemeralTestnet, Testnet,
};
use std::str::FromStr;
use std::time::Duration;

async fn assert_scoped_write_access(session: &PubkySession) {
    session
        .storage()
        .put("/pub/pubky.app/foo", Vec::<u8>::new())
        .await
        .unwrap();

    let err = session
        .storage()
        .put("/pub/pubky.app", Vec::<u8>::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::FORBIDDEN)
    );

    let err = session
        .storage()
        .put("/pub/foo.bar/file", Vec::<u8>::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::FORBIDDEN)
    );
}
