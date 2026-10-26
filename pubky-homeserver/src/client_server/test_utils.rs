//! Helpers shared by the client server's tests.

use axum::http::header;
use axum_test::TestServer;
use pubky_common::{auth::AuthToken, capabilities::Capability, crypto::Keypair};

/// Sign `keypair` up through `POST /signup` with a cookie session holding
/// `capabilities`, returning the `Set-Cookie` value for later requests.
pub(crate) async fn signup_cookie(
    server: &TestServer,
    keypair: &Keypair,
    capabilities: Vec<Capability>,
) -> String {
    let auth_token = AuthToken::sign(keypair, capabilities);
    let response = server
        .post("/signup")
        .add_header("host", keypair.public_key().z32())
        .bytes(auth_token.serialize().into())
        .expect_success()
        .await;
    response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|h| h.to_str().ok())
        .expect("signup should return a session cookie")
        .to_string()
}
