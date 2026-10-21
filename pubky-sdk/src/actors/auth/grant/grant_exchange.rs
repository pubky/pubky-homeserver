//! grant-mode session construction functions.
//!
//! This module is the SDK's gateway to the homeserver's grant-based auth flow:
//! - [`credential_from_grant_exchange`] turns a fresh user-signed grant
//!   into a ready-to-use grant credential.
//! - [`signup_account_from_grant`] creates a user via grant + `PoP` without
//!   minting a session.
//!
//! Current grant-session operations (`current_bearer`, `force_refresh`,
//! `grant_id`) live on [`super::view::GrantSessionView`].

use pubky_common::{
    auth::{grant::GrantClaims, grant_session_responses::GrantSessionResponse},
    crypto::PublicKey,
};
use reqwest::{Method, Response};

use super::{
    credential::{GrantCredential, sign_pop_for_grant},
    pop_signer::GrantPopSigner,
};
use crate::PubkyHttpClient;
use crate::client::without_cookies;
use crate::errors::{CredentialRefreshError, Error, RequestError, Result};

/// Establish a grant-backed session by exchanging a user-signed grant for
/// an opaque bearer at the user's homeserver.
///
/// Used by [`PubkyGrantAuthFlow`](crate::PubkyGrantAuthFlow) once the signer (Ring)
/// has delivered an encrypted grant via the relay channel.
///
/// # Errors
/// - Propagates HTTP transport / server errors from `POST /auth/grant/session`.
/// - Returns [`crate::errors::Error::Authentication`] if the response bearer
///   cannot be decoded.
pub(crate) async fn credential_from_grant_exchange(
    client: &PubkyHttpClient,
    grant_jws: String,
    grant_claims: GrantClaims,
    client_signer: GrantPopSigner,
    homeserver_pubkey: PublicKey,
) -> Result<GrantCredential> {
    let response = post_grant_session(
        client,
        &grant_jws,
        &grant_claims,
        &client_signer,
        &homeserver_pubkey,
    )
    .await?;
    Ok(GrantCredential::from_response(
        response,
        grant_jws,
        grant_claims,
        client_signer,
        homeserver_pubkey,
    ))
}

/// Create a user via `POST /auth/grant/signup` without minting a session.
pub(crate) async fn signup_account_from_grant(
    client: &PubkyHttpClient,
    grant_jws: &str,
    grant_claims: &GrantClaims,
    client_signer: &GrantPopSigner,
    homeserver_pk: &PublicKey,
    signup_token: Option<&str>,
) -> Result<()> {
    let pop_jws = sign_pop_for_grant(client_signer, homeserver_pk, &grant_claims.jti).await?;
    let body = serde_json::json!({ "grant": grant_jws, "pop": pop_jws });
    let mut url = url::Url::parse(&format!(
        "https://{}/auth/grant/signup",
        homeserver_pk.z32()
    ))
    .map_err(|e| RequestError::Validation {
        message: format!("invalid signup url: {e}"),
    })?;
    if let Some(token) = signup_token {
        url.query_pairs_mut().append_pair("signup_token", token);
    }
    let resp = without_cookies(client.cross_request(Method::POST, url).await?)
        .json(&body)
        .send()
        .await?;
    client.check_http_status(resp).await?;
    Ok(())
}

/// `POST` a grant + `PoP` proof to `/auth/grant/session`.
async fn post_grant_session(
    client: &PubkyHttpClient,
    grant_jws: &str,
    grant_claims: &GrantClaims,
    client_signer: &GrantPopSigner,
    homeserver_pk: &PublicKey,
) -> Result<GrantSessionResponse> {
    let resp = post_grant_session_response(
        client,
        grant_jws,
        grant_claims,
        client_signer,
        homeserver_pk,
    )
    .await?;
    let resp = client.check_http_status(resp).await?;
    let response: GrantSessionResponse =
        resp.json().await.map_err(|e| RequestError::DecodeJson {
            message: format!("decoding grant session response: {e}"),
        })?;
    Ok(response)
}

/// Refresh a grant session while redacting HTTP request diagnostics.
///
/// HTTP request errors are replaced with their secret-safe refresh category.
/// Other error categories pass through unchanged.
pub(crate) async fn refresh_grant_session(
    client: &PubkyHttpClient,
    grant_jws: &str,
    grant_claims: &GrantClaims,
    client_signer: &GrantPopSigner,
    homeserver_pk: &PublicKey,
) -> Result<GrantSessionResponse> {
    let response = post_grant_session_response(
        client,
        grant_jws,
        grant_claims,
        client_signer,
        homeserver_pk,
    )
    .await
    .map_err(redact_refresh_request_error)?;
    let status = response.status();
    if !status.is_success() {
        // Acquiring then dropping the body stream cancels the unread browser
        // `ReadableStream`; native transports also release the response here.
        drop(response.bytes_stream());
        return Err(CredentialRefreshError::Request {
            status: Some(status),
        }
        .into());
    }
    response
        .json()
        .await
        .map_err(|_error| CredentialRefreshError::Request {
            status: Some(status),
        })
        .map_err(Into::into)
}

fn redact_refresh_request_error(error: Error) -> Error {
    match error {
        Error::Request(RequestError::Server { status, .. }) => CredentialRefreshError::Request {
            status: Some(status),
        }
        .into(),
        Error::Request(_) => CredentialRefreshError::Request { status: None }.into(),
        error => error,
    }
}

async fn post_grant_session_response(
    client: &PubkyHttpClient,
    grant_jws: &str,
    grant_claims: &GrantClaims,
    client_signer: &GrantPopSigner,
    homeserver_pk: &PublicKey,
) -> Result<Response> {
    let pop_jws = sign_pop_for_grant(client_signer, homeserver_pk, &grant_claims.jti).await?;
    let body = serde_json::json!({ "grant": grant_jws, "pop": pop_jws });

    let request = client
        .cross_request_via_homeserver(
            Method::POST,
            homeserver_pk,
            &grant_claims.iss,
            "/auth/grant/session",
        )
        .await?;
    Ok(without_cookies(request).json(&body).send().await?)
}
