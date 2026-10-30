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
use crate::errors::{CredentialRefreshError, Error, RequestError, Result};
use crate::util::read_json_body;

/// Maximum size of a `/auth/grant/session` response body: a session id,
/// expiry and capabilities, the same shape as a cookie session record.
pub(super) const MAX_GRANT_SESSION_BYTES: usize = 64 * 1024;

/// Decode a refreshed grant session response, redacting every read or decode
/// failure to its secret-safe refresh category.
async fn decode_refreshed_grant_session(response: Response) -> Result<GrantSessionResponse> {
    let status = response.status();
    read_json_body(response, MAX_GRANT_SESSION_BYTES, "grant session response")
        .await
        .map_err(|_error| {
            CredentialRefreshError::Request {
                status: Some(status),
            }
            .into()
        })
}

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
    let resp = client
        .cross_request(Method::POST, url)
        .await?
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
    read_json_body(resp, MAX_GRANT_SESSION_BYTES, "grant session response").await
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
    decode_refreshed_grant_session(response).await
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

    Ok(client
        .cross_request_via_homeserver(
            Method::POST,
            homeserver_pk,
            &grant_claims.iss,
            "/auth/grant/session",
        )
        .await?
        .json(&body)
        .send()
        .await?)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod redaction_tests {
    use super::*;
    use crate::util::tests::serve_response;

    #[tokio::test]
    async fn refreshed_grant_session_failures_stay_redacted() {
        let declared = MAX_GRANT_SESSION_BYTES + 1;
        let body = b"not json";
        // Oversized, undecodable, and truncated mid-body (connection dropped).
        for (framing, wire, drop_connection) in [
            (
                format!("Content-Length: {declared}\r\n"),
                b"".as_slice(),
                false,
            ),
            (
                format!("Content-Length: {}\r\n", body.len()),
                body.as_slice(),
                false,
            ),
            (
                "Content-Length: 100\r\n".to_string(),
                b"partial".as_slice(),
                true,
            ),
        ] {
            let (response, connection) = serve_response(200, &framing, wire).await;
            if drop_connection {
                drop(connection);
            }
            let error = decode_refreshed_grant_session(response).await.unwrap_err();
            assert!(matches!(
                error,
                Error::CredentialRefresh(CredentialRefreshError::Request {
                    status: Some(reqwest::StatusCode::OK)
                })
            ));
        }
    }
}
