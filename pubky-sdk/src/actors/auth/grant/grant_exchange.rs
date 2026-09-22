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
    auth::{grant::GrantClaims, grant_session_responses::GrantSessionResponse, jws::RandomId},
    crypto::PublicKey,
};
use reqwest::Method;

use super::{
    credential::{GrantCredential, sign_pop_for_grant},
    pop_signer::GrantPopSigner,
};
use crate::PubkyHttpClient;
use crate::errors::{RequestError, Result};

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
    session_id: Option<RandomId>,
) -> Result<GrantCredential> {
    let supports_slots = client
        .features
        .supports(
            client,
            &homeserver_pubkey,
            pubky_common::constants::features::GRANT_SESSION_SLOTS,
        )
        .await;
    if session_id.is_some() && !supports_slots {
        return Err(RequestError::Validation {
            message: "Homeserver does not advertise grant-session-slots; browser tab restore requires an upgraded homeserver".into(),
        }.into());
    }
    let session_id = supports_slots.then(|| session_id.unwrap_or_else(RandomId::generate));
    let response = post_grant_session(
        client,
        &grant_jws,
        &grant_claims,
        &client_signer,
        &homeserver_pubkey,
        session_id.as_ref(),
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
pub(crate) async fn post_grant_session(
    client: &PubkyHttpClient,
    grant_jws: &str,
    grant_claims: &GrantClaims,
    client_signer: &GrantPopSigner,
    homeserver_pk: &PublicKey,
    session_id: Option<&RandomId>,
) -> Result<GrantSessionResponse> {
    let pop_jws = sign_pop_for_grant(client_signer, homeserver_pk, &grant_claims.jti).await?;
    let mut body = serde_json::json!({ "grant": grant_jws, "pop": pop_jws });
    if let Some(id) = session_id {
        body["session_id"] = serde_json::json!(id);
    }

    let resp = client
        .cross_request_via_homeserver(
            Method::POST,
            homeserver_pk,
            &grant_claims.iss,
            "/auth/grant/session",
        )
        .await?
        .json(&body)
        .send()
        .await?;
    let resp = client.check_http_status(resp).await?;
    let response: GrantSessionResponse =
        resp.json().await.map_err(|e| RequestError::DecodeJson {
            message: format!("decoding grant session response: {e}"),
        })?;
    if response.session.session_id.as_ref() != session_id {
        return Err(RequestError::Validation {
            message: "Homeserver returned a different grant session identity".into(),
        }
        .into());
    }
    Ok(response)
}
