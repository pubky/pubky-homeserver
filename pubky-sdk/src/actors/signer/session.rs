use std::sync::Arc;

use pubky_common::auth::{
    AuthToken,
    grant::GrantClaims,
    jws::{ClientId, GRANT_JWS_TYP, GrantId},
};
use pubky_common::crypto::Keypair;
use reqwest::Method;
use url::Url;

use super::PubkySigner;
use crate::{
    Capabilities, Capability, PubkySession, PublicKey, Result,
    actors::auth::{
        cookie::CookieCredential,
        grant::constants::DEFAULT_GRANT_LIFETIME_SECS,
        grant::grant_exchange::{credential_from_grant_exchange, signup_account_from_grant},
        grant::pop_signer::GrantPopSigner,
    },
    cross_log,
    util::check_http_status,
};

const SIGNUP_CLIENT_ID: &str = "pubky.signup";
const SIGNUP_GRANT_LIFETIME_SECS: u64 = 5 * 60;

#[derive(Debug, Clone, Copy)]
enum PublishMode {
    Background,
    Blocking,
}

impl PubkySigner {
    /// Create an account on a homeserver.
    ///
    /// Side effects:
    /// - Publishes the `_pubky` pkarr record pointing to `homeserver` (force mode).
    ///
    /// Notes:
    /// - Uses a short-lived root grant + `PoP` proof (sufficient for signup).
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Parse`] if the homeserver URL cannot be constructed.
    /// - Propagates transport failures while creating the account or publishing the homeserver record.
    /// - Propagates validation errors from the session hydration step.
    pub async fn signup(&self, homeserver: &PublicKey, signup_token: Option<&str>) -> Result<()> {
        cross_log!(info, "Signing up new account on homeserver {}", homeserver);

        let client_keypair = Keypair::random();
        let (grant_jws, grant_claims) = self.signup_grant(&client_keypair)?;
        let client_signer = GrantPopSigner::local(client_keypair);
        signup_account_from_grant(
            &self.client,
            &grant_jws,
            &grant_claims,
            &client_signer,
            homeserver,
            signup_token,
        )
        .await?;

        self.publish_signup_homeserver(homeserver).await?;
        Ok(())
    }

    // All of these methods use root capabilities

    /// Sign in to the users homeserver by locally signing a root-capability token.
    /// This call returns a user session.
    ///
    /// In case the users pkdns records are stale, this call with republish them in the background.
    ///
    /// Prefer this signin for best user experience, it returns fast.
    ///
    /// # Errors
    /// - Propagates transport failures during the session exchange.
    /// - Propagates validation errors from the session exchange or PKDNS publishing.
    pub async fn signin(&self, client_id: ClientId) -> Result<PubkySession> {
        self.signin_with_publish(client_id, PublishMode::Background)
            .await
    }

    /// Sign in by locally signing a root-capability token. Returns a session-bound session.
    /// Publishes the homeserver record if stale in the background.
    ///
    /// Prefer this signin for highest guarantees of discoverability from Dht and pkarr relays,
    /// it returns slow (~3-5 seconds).
    ///
    /// # Errors
    /// - Propagates transport failures during the session exchange.
    /// - Propagates validation errors from the session exchange or PKDNS publishing.
    pub async fn signin_blocking(&self, client_id: ClientId) -> Result<PubkySession> {
        self.signin_with_publish(client_id, PublishMode::Blocking)
            .await
    }

    /// Internal helper to sign in, then optionally refresh `_pubky` record.
    async fn signin_with_publish(
        &self,
        client_id: ClientId,
        mode: PublishMode,
    ) -> Result<PubkySession> {
        let user = self.keypair.public_key();
        let homeserver = self.pkdns().require_homeserver_of(&user).await?;
        let client_keypair = Keypair::random();
        let (grant_jws, grant_claims) = self.session_grant(client_id, &client_keypair);
        let client_signer = GrantPopSigner::local(client_keypair);
        let credential = credential_from_grant_exchange(
            &self.client,
            grant_jws,
            grant_claims,
            client_signer,
            homeserver,
        )
        .await?;
        let session = PubkySession::from_grant_credential(self.client.clone(), credential);
        cross_log!(
            info,
            "Signin completed for {}; mode {:?}",
            self.keypair.public_key(),
            mode
        );

        self.publish_after_signin(mode).await?;

        Ok(session)
    }

    /// Legacy cookie signup. Prefer [`Self::signup`] plus [`Self::signin`].
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Parse`] if the homeserver URL cannot be constructed.
    /// - Propagates transport failures while creating the account or publishing the homeserver record.
    /// - Propagates validation errors while hydrating the cookie session.
    pub async fn signup_cookie(
        &self,
        homeserver: &PublicKey,
        signup_token: Option<&str>,
    ) -> Result<PubkySession> {
        let url = Self::build_signup_url(homeserver, signup_token)?;
        let auth_token = self.root_capability_token();
        let response = self
            .send_signup_request(url, auth_token.serialize())
            .await?;

        self.publish_signup_homeserver(homeserver).await?;
        let cookie_credential =
            CookieCredential::from_response(response, Some(homeserver.clone())).await?;
        Ok(PubkySession::from_credential(
            self.client.clone(),
            Arc::new(cookie_credential),
        ))
    }

    /// Legacy cookie signin. Prefer [`Self::signin`].
    ///
    /// # Errors
    /// - Propagates transport failures during the session exchange.
    /// - Propagates validation errors while creating the cookie credential.
    pub async fn signin_cookie(&self) -> Result<PubkySession> {
        self.signin_cookie_with_publish(PublishMode::Background)
            .await
    }

    /// Legacy cookie signin with blocking PKDNS refresh. Prefer [`Self::signin_blocking`].
    ///
    /// # Errors
    /// - Propagates transport failures during the session exchange.
    /// - Propagates failures while refreshing the homeserver record.
    pub async fn signin_cookie_blocking(&self) -> Result<PubkySession> {
        self.signin_cookie_with_publish(PublishMode::Blocking).await
    }

    async fn signin_cookie_with_publish(&self, mode: PublishMode) -> Result<PubkySession> {
        let token = self.root_capability_token();
        let user = self.keypair.public_key();
        let homeserver = self.pkdns().get_homeserver_of(&user).await;
        let credential =
            CookieCredential::from_auth_token(&token, &self.client, homeserver).await?;
        let session = PubkySession::from_cookie_credential(self.client.clone(), credential);
        self.publish_after_signin(mode).await?;
        Ok(session)
    }

    async fn publish_after_signin(&self, mode: PublishMode) -> Result<()> {
        match mode {
            PublishMode::Blocking => {
                cross_log!(
                    info,
                    "Publishing homeserver for {} in blocking mode",
                    self.keypair.public_key()
                );
                self.pkdns().publish_homeserver_if_stale(None).await?;
            }
            PublishMode::Background => {
                let signer = self.clone();
                let fut = async move {
                    cross_log!(
                        info,
                        "Background publish of homeserver for {} started",
                        signer.keypair.public_key()
                    );
                    if let Err(e) = signer.pkdns().publish_homeserver_if_stale(None).await {
                        cross_log!(
                            error,
                            "Background publish for {} failed: {:?}",
                            signer.keypair.public_key(),
                            e
                        );
                    } else {
                        cross_log!(
                            info,
                            "Background publish task for {} completed",
                            signer.keypair.public_key()
                        );
                    }
                };
                #[cfg(not(target_arch = "wasm32"))]
                tokio::spawn(fut);
                #[cfg(target_arch = "wasm32")]
                wasm_bindgen_futures::spawn_local(fut);
            }
        }
        Ok(())
    }

    fn build_signup_url(homeserver: &PublicKey, signup_token: Option<&str>) -> Result<Url> {
        let mut url = Url::parse(&format!("https://{}", homeserver.z32()))?;
        url.set_path("/signup");
        if let Some(token) = signup_token {
            url.query_pairs_mut().append_pair("signup_token", token);
        }
        Ok(url)
    }

    fn root_capability_token(&self) -> AuthToken {
        let capabilities = Capabilities::builder().cap(Capability::root()).finish();
        AuthToken::sign(&self.keypair, capabilities)
    }

    fn signup_grant(&self, client_keypair: &Keypair) -> Result<(String, GrantClaims)> {
        let client_id = ClientId::new(SIGNUP_CLIENT_ID)
            .map_err(|e| crate::errors::AuthError::Validation(e.to_string()))?;
        let claims = self.grant_claims(client_id, client_keypair, SIGNUP_GRANT_LIFETIME_SECS);
        let jws = claims.sign(&self.keypair, GRANT_JWS_TYP);
        Ok((jws, claims))
    }

    fn session_grant(
        &self,
        client_id: ClientId,
        client_keypair: &Keypair,
    ) -> (String, GrantClaims) {
        let claims = self.grant_claims(client_id, client_keypair, DEFAULT_GRANT_LIFETIME_SECS);
        let jws = claims.sign(&self.keypair, GRANT_JWS_TYP);
        (jws, claims)
    }

    fn grant_claims(
        &self,
        client_id: ClientId,
        client_keypair: &Keypair,
        lifetime_secs: u64,
    ) -> GrantClaims {
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        GrantClaims {
            iss: self.keypair.public_key(),
            client_id,
            caps: Capabilities::builder()
                .cap(Capability::root())
                .finish()
                .to_vec(),
            cnf: client_keypair.public_key(),
            jti: GrantId::generate(),
            iat: now,
            exp: now + lifetime_secs,
        }
    }

    async fn send_signup_request(&self, url: Url, body: Vec<u8>) -> Result<reqwest::Response> {
        let response = self
            .client
            .cross_request(Method::POST, url)
            .await?
            .body(body)
            .send()
            .await?;

        // Map non-2xx into our error type; keep body/headers intact for the caller.
        check_http_status(response).await
    }

    async fn publish_signup_homeserver(&self, homeserver: &PublicKey) -> Result<()> {
        cross_log!(
            info,
            "Signup request for {} succeeded; publishing homeserver",
            self.keypair.public_key()
        );

        self.pkdns()
            .publish_homeserver_force(Some(homeserver))
            .await?;

        cross_log!(
            info,
            "Signup homeserver publish complete for {}",
            self.keypair.public_key()
        );
        Ok(())
    }
}
