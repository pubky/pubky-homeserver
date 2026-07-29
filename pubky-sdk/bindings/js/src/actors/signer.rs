use wasm_bindgen::prelude::*;

use super::{pkdns::Pkdns, session::Session};
use crate::js_error::JsResult;
use crate::wrappers::{keys::Keypair, keys::PublicKey};
use pubky::ClientId;

/// Holds a user’s `Keypair` and performs identity operations:
/// - `signup` creates a new homeserver user.
/// - `signin` creates a homeserver session for an existing user.
/// - Approve pubkyauth requests
/// - Publish PKDNS when signer-bound
#[wasm_bindgen]
pub struct Signer(pub(crate) pubky::PubkySigner);

#[wasm_bindgen]
impl Signer {
    /// Create a signer from a `Keypair` (prefer `pubky.signer(kp)`).
    ///
    /// @param {Keypair} keypair
    /// @returns {Signer}
    #[wasm_bindgen(js_name = "fromKeypair")]
    pub fn new(keypair: &Keypair) -> JsResult<Signer> {
        let signer = pubky::PubkySigner::new(keypair.as_inner().clone())?;
        Ok(Signer(signer))
    }

    /// Get the public key of this signer.
    ///
    /// @returns {PublicKey}
    #[wasm_bindgen(js_name = "publicKey", getter)]
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key().into()
    }

    /// Sign up at a homeserver.
    ///
    /// Creates the account and publishes PKDNS. Call `signin(clientId)` to create a session.
    ///
    /// @param {PublicKey} homeserver The homeserver’s public key.
    /// @param {string|null} signupToken Invite/registration token or `null`.
    /// @returns {Promise<void>}
    ///
    /// @throws {PubkyError}
    /// - `AuthenticationError` (bad/expired token)
    /// - `RequestError` (network/server)
    #[wasm_bindgen]
    pub async fn signup(
        &self,
        homeserver: &PublicKey,
        signup_token: Option<String>,
    ) -> JsResult<()> {
        self.0
            .signup(homeserver.as_inner(), signup_token.as_deref())
            .await?;
        Ok(())
    }

    /// Fast sign-in for a returning user. Publishes PKDNS in the background.
    ///
    /// Creates a valid grant-backed homeserver Session with root capabilities.
    /// `clientId` is shown in the user's grant/session list.
    /// @param {string} clientId App identifier, typically a domain.
    ///
    /// @returns {Promise<Session>}
    ///
    /// @throws {PubkyError}
    #[wasm_bindgen]
    pub async fn signin(&self, client_id: String) -> JsResult<Session> {
        let client_id = parse_client_id(&client_id)?;
        Ok(Session(self.0.signin(client_id).await?))
    }

    /// Blocking sign-in. Waits for PKDNS publish to complete (slower; safer).
    ///
    /// Creates a valid grant-backed homeserver Session with root capabilities.
    /// `clientId` is shown in the user's grant/session list.
    /// @param {string} clientId App identifier, typically a domain.
    ///
    /// @returns {Promise<Session>}
    #[wasm_bindgen(js_name = "signinBlocking")]
    pub async fn signin_blocking(&self, client_id: String) -> JsResult<Session> {
        let client_id = parse_client_id(&client_id)?;
        Ok(Session(self.0.signin_blocking(client_id).await?))
    }

    /// Legacy cookie signup. Prefer `signup()` plus `signin(clientId)`.
    ///
    /// @deprecated Prefer `signup()` followed by `signin(clientId)`.
    #[wasm_bindgen(js_name = "signupCookie")]
    pub async fn signup_cookie(
        &self,
        homeserver: &PublicKey,
        signup_token: Option<String>,
    ) -> JsResult<Session> {
        let session = self
            .0
            .signup_cookie(homeserver.as_inner(), signup_token.as_deref())
            .await?;
        Ok(Session(session))
    }

    /// Legacy cookie signin. Prefer `signin(clientId)`.
    ///
    /// @deprecated Prefer `signin(clientId)`.
    #[wasm_bindgen(js_name = "signinCookie")]
    pub async fn signin_cookie(&self) -> JsResult<Session> {
        Ok(Session(self.0.signin_cookie().await?))
    }

    /// Legacy cookie blocking signin. Prefer `signinBlocking(clientId)`.
    ///
    /// @deprecated Prefer `signinBlocking(clientId)`.
    #[wasm_bindgen(js_name = "signinCookieBlocking")]
    pub async fn signin_cookie_blocking(&self) -> JsResult<Session> {
        Ok(Session(self.0.signin_cookie_blocking().await?))
    }

    /// Approve a `pubkyauth://` request URL (encrypts & POSTs the signed AuthToken).
    #[wasm_bindgen(js_name = "approveAuthRequest")]
    pub async fn approve_auth(&self, pubkyauth_url: String) -> JsResult<()> {
        self.0.approve_auth(&pubkyauth_url).await?;
        Ok(())
    }

    /// Handle a `pubkyauth://` deep link.
    ///
    /// Auth requests are approved through their relay. A `direct_signup` link
    /// creates an account on its target homeserver.
    #[wasm_bindgen(js_name = "handleDeepLink")]
    pub async fn handle_deeplink(&self, pubkyauth_url: String) -> JsResult<()> {
        self.0.handle_deeplink(&pubkyauth_url).await?;
        Ok(())
    }

    /// Get a PKDNS actor bound to this signer's client & keypair (publishing enabled).
    ///
    /// @returns {Pkdns}
    ///
    /// @example
    /// await signer.pkdns.publishHomeserverIfStale(homeserverPk);
    #[wasm_bindgen(getter)]
    pub fn pkdns(&self) -> Pkdns {
        Pkdns(self.0.pkdns())
    }
}

fn parse_client_id(value: &str) -> JsResult<ClientId> {
    ClientId::new(value).map_err(|e| {
        pubky::Error::Authentication(pubky::errors::AuthError::Validation(e.to_string())).into()
    })
}
