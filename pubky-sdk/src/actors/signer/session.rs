use pubky_common::auth::{
    grant::GrantClaims,
    jws::{ClientId, GRANT_JWS_TYP, GrantId},
};
use pubky_common::crypto::Keypair;

use super::PubkySigner;
use crate::{
    Capabilities, Capability, PubkySession, PublicKey, Result,
    actors::auth::{
        grant::constants::DEFAULT_GRANT_LIFETIME_SECS,
        grant::credential::GrantChain,
        grant::grant_exchange::{credential_from_grant_exchange, signup_account_from_grant},
        grant::pop_signer::GrantPopSigner,
    },
    cross_log,
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
    /// This is a **one-time** operation. After signing up, call
    /// [`signin`](Self::signin) to obtain a [`PubkySession`] for reading and
    /// writing data.
    ///
    /// Side effects:
    /// - Publishes the `_pubky` PKARR record pointing to `homeserver` (force mode),
    ///   so other users can discover this identity.
    ///
    /// # Arguments
    /// - `homeserver` — public key of the homeserver to register on.
    /// - `signup_token` — optional invite token required by some homeservers.
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

    /// Sign in to the user's homeserver and return a [`PubkySession`].
    ///
    /// Locally signs a root-capability grant and exchanges it for a
    /// session at the homeserver. If the user's PKDNS record is stale,
    /// it is republished **in the background** so this call returns fast.
    /// Grants root storage access (`/:rw`) without encryption keys. To receive
    /// keys, explicitly request `e` through [`crate::PubkyGrantAuthFlow`].
    ///
    /// # Arguments
    /// - `client_id` — a [`ClientId`] identifying your application (e.g.
    ///   `ClientId::new("my.app").unwrap()`). The homeserver records which
    ///   app holds each grant.
    ///
    /// # Example
    /// ```no_run
    /// # use pubky::{Pubky, Keypair, ClientId};
    /// # async fn run() -> pubky::Result<()> {
    /// let signer = Pubky::new()?.signer(Keypair::random());
    /// let session = signer.signin(ClientId::new("my.app").unwrap()).await?;
    /// println!("Signed in as {}", session.public_key());
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// - Propagates transport failures during the session exchange.
    /// - Propagates validation errors from the session exchange or PKDNS publishing.
    pub async fn signin(&self, client_id: ClientId) -> Result<PubkySession> {
        self.signin_with_publish(client_id, PublishMode::Background)
            .await
    }

    /// Sign in, **blocking** until the PKDNS record is republished (if stale).
    ///
    /// Unlike [`Self::signin`], this variant waits for the homeserver PKDNS
    /// record to be fully published before returning. This gives the highest
    /// guarantee of discoverability from the DHT and Pkarr relays, at the
    /// cost of being slower (~3–5 seconds).
    ///
    /// Use this when the signer's identity must be immediately discoverable
    /// by other users (e.g. first-time setup). For interactive apps, prefer
    /// [`Self::signin`] which publishes in the background.
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
            GrantChain::Direct,
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
