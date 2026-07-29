//! Legacy cookie auth flow — QR/deeplink → signer approval → cookie session.
//!
//! ## Sign in
//! ```no_run
//! # use pubky::{Capabilities, PubkyCookieAuthFlow, AuthFlowKind};
//! # async fn run() -> pubky::Result<()> {
//! # #[allow(deprecated)] {
//! let caps = Capabilities::default();
//! let flow = PubkyCookieAuthFlow::start(&caps, AuthFlowKind::signin())?;
//! println!("Scan to sign in: {}", flow.authorization_url());
//!
//! let session = flow.await_approval().await?;
//! println!("Signed in as {}", session.info().public_key());
//! # }
//! # Ok(()) }
//! ```
//!
//! ## Sign in (credential-level, for persistence or inspection)
//! ```no_run
//! # use pubky::{Capabilities, PubkyCookieAuthFlow, AuthFlowKind, PubkyHttpClient, PubkySession};
//! # async fn run() -> pubky::Result<()> {
//! # #[allow(deprecated)] {
//! let client = PubkyHttpClient::new()?;
//! let flow = PubkyCookieAuthFlow::builder(&Capabilities::default(), AuthFlowKind::signin())
//!     .client(client.clone())
//!     .start()?;
//! let credential = flow.await_credential().await?;
//! // ... store or inspect the credential ...
//! let session = PubkySession::from_cookie_credential(client, credential);
//! # }
//! # Ok(()) }
//! ```
//!
//! ## Sign up
//! ```no_run
//! # use pubky::{Capabilities, PubkyCookieAuthFlow, AuthFlowKind, PublicKey};
//! # async fn run() -> pubky::Result<()> {
//! # #[allow(deprecated)] {
//! let caps = Capabilities::default();
//! let homeserver: PublicKey = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo".parse().unwrap();
//! let flow = PubkyCookieAuthFlow::start(
//!     &caps,
//!     AuthFlowKind::signup(homeserver, Some("token".into())),
//! )?;
//! let session = flow.await_approval().await?;
//! # }
//! # Ok(()) }
//! ```

use url::Url;

#[allow(deprecated, reason = "Internal use of deprecated public API")]
use crate::AuthToken;
use crate::actors::auth::cookie::approval::CookieApproval;
use crate::actors::auth::cookie::builder::CookieAuthFlowBuilder;
use crate::actors::auth::cookie::credential::CookieCredential;
use crate::actors::auth::deep_links::DeepLink;
use crate::actors::auth::kind::AuthFlowKind;
use crate::actors::auth::relay::auth_relay_listener::AuthRelayListener;
use crate::errors::Result;
use crate::{Capabilities, PubkyHttpClient, PubkySession};

/// End-to-end **legacy (cookie) auth flow** handle.
///
/// 1. Construct with [`PubkyCookieAuthFlow::start`] or
///    [`PubkyCookieAuthFlow::builder`].
/// 2. Display [`authorization_url`](Self::authorization_url) (QR/deeplink) to
///    the signer.
/// 3. Complete the flow with [`await_approval`](Self::await_approval) for a
///    ready [`PubkySession`], or [`await_credential`](Self::await_credential)
///    for a raw [`CookieCredential`]. Non-blocking companions:
///    [`try_poll_once`](Self::try_poll_once),
///    [`try_poll_credential_once`](Self::try_poll_credential_once).
///
/// Background polling **starts immediately** at construction. Dropping this
/// value cancels the background task; the relay channel itself expires
/// server-side after its TTL.
#[deprecated(
    note = "Use PubkyGrantAuthFlow instead. Cookie-backed sessions are being phased out in favor of grant-backed, self-refreshing sessions."
)]
#[derive(Debug)]
pub struct PubkyCookieAuthFlow {
    relay_listener: AuthRelayListener,
    client: PubkyHttpClient,
    auth_url: DeepLink,
}

#[allow(deprecated, reason = "Internal use of deprecated public API")]
impl PubkyCookieAuthFlow {
    pub(crate) fn new(
        relay_listener: AuthRelayListener,
        client: PubkyHttpClient,
        auth_url: DeepLink,
    ) -> Self {
        Self {
            relay_listener,
            client,
            auth_url,
        }
    }

    /// Start a cookie flow with the default HTTP relay.
    ///
    /// Spawns the background poller immediately and returns a handle.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error`] if constructing the backing
    ///   [`PubkyHttpClient`] or generating the relay URL fails.
    pub fn start(caps: &Capabilities, auth_kind: AuthFlowKind) -> Result<Self> {
        CookieAuthFlowBuilder::new(caps.clone(), auth_kind).start()
    }

    /// Create a builder to override the **relay** and/or provide a custom
    /// **client**.
    #[must_use]
    pub fn builder(caps: &Capabilities, auth_kind: AuthFlowKind) -> CookieAuthFlowBuilder {
        CookieAuthFlowBuilder::new(caps.clone(), auth_kind)
    }

    /// The `pubkyauth://` deep link you display (QR/URL) to the signer.
    #[must_use]
    pub fn authorization_url(&self) -> Url {
        self.auth_url.clone().into()
    }

    /// Block until the signer approves and return a ready-to-use
    /// [`PubkySession`].
    ///
    /// Composes [`await_credential`](Self::await_credential) +
    /// [`PubkySession::from_cookie_credential`]. Use
    /// [`await_credential`](Self::await_credential) directly if you need to
    /// inspect or persist the credential before building a session.
    ///
    /// Signup flows bind the cookie credential to the homeserver named in the
    /// signup deep link. Signin flows do not name a homeserver, so their cookie
    /// credential remains unbound until a successful
    /// [`PubkySession::revalidate`](PubkySession::revalidate). Until then, the
    /// session can still use normal cookie storage APIs, but it will not
    /// authenticate private event streams.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Authentication`] if the relay channel
    ///   expires before approval.
    /// - Propagates HTTP/transport failures while polling the relay or
    ///   exchanging the token at `/session`.
    pub async fn await_approval(self) -> Result<PubkySession> {
        let client = self.client.clone();
        let credential = self.await_credential().await?;
        Ok(PubkySession::from_cookie_credential(client, credential))
    }

    /// Block until the signer approves and the homeserver issues a
    /// [`CookieCredential`].
    ///
    /// The credential can be inspected, persisted, or lifted into a full
    /// [`PubkySession`] via [`PubkySession::from_cookie_credential`].
    ///
    /// Signup credentials are bound immediately to the deep link homeserver.
    /// Signin credentials are unbound because the signin deep link carries no
    /// homeserver; call [`PubkySession::revalidate`](PubkySession::revalidate)
    /// after constructing a session if it needs to authenticate private event
    /// streams.
    ///
    /// # Errors
    /// - See [`await_approval`](Self::await_approval).
    pub async fn await_credential(self) -> Result<CookieCredential> {
        let homeserver = self.target_homeserver();
        let Self {
            relay_listener,
            client,
            ..
        } = self;
        let approval = Self::await_decoded_approval(relay_listener).await?;
        CookieCredential::from_auth_token(&approval.0, &client, homeserver).await
    }

    /// Block until the signer approves and we receive an [`AuthToken`].
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Authentication`] if the relay channel
    ///   expires before approval.
    /// - Propagates HTTP/transport failures encountered while polling the relay.
    pub async fn await_token(self) -> Result<AuthToken> {
        let approval = Self::await_decoded_approval(self.relay_listener).await?;
        Ok(approval.0)
    }

    /// Non-blocking probe (single step) that **consumes any ready token** and returns:
    /// - `Ok(Some(session))` when a token was delivered and the session established.
    /// - `Ok(None)` if no payload yet (keep polling later).
    /// - `Err(e)` on transport/server errors or if the channel expired.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Authentication`] if the relay channel
    ///   expired before a token arrived.
    /// - Propagates HTTP/transport failures from constructing the session.
    pub async fn try_poll_once(&self) -> Result<Option<PubkySession>> {
        let Some(credential) = self.try_poll_credential_once().await? else {
            return Ok(None);
        };
        Ok(Some(PubkySession::from_cookie_credential(
            self.client.clone(),
            credential,
        )))
    }

    /// Non-blocking variant of [`await_credential`](Self::await_credential).
    ///
    /// Returns `Ok(Some(credential))` when a token has been delivered and the
    /// homeserver has issued a credential; `Ok(None)` if no payload yet;
    /// `Err` on transport/server errors.
    ///
    /// # Errors
    /// - See [`try_poll_once`](Self::try_poll_once).
    pub async fn try_poll_credential_once(&self) -> Result<Option<CookieCredential>> {
        let Some(approval) = self.try_decoded_approval()? else {
            return Ok(None);
        };
        Ok(Some(
            CookieCredential::from_auth_token(&approval.0, &self.client, self.target_homeserver())
                .await?,
        ))
    }

    /// Non-blocking check: returns a verified `AuthToken` if the background
    /// poller has delivered it.
    ///
    /// - `Some(Ok(AuthToken))` when ready.
    /// - `Some(Err(_))` if the background task failed (expired/transport error).
    /// - `None` if not yet delivered.
    #[must_use]
    pub fn try_token(&self) -> Option<Result<AuthToken>> {
        match self.try_decoded_approval() {
            Ok(Some(approval)) => Some(Ok(approval.0)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }

    /// Homeserver this flow targets, when the deep link names one.
    ///
    /// Only signup links carry it. Signin links intentionally return `None`; a
    /// signin cookie stays unbound and private event streams remain anonymous
    /// until the resulting session successfully revalidates.
    fn target_homeserver(&self) -> Option<crate::PublicKey> {
        match &self.auth_url {
            DeepLink::Signup(link) => Some(link.params().homeserver.clone()),
            _ => None,
        }
    }

    async fn await_decoded_approval(relay_listener: AuthRelayListener) -> Result<CookieApproval> {
        let message = relay_listener.await_message().await?;
        CookieApproval::decode(&message)
    }

    fn try_decoded_approval(&self) -> Result<Option<CookieApproval>> {
        let Some(message) = self.relay_listener.try_message() else {
            return Ok(None);
        };
        Ok(Some(CookieApproval::decode(&message?)?))
    }
}

#[cfg(test)]
#[allow(
    deprecated,
    reason = "Tests exercise the deprecated cookie flow on purpose"
)]
mod tests {
    use super::*;
    use crate::actors::auth::relay::http_relay_inbox_channel::EncryptedHttpRelayInboxChannel;
    use crate::{Keypair, Pubky};
    use std::str::FromStr;

    async fn build_flow(auth_kind: AuthFlowKind) -> PubkyCookieAuthFlow {
        let relay = http_relay::HttpRelay::builder()
            .http_port(0)
            .run()
            .await
            .unwrap();
        let inbox_base = relay.local_url().join("inbox").unwrap();
        PubkyCookieAuthFlow::builder(&Capabilities::default(), auth_kind)
            .client(PubkyHttpClient::new().unwrap())
            .relay(inbox_base)
            .start()
            .unwrap()
    }

    async fn assert_resume_reconnects(auth_kind: AuthFlowKind) {
        let relay = http_relay::HttpRelay::builder()
            .http_port(0)
            .run()
            .await
            .unwrap();
        let inbox_base = relay.local_url().join("inbox").unwrap();
        let client = PubkyHttpClient::new().unwrap();
        let pubky = Pubky::with_client(client.clone());

        let caps = Capabilities::default();
        let flow = PubkyCookieAuthFlow::builder(&caps, auth_kind)
            .client(client.clone())
            .relay(inbox_base)
            .start()
            .unwrap();

        let auth_url_str = flow.authorization_url().as_str().to_string();

        let deep_link = DeepLink::from_str(&auth_url_str).unwrap();
        let secret = match &deep_link {
            DeepLink::Signin(s) => s.params().secret,
            DeepLink::Signup(s) => s.params().secret,
            _ => panic!("Expected signin or signup deep link"),
        };

        // Drop the original flow — simulates a page refresh wiping WASM memory.
        drop(flow);

        // Signer approves while the original flow is gone (token waits in the relay inbox).
        let keypair = Keypair::random();
        let token = AuthToken::sign(&keypair, caps);
        let token_bytes = token.serialize();

        let encrypted_channel =
            EncryptedHttpRelayInboxChannel::new(relay.local_url().join("inbox").unwrap(), secret)
                .unwrap();
        encrypted_channel
            .produce(&client, &token_bytes)
            .await
            .unwrap();

        let resumed = pubky.resume_cookie_auth_flow(&auth_url_str).unwrap();

        assert_eq!(
            resumed.authorization_url().as_str(),
            auth_url_str,
            "resumed flow produces the same authorization URL"
        );

        let received_token = resumed.await_token().await.unwrap();
        assert_eq!(
            received_token, token,
            "resumed flow retrieves the original token"
        );
    }

    #[tokio::test]
    async fn resume_signin_reconnects_to_same_channel() {
        assert_resume_reconnects(AuthFlowKind::signin()).await;
    }

    #[tokio::test]
    async fn resume_signup_reconnects_to_same_channel() {
        let homeserver = Keypair::random().public_key();
        let signup_token = Some("test-signup-token".to_string());
        assert_resume_reconnects(AuthFlowKind::signup(homeserver, signup_token)).await;
    }

    #[test]
    fn resume_rejects_invalid_url() {
        let client = PubkyHttpClient::new().unwrap();
        let pubky = Pubky::with_client(client);

        let result = pubky.resume_cookie_auth_flow("https://not-a-pubkyauth-url.com");
        assert!(result.is_err(), "non-pubkyauth URL should fail to resume");
    }

    #[test]
    fn resume_rejects_seed_export_url() {
        let client = PubkyHttpClient::new().unwrap();
        let pubky = Pubky::with_client(client);

        let url = "pubkyauth://secret_export?secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8";
        let result = pubky.resume_cookie_auth_flow(url);
        assert!(result.is_err(), "seed export URL should fail to resume");
    }

    #[test]
    fn resume_rejects_direct_signup_url() {
        let client = PubkyHttpClient::new().unwrap();
        let pubky = Pubky::with_client(client);

        let url =
            "pubkyauth://direct_signup?hs=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo";
        let result = pubky.resume_cookie_auth_flow(url);
        assert!(result.is_err(), "direct signup URL should fail to resume");
    }

    #[tokio::test]
    async fn signup_flow_binds_cookie_to_deep_link_homeserver() {
        let homeserver = Keypair::random().public_key();
        let flow = build_flow(AuthFlowKind::signup(
            homeserver.clone(),
            Some("token".to_string()),
        ))
        .await;

        assert_eq!(
            flow.target_homeserver(),
            Some(homeserver),
            "signup deep link binds the cookie to its homeserver"
        );
    }

    #[tokio::test]
    async fn signin_flow_leaves_cookie_unbound() {
        let flow = build_flow(AuthFlowKind::signin()).await;

        assert_eq!(
            flow.target_homeserver(),
            None,
            "signin deep link names no homeserver; the cookie binds on revalidate"
        );
    }
}
