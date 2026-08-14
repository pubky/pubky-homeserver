//! High-level facade for the Pubky crate.
//!
//! ## Mental model
//! - `Pubky` - your entrypoint/handle to the SDK. Owns a `PubkyHttpClient`.
//! - `Signer` - local private keys; can `signin`/`signup`, publish PKDNS, approve auth requests.
//! - `Session` - authenticated, “as me” API; exposes scoped storage.
//! - `PublicStorage` - unauthenticated, “read others” API.
//!
//! ## Quick starts
//! ### 1) App sign-in via QR/deeplink (auth flow)
//! ```no_run
//! use pubky::{Pubky, Capabilities, AuthFlowKind};
//!
//! # async fn run() -> pubky::Result<()> {
//! let pubky = Pubky::new()?; // or Pubky::testnet() / Pubky::with_client(...)
//!
//! let caps = Capabilities::builder()
//!     .write("/pub/demoapp/")
//!     .expect("static scope is canonical")
//!     .finish();
//! let flow = pubky.start_cookie_auth_flow(&caps, AuthFlowKind::signin())?;
//! println!("Scan to sign in: {}", flow.authorization_url());
//!
//! let session = flow.await_approval().await?;
//! println!("Signed in as {}", session.info().public_key());
//! # Ok(()) }
//! ```
//!
//! ### 2) Script that holds a key and signs in locally with write capabilities for a demo app
//! ```no_run
//! use pubky::{ClientId, Pubky, PubkySigner, Keypair};
//!
//! # async fn run() -> pubky::Result<()> {
//! let pubky = Pubky::new()?;
//! let kp = Keypair::random();
//! let signer = pubky.signer(kp);
//!
//! let session = signer.signin(ClientId::new("demo.app").unwrap()).await?;
//! // do writes as-me
//! session.storage().put("/pub/demoapp/hello.txt", "hi").await?;
//! # Ok(()) }
//! ```
//!
//! ### 3) Public read (no identity)
//! ```no_run
//! use pubky::Pubky;
//!
//! # async fn run(user: pubky::PublicKey) -> pubky::Result<()> {
//! let pubky = Pubky::new()?;
//! let public = pubky.public_storage();
//! let addr = format!("{}/pub/pubky.app/profile.json", user);
//! let html = public.get(addr).await?.text().await?;
//! # Ok(()) }
//! ```

use std::str::FromStr;

use crate::PublicKey;

#[allow(deprecated, reason = "Internal use of deprecated public API")]
use crate::PubkyCookieAuthFlow;
use crate::{
    Capabilities, ClientId, DelegatedGrantCredentialState, EventCursor, EventStreamBuilder,
    GrantCredential, Pkdns, PubkyGrantAuthFlow, PubkyHttpClient, PubkySession, PubkySigner,
    PublicStorage, Result,
    actors::AuthFlowKind,
    deep_links::{DeepLink, XCallbackParams},
    errors::AuthError,
};

#[cfg(not(target_arch = "wasm32"))]
use crate::errors::RequestError;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

/// High-level facade — your entry point to the Pubky SDK.
///
/// Create one at startup and share it across your app. It holds the HTTP client
/// and connection pool, and provides access to everything else: signers, sessions,
/// public storage, event streams, and PKDNS resolution.
///
/// Prefer to instantiate only once and reuse a single shared `Pubky` instead of
/// constructing one per request. This avoids reinitializing transports and keeps
/// the same connection pool available for repeated usage.
///
/// # Actor overview
///
/// ```text
///   Pubky::new()
///     ├── .signer(keypair)          → PubkySigner        (signup / signin / approve auth)
///     │     └── .signin(cid)        → PubkySession        (authenticated handle)
///     │           └── .storage()    → SessionStorage       (put / get / delete / list)
///     ├── .public_storage()         → PublicStorage        (read anyone's data, no keys)
///     ├── .pkdns()                  → Pkdns                (resolve homeserver records)
///     ├── .event_stream_for_user()  → EventStreamBuilder   (real-time SSE subscriptions)
///     └── .start_grant_auth_flow()  → PubkyGrantAuthFlow   (QR / deeplink auth)
/// ```
///
/// # Examples
///
/// **Sign in with a local key and write data:**
/// ```no_run
/// use pubky::{ClientId, Pubky, Keypair};
///
/// # async fn run() -> pubky::Result<()> {
/// let pubky = Pubky::new()?;
/// let signer = pubky.signer(Keypair::random());
///
/// let session = signer.signin(ClientId::new("demo.app").unwrap()).await?;
/// session.storage().put("/pub/demo.app/hello.txt", "hi").await?;
/// # Ok(()) }
/// ```
///
/// **Read public data (no identity needed):**
/// ```no_run
/// use pubky::Pubky;
///
/// # async fn run(user: pubky::PublicKey) -> pubky::Result<()> {
/// let pubky = Pubky::new()?;
/// let addr = format!("pubky://{}/pub/pubky.app/profile.json", user.z32());
/// let body = pubky.public_storage().get(addr).await?.text().await?;
/// # Ok(()) }
/// ```
#[derive(Clone, Debug)]
pub struct Pubky {
    client: PubkyHttpClient,
}

impl Pubky {
    /// Construct with defaults (mainnet relays, standard timeouts).
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error`] when the underlying [`PubkyHttpClient`] fails to
    ///   initialize (e.g., TLS configuration or relay/bootstrap setup issues).
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: PubkyHttpClient::new()?,
        })
    }

    /// Construct preconfigured for a local Pubky testnet.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error`] when the testnet-configured [`PubkyHttpClient`]
    ///   cannot be created (for example, invalid local relay/testnet configuration).
    pub fn testnet() -> Result<Self> {
        Ok(Self {
            client: PubkyHttpClient::testnet()?,
        })
    }

    /// Construct from an already-configured transport.
    #[must_use]
    pub const fn with_client(client: PubkyHttpClient) -> Self {
        Self { client }
    }

    /// Start an end-to-end **legacy (cookie)** auth flow (QR/deeplink).
    /// Depending on the auth kind, the flow will be different.
    /// - `AuthFlowKind::SignIn` - Sign in to an existing account.
    /// - `AuthFlowKind::SignUp` - Sign up for a new account.
    ///
    /// Use with `flow.authorization_url()` and then `await_approval()` (blocking)
    /// or `try_poll_once()` (non-blocking UI loops). Raw credentials are
    /// available via `await_credential()` / `try_poll_credential_once()`.
    ///
    /// For long-lived, mirror-friendly sessions prefer [`Self::start_grant_auth_flow`].
    ///
    /// # Errors
    /// - [`crate::errors::Error::Parse`] if internal URL construction for the flow
    ///   fails (e.g., malformed relay URL when configured via the builder).
    #[allow(
        deprecated,
        reason = "Cookie flow is intentionally exposed via this facade while deprecated"
    )]
    pub fn start_cookie_auth_flow(
        &self,
        caps: &Capabilities,
        auth_kind: AuthFlowKind,
    ) -> Result<PubkyCookieAuthFlow> {
        PubkyCookieAuthFlow::builder(caps, auth_kind)
            .client(self.client.clone())
            .start()
    }

    /// Start an end-to-end **Grant + `PoP`** auth flow (QR/deeplink).
    ///
    /// The resulting [`PubkyGrantAuthFlow`] emits a deep link with `cid` and `cpk`
    /// query params; the signer signs a `pubky-grant` JWS and the SDK exchanges
    /// it for a self-refreshing grant-backed session.
    ///
    /// # Errors
    /// - [`crate::errors::Error::Parse`] if internal URL construction for the flow
    ///   fails (e.g., malformed relay URL when configured via the builder).
    pub fn start_grant_auth_flow(
        &self,
        caps: &Capabilities,
        auth_kind: AuthFlowKind,
        client_id: ClientId,
    ) -> Result<PubkyGrantAuthFlow> {
        PubkyGrantAuthFlow::builder(caps, auth_kind, client_id)
            .client(self.client.clone())
            .start()
    }

    /// Resume a previously started auth flow from its `authorization_url`.
    /// **Cookie Auth Flow only**
    ///
    /// Parses the secret, capabilities, relay, and flow kind from the URL
    /// and rebuilds the flow against the same relay channel. If the signer
    /// already approved, the first `try_poll_once()` returns a session.
    ///
    /// The relay inbox persists messages for **~5 minutes**; resume is only
    /// viable within that window. After the TTL expires the channel is gone
    /// and you must start a fresh flow with
    /// [`start_cookie_auth_flow`](Self::start_cookie_auth_flow).
    ///
    /// The `authorization_url` contains the `client_secret`; follow
    /// [`start_cookie_auth_flow`](Self::start_cookie_auth_flow) storage guidance and delete it
    /// once resume completes or is abandoned.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Authentication`] if the URL cannot be parsed
    ///   or is not a signin/signup deep link.
    #[allow(
        deprecated,
        reason = "Cookie flow is intentionally exposed via this facade while deprecated"
    )]
    pub fn resume_cookie_auth_flow(&self, authorization_url: &str) -> Result<PubkyCookieAuthFlow> {
        let (caps, relay, secret, auth_kind, x_callback) = parse_auth_deep_link(authorization_url)?;

        PubkyCookieAuthFlow::builder(&caps, auth_kind)
            .client_secret(secret)
            .relay(relay)
            .x_callback(x_callback)
            .client(self.client.clone())
            .start()
    }

    /// Create a `PubkySigner` for a given keypair.
    #[must_use]
    pub fn signer(&self, keypair: crate::Keypair) -> PubkySigner {
        PubkySigner {
            client: self.client.clone(),
            keypair,
        }
    }

    /// Create a public, unauthenticated storage handle using this facade’s client.
    #[must_use]
    pub fn public_storage(&self) -> PublicStorage {
        PublicStorage {
            client: self.client.clone(),
        }
    }

    /// Read-only [`Pkdns`] actor (resolve `_pubky` records) using this facade’s client.
    #[must_use]
    pub fn pkdns(&self) -> Pkdns {
        Pkdns::with_client(self.client.clone())
    }

    /// Resolve current homeserver for a user public key via Pkarr.
    ///
    /// Returns `Ok(Some(host))` when the `_pubky` record resolves to a valid homeserver public
    /// key, `Ok(None)` when no record exists or no homeserver is configured, and `Err(_)` when
    /// Pkarr resolution fails or a resolved `_pubky` target is malformed.
    ///
    /// # Errors
    /// - [`crate::errors::Error::Pkarr`] if Pkarr resolution fails or the resolved `_pubky`
    ///   target is not a valid public key (see [`Pkdns::get_homeserver_of`]).
    pub async fn get_homeserver_of(
        &self,
        user_public_key: &PublicKey,
    ) -> Result<Option<PublicKey>> {
        Pkdns::with_client(self.client.clone())
            .get_homeserver_of(user_public_key)
            .await
    }

    /// Create an event stream builder for a single user.
    ///
    /// This is the simplest way to subscribe to events for one user. The homeserver
    /// is automatically resolved from the user's Pkarr record.
    ///
    /// # Example
    /// ```no_run
    /// use pubky::{Pubky, PublicKey, EventCursor};
    /// use futures_util::StreamExt;
    ///
    /// # async fn example() -> pubky::Result<()> {
    /// let pubky = Pubky::new()?;
    /// let user = PublicKey::try_from("o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo").unwrap();
    ///
    /// let mut stream = pubky.event_stream_for_user(&user, None)
    ///     .live()
    ///     .subscribe()
    ///     .await?;
    ///
    /// while let Some(result) = stream.next().await {
    ///     let event = result?;
    ///     println!("Event: {:?} at {}", event.event_type, event.resource);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn event_stream_for_user(
        &self,
        user: &PublicKey,
        cursor: Option<EventCursor>,
    ) -> EventStreamBuilder {
        EventStreamBuilder::for_user(self.client.clone(), user, cursor)
    }

    /// Create an event stream builder for a specific homeserver.
    ///
    /// Use this when you already know the homeserver pubkey. This avoids
    /// Pkarr resolution overhead. Obtain a homeserver pubkey via [`Self::get_homeserver_of`].
    ///
    /// # Example
    /// ```no_run
    /// use pubky::{Pubky, PublicKey};
    /// use futures_util::StreamExt;
    ///
    /// # async fn example() -> pubky::Result<()> {
    /// let pubky = Pubky::new()?;
    /// let user1 = PublicKey::try_from("o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo").unwrap();
    /// let user2 = PublicKey::try_from("pxnu33x7jtpx9ar1ytsi4yxbp6a5o36gwhffs8zoxmbuptici1jy").unwrap();
    ///
    /// // When subscribing to multiple users on the same homeserver,
    /// // specify the homeserver directly to avoid redundant Pkarr lookups
    /// let homeserver = pubky.get_homeserver_of(&user1).await?.unwrap();
    ///
    /// let mut stream = pubky.event_stream_for(&homeserver)
    ///     .add_users([(&user1, None), (&user2, None)])?
    ///     .subscribe()
    ///     .await?;
    ///
    /// while let Some(result) = stream.next().await {
    ///     let event = result?;
    ///     println!("Event: {:?} at {}", event.event_type, event.resource);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn event_stream_for(&self, homeserver: &PublicKey) -> EventStreamBuilder {
        EventStreamBuilder::for_homeserver(self.client.clone(), homeserver)
    }

    // ------ Persistance helpers ----------

    /// Restore a session from a `.sess` secret file.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Request`] if the secret file cannot be read.
    /// - Returns [`crate::errors::RequestError::Validation`] when the file contents are malformed.
    /// - Propagates transport errors from [`PubkySession::from_secret_file`] if the client
    ///   cannot be prepared.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn session_from_file<P: AsRef<Path>>(&self, path: P) -> Result<PubkySession> {
        PubkySession::from_secret_file(path.as_ref(), Some(self.client.clone())).await
    }

    /// Restore a session from an exported session secret token.
    ///
    /// Accepts both legacy cookie session tokens from
    /// [`CookieSessionView::export_secret`](crate::CookieSessionView::export_secret)
    /// and grant session tokens from
    /// [`GrantSessionView::export_local_secret`](crate::GrantSessionView::export_local_secret).
    /// Grant restore mints a fresh short-lived bearer; cookie restore revalidates
    /// the stored cookie secret.
    ///
    /// # Errors
    /// - Returns [`crate::errors::RequestError::Validation`] when the token is malformed.
    /// - Returns [`crate::errors::AuthError::RequestExpired`] when a stored cookie
    ///   session is no longer valid.
    /// - Returns [`crate::errors::Error::Authentication`] when a stored grant is
    ///   expired or its stored `PoP` key does not match the grant.
    /// - Propagates transport/server errors while validating or restoring the session.
    pub async fn restore_session(&self, token: &str) -> Result<PubkySession> {
        if GrantCredential::is_secret_token(token) {
            return PubkySession::import_grant_secret(token, Some(self.client.clone())).await;
        }

        PubkySession::import_secret(token, Some(self.client.clone())).await
    }

    /// Restore an origin-bound delegated browser grant session.
    ///
    /// This uses non-secret metadata plus a browser-held non-extractable key.
    /// It is not a portable restore mechanism.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Authentication`] when the metadata is
    ///   malformed, expired, or does not match the delegated signer.
    /// - Propagates transport/server errors while restoring the grant session.
    #[doc(hidden)]
    pub async fn restore_delegated_grant_session(
        &self,
        state: DelegatedGrantCredentialState,
        sign: crate::DelegatedSignFn,
    ) -> Result<PubkySession> {
        let credential = GrantCredential::import_delegated_state(state, &self.client, sign).await?;
        Ok(PubkySession::from_grant_credential(
            self.client.clone(),
            credential,
        ))
    }

    /// Recover a keypair from an encrypted `.pkarr` secret file and return a [`PubkySigner`].
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Request`] when reading the recovery file fails.
    /// - Returns [`crate::errors::Error::Request`] when decryption fails (invalid passphrase or corrupted file).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn signer_from_recovery_file<P: AsRef<Path>>(
        &self,
        path: P,
        passphrase: &str,
    ) -> Result<PubkySigner> {
        use pubky_common::recovery_file::decrypt_recovery_file;

        let bytes = std::fs::read(path.as_ref()).map_err(|e| RequestError::Validation {
            message: format!("failed to read recovery file: {e}"),
        })?;

        let kp =
            decrypt_recovery_file(&bytes, passphrase).map_err(|e| RequestError::Validation {
                message: format!("failed to decrypt recovery file: {e}"),
            })?;

        Ok(self.signer(kp))
    }

    /// Access the underlying transport (advanced use).
    #[inline]
    #[must_use]
    pub const fn client(&self) -> &PubkyHttpClient {
        &self.client
    }
}

/// Parse a `pubkyauth://` URL into the components needed to rebuild an auth flow.
///
/// Rejects `SeedExport` deep links since they cannot be resumed as auth flows.
fn parse_auth_deep_link(
    url: &str,
) -> Result<(
    Capabilities,
    url::Url,
    [u8; 32],
    AuthFlowKind,
    XCallbackParams,
)> {
    let deep_link = DeepLink::from_str(url)
        .map_err(|e| AuthError::Validation(format!("Failed to parse authorization URL: {e}")))?;

    match &deep_link {
        DeepLink::Signin(s) => Ok((
            s.params().capabilities.clone(),
            s.params().relay.clone(),
            s.params().secret,
            AuthFlowKind::signin(),
            s.x_callback().clone(),
        )),
        DeepLink::Signup(s) => Ok((
            s.params().capabilities.clone(),
            s.params().relay.clone(),
            s.params().secret,
            AuthFlowKind::signup(
                s.params().homeserver.clone(),
                s.params().signup_token.clone(),
            ),
            s.x_callback().clone(),
        )),
        DeepLink::SigninGrant(_) | DeepLink::SignupGrant(_) => Err(AuthError::Validation(
            "grant auth flows cannot be resumed from the authorization URL alone; the PoP client private key is required and is not encoded in the deep link."
                .into(),
        )
        .into()),
        DeepLink::DirectSignup(_) => Err(AuthError::Validation(
            "Direct signup URLs cannot be resumed as cookie auth flows.".into(),
        )
        .into()),
        DeepLink::SeedExport(_) => {
            Err(AuthError::Validation("Only signin and signup URLs can be resumed.".into()).into())
        }
    }
}
