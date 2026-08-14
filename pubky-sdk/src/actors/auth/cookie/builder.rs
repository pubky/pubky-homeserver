use url::Url;

use pubky_common::crypto::random_bytes;

use crate::actors::DEFAULT_HTTP_RELAY_INBOX;
#[allow(deprecated, reason = "Internal use of deprecated public API")]
use crate::actors::auth::cookie::flow::PubkyCookieAuthFlow;
use crate::actors::auth::deep_links::{
    DeepLink, DeepLinkScheme, SigninDeepLink, SigninParams, SignupDeepLink, SignupParams,
    XCallbackParams,
};
use crate::actors::auth::kind::AuthFlowKind;
use crate::actors::auth::relay::auth_relay_listener::AuthRelayListener;
use crate::errors::Result;
use crate::{Capabilities, PubkyHttpClient};

/// Builder for the **legacy (cookie)** [`PubkyCookieAuthFlow`].
///
/// The signer returns a [`pubky_common::auth::AuthToken`] which the SDK
/// exchanges for a session cookie. For long-lived, mirror-friendly
/// sessions, prefer [`crate::PubkyGrantAuthFlow`].
#[derive(Debug, Clone)]
pub struct CookieAuthFlowBuilder {
    caps: Capabilities,
    base_relay: Url,
    client: Option<PubkyHttpClient>,
    auth_kind: AuthFlowKind,
    client_secret: [u8; 32],
    x_callback: XCallbackParams,
}

impl CookieAuthFlowBuilder {
    pub(crate) fn new(caps: Capabilities, auth_kind: AuthFlowKind) -> Self {
        Self {
            caps,
            base_relay: Url::parse(DEFAULT_HTTP_RELAY_INBOX)
                .expect("Should be able to parse the default HTTP relay"),
            client: None,
            auth_kind,
            client_secret: random_bytes::<32>(),
            x_callback: XCallbackParams::default(),
        }
    }

    /// Set a custom relay base URL. Trailing slash optional.
    #[must_use]
    pub fn relay(mut self, url: Url) -> Self {
        self.base_relay = url;
        self
    }

    /// Provide a custom `PubkyHttpClient` (e.g., with custom TLS, roots, or test wiring).
    #[must_use]
    pub fn client(mut self, client: PubkyHttpClient) -> Self {
        self.client = Some(client);
        self
    }

    /// Override the random `client_secret`. By default, a fresh 32-byte secret is generated.
    #[must_use]
    pub fn client_secret(mut self, client_secret: [u8; 32]) -> Self {
        self.client_secret = client_secret;
        self
    }

    /// Attach optional x-callback-url metadata to the authorization deep link.
    #[must_use]
    pub fn x_callback(mut self, x_callback: XCallbackParams) -> Self {
        self.x_callback = x_callback;
        self
    }

    /// Finalize: derive channel, compute the `pubkyauth://` deep link, spawn
    /// the background poller, and return the flow handle.
    ///
    /// # Errors
    /// - Propagates failures from constructing the default [`PubkyHttpClient`]
    ///   or starting the [`AuthRelayListener`].
    #[allow(deprecated, reason = "Internal use of deprecated public API")]
    pub fn start(self) -> Result<PubkyCookieAuthFlow> {
        let Self {
            caps,
            base_relay,
            client,
            auth_kind,
            client_secret,
            x_callback,
        } = self;

        let client = match client {
            Some(c) => c,
            None => PubkyHttpClient::new()?,
        };

        let auth_url = match auth_kind {
            AuthFlowKind::SignIn => DeepLink::Signin(SigninDeepLink::new(
                DeepLinkScheme::PubkyAuth,
                SigninParams {
                    capabilities: caps,
                    relay: base_relay.clone(),
                    secret: client_secret,
                },
            )),
            AuthFlowKind::SignUp {
                homeserver_public_key,
                signup_token,
            } => DeepLink::Signup(SignupDeepLink::new(
                DeepLinkScheme::PubkyAuth,
                SignupParams {
                    capabilities: caps,
                    relay: base_relay.clone(),
                    secret: client_secret,
                    homeserver: *homeserver_public_key,
                    signup_token,
                },
            )),
        }
        .with_x_callback(x_callback);

        let relay_listener = AuthRelayListener::builder(client_secret)
            .relay_base_url(base_relay)
            .client(client.clone())
            .start()?;

        Ok(PubkyCookieAuthFlow::new(relay_listener, client, auth_url))
    }
}
