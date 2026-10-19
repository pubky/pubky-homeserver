use std::fmt;

use futures_util::future::{AbortHandle, Abortable};

use url::Url;

#[allow(deprecated, reason = "Internal use of deprecated public API")]
use super::{
    AuthRelayMessage,
    http_relay_inbox_channel::{EncryptedHttpRelayInboxChannel, HttpRelayInboxChannel},
    http_relay_link_channel::{EncryptedHttpRelayLinkChannel, HttpRelayLinkChannel},
};
use crate::actors::auth::deep_links::GrantRelayChannel;
#[allow(deprecated, reason = "Internal use of deprecated public API")]
use crate::{
    PubkyHttpClient,
    actors::DEFAULT_HTTP_RELAY_INBOX,
    cross_log,
    errors::{AuthError, Result},
};

#[cfg(target_arch = "wasm32")]
use futures_util::FutureExt; // for `.map(|_| ())` in WASM spawn

/// Dispatch between encrypted legacy channels and raw HPKE channels.
///
/// The relay path chooses link versus inbox; the channel key chooses whether
/// the relay body uses legacy shared-secret encryption.
#[derive(Clone)]
#[allow(deprecated, reason = "Internal use of deprecated public API")]
enum AuthRelayChannel {
    EncryptedInbox(EncryptedHttpRelayInboxChannel),
    EncryptedLink(EncryptedHttpRelayLinkChannel),
    Inbox(HttpRelayInboxChannel),
    Link(HttpRelayLinkChannel),
}

#[allow(deprecated, reason = "Internal use of deprecated public API")]
impl AuthRelayChannel {
    /// Poll the underlying channel for a message.
    async fn poll(
        &self,
        client: &PubkyHttpClient,
        timeout: Option<std::time::Duration>,
    ) -> Result<Option<Vec<u8>>> {
        match self {
            Self::EncryptedInbox(ch) => Ok(ch.poll(client, timeout).await?),
            Self::EncryptedLink(ch) => Ok(ch.poll(client, timeout).await?),
            Self::Inbox(ch) => ch.poll(client, timeout).await,
            Self::Link(ch) => ch.poll(client, timeout).await,
        }
    }

    /// Acknowledge receipt. Only meaningful for inbox channels (no-op for link).
    /// Errors are propagated for inbox so callers know if the ACK failed.
    async fn ack(&self, client: &PubkyHttpClient) -> Result<()> {
        match self {
            Self::EncryptedInbox(ch) => {
                ch.ack(client).await?;
            }
            Self::Inbox(ch) => {
                ch.ack(client).await?;
            }
            Self::EncryptedLink(_) | Self::Link(_) => {}
        }
        Ok(())
    }
}

#[allow(deprecated, reason = "Internal use of deprecated public API")]
impl fmt::Display for AuthRelayChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptedInbox(ch) => write!(f, "{ch}"),
            Self::EncryptedLink(ch) => write!(f, "{ch}"),
            Self::Inbox(ch) => write!(f, "{ch}"),
            Self::Link(ch) => write!(f, "{ch}"),
        }
    }
}

#[allow(deprecated, reason = "Internal use of deprecated public API")]
impl fmt::Debug for AuthRelayChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptedInbox(ch) => f.debug_tuple("EncryptedInbox").field(ch).finish(),
            Self::EncryptedLink(ch) => f.debug_tuple("EncryptedLink").field(ch).finish(),
            Self::Inbox(ch) => f.debug_tuple("Inbox").field(ch).finish(),
            Self::Link(ch) => f.debug_tuple("Link").field(ch).finish(),
        }
    }
}

/// Returns `true` if the URL path ends with `/link` or `/link/`.
fn is_link_url(url: &Url) -> bool {
    let path = url.path().trim_end_matches('/');
    path.ends_with("/link")
}

/// **auth subscription** (long polling for a single auth approval) you *hold on to*.
///
/// Use it like this:
/// 1. Construct with the builder
///    [`AuthRelayListener::builder`] to override relay/client.
/// 2. Receive the decrypted relay message with [`await_message`](Self::await_message)
///    or [`try_message`](Self::try_message). HPKE messages remain encrypted;
///    the grant flow opens them after receipt.
///
/// Background polling **starts immediately** at construction. Dropping this value cancels
/// the background task; the relay channel itself expires server-side after its TTL.
#[derive(Debug)]
pub struct AuthRelayListener {
    rx: flume::Receiver<Result<AuthRelayMessage>>,
    abort: AbortHandle,
}

impl AuthRelayListener {
    /// Create a builder for [`AuthRelayListener`].
    pub fn builder(secret: [u8; 32]) -> AuthRelayListenerBuilder {
        Self::builder_for_channel(GrantRelayChannel::SharedSecret(secret))
    }

    pub(crate) fn builder_for_channel(channel: GrantRelayChannel) -> AuthRelayListenerBuilder {
        AuthRelayListenerBuilder::new(channel)
    }

    /// Block until the signer approves and the relay delivers the decrypted
    /// auth message.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Authentication`] if the relay channel expires before approval.
    /// - Propagates HTTP/transport failures while polling the relay.
    pub(crate) async fn await_message(self) -> Result<AuthRelayMessage> {
        self.recv_message().await
    }

    async fn recv_message(&self) -> Result<AuthRelayMessage> {
        self.rx
            .recv_async()
            .await
            .map_err(|_err| AuthError::RequestExpired)?
    }

    /// Non-blocking check for a ready relay message.
    #[must_use]
    pub(crate) fn try_message(&self) -> Option<Result<AuthRelayMessage>> {
        self.rx.try_recv().ok()
    }

    // -- internals --

    /// Long-poll until an approval arrives or the channel expires. Runs in
    /// the background task.
    async fn poll_for_approval_loop(
        client: PubkyHttpClient,
        channel: AuthRelayChannel,
        tx: flume::Sender<Result<AuthRelayMessage>>,
    ) {
        cross_log!(
            info,
            "Starting auth flow polling for relay channel {}",
            channel
        );
        let result = Self::poll_for_message(&client, &channel).await;

        if result.is_ok() {
            cross_log!(
                info,
                "Auth flow successfully received approval for relay channel {}",
                channel
            );
        }

        let _ = tx.send(result);
    }

    async fn poll_for_message(
        client: &PubkyHttpClient,
        channel: &AuthRelayChannel,
    ) -> Result<AuthRelayMessage> {
        let response = channel
            .poll(client, None)
            .await?
            .ok_or(AuthError::RequestExpired)?;

        // ACK: confirms receipt for inbox channels, no-op for link.
        // Best-effort: a failed ACK should not invalidate a delivered payload.
        if let Err(e) = channel.ack(client).await {
            cross_log!(warn, "Inbox ACK failed (non-fatal): {e}");
        }

        Ok(AuthRelayMessage::new(response))
    }
}

impl Drop for AuthRelayListener {
    fn drop(&mut self) {
        // Stop background polling immediately.
        self.abort.abort();
    }
}

/// Builder for [`AuthRelayListener`].
///
/// Use to override the HTTP relay and/or the `PubkyHttpClient`.
#[derive(Clone)]
pub struct AuthRelayListenerBuilder {
    relay_base_url: Url,
    relay_channel: GrantRelayChannel,
    client: Option<PubkyHttpClient>,
}

impl fmt::Debug for AuthRelayListenerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthRelayListenerBuilder")
            .field("relay_base_url", &self.relay_base_url)
            .field("relay_channel", &self.relay_channel)
            .field("client", &self.client)
            .finish()
    }
}

#[allow(deprecated, reason = "Internal use of deprecated public API")]
impl AuthRelayListenerBuilder {
    pub(crate) fn new(relay_channel: GrantRelayChannel) -> Self {
        Self {
            relay_base_url: Url::parse(DEFAULT_HTTP_RELAY_INBOX).expect("Always valid"),
            relay_channel,
            client: None,
        }
    }

    /// Set a custom relay base URL. Trailing slash optional.
    pub fn relay_base_url(mut self, url: Url) -> Self {
        self.relay_base_url = url;
        self
    }

    /// Provide a custom `PubkyHttpClient` (e.g., with custom TLS, roots, or test wiring).
    pub fn client(mut self, client: PubkyHttpClient) -> Self {
        self.client = Some(client);
        self
    }

    // Spawn background polling (single-shot delivery)
    fn spawn_background_polling(
        channel: AuthRelayChannel,
        client: &PubkyHttpClient,
    ) -> AuthRelayListener {
        let (tx, rx) = flume::bounded(1);
        let (abort_handle, abort_reg) = AbortHandle::new_pair();
        let bg_client = client.clone();

        let fut = async move {
            cross_log!(info, "Spawning auth flow polling task");
            AuthRelayListener::poll_for_approval_loop(bg_client, channel.clone(), tx).await;
        };

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(Abortable::new(fut, abort_reg));

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(Abortable::new(fut, abort_reg).map(|_| ()));

        AuthRelayListener {
            rx,
            abort: abort_handle,
        }
    }

    /// Finalize: derive channel, spawn the background poller,
    /// and return the subscription handle.
    ///
    /// The channel type is auto-detected from the relay URL path:
    /// - `/link` or `/link/` → link channel (synchronous pairing)
    /// - Otherwise → inbox channel (store-and-forward, default)
    pub fn start(self) -> Result<AuthRelayListener> {
        let client = match self.client {
            Some(c) => c,
            None => PubkyHttpClient::new()?,
        };

        let channel_id = self.relay_channel.http_channel_id();
        let link_channel = is_link_url(&self.relay_base_url);
        let channel = match (self.relay_channel, link_channel) {
            (GrantRelayChannel::SharedSecret(secret), true) => AuthRelayChannel::EncryptedLink(
                EncryptedHttpRelayLinkChannel::new(self.relay_base_url, secret)?,
            ),
            (GrantRelayChannel::SharedSecret(secret), false) => AuthRelayChannel::EncryptedInbox(
                EncryptedHttpRelayInboxChannel::new(self.relay_base_url, secret)?,
            ),
            (GrantRelayChannel::Hpke { .. }, true) => {
                AuthRelayChannel::Link(HttpRelayLinkChannel::new(self.relay_base_url, channel_id)?)
            }
            (GrantRelayChannel::Hpke { .. }, false) => AuthRelayChannel::Inbox(
                HttpRelayInboxChannel::new(self.relay_base_url, channel_id)?,
            ),
        };

        Ok(Self::spawn_background_polling(channel, &client))
    }
}

#[cfg(test)]
mod tests {
    use pubky_common::capabilities::Capabilities;

    use super::*;
    use crate::AuthToken;
    use crate::Keypair;

    #[test]
    fn is_link_url_with_link_path() {
        let url = Url::parse("https://relay.example.com/link").unwrap();
        assert!(is_link_url(&url));
    }

    #[test]
    fn is_link_url_with_link_trailing_slash() {
        let url = Url::parse("https://relay.example.com/link/").unwrap();
        assert!(is_link_url(&url));
    }

    #[test]
    fn is_link_url_with_inbox_path() {
        let url = Url::parse("https://relay.example.com/inbox").unwrap();
        assert!(!is_link_url(&url));
    }

    #[test]
    fn is_link_url_with_nested_link_path() {
        let url = Url::parse("https://relay.example.com/api/v1/link").unwrap();
        assert!(is_link_url(&url));
    }

    #[test]
    fn is_link_url_with_root_path() {
        let url = Url::parse("https://relay.example.com/").unwrap();
        assert!(!is_link_url(&url));
    }

    #[test]
    fn is_link_url_with_link_prefix_not_suffix() {
        // "linkage" ends with "linkage", not "/link"
        let url = Url::parse("https://relay.example.com/linkage").unwrap();
        assert!(!is_link_url(&url));
    }

    #[tokio::test]
    async fn subscribe_to_auth_token() {
        // Start a local relay so the test doesn't depend on production.
        let relay = http_relay::HttpRelay::builder()
            .http_port(0)
            .run()
            .await
            .unwrap();
        let inbox_base = relay.local_url().join("inbox").unwrap();

        let encrypted_channel =
            EncryptedHttpRelayInboxChannel::random_secret(inbox_base.clone()).unwrap();

        let keypair = Keypair::random();
        let capabilities = Capabilities::default();
        let token = AuthToken::sign(&keypair, capabilities);
        let token_bytes = token.serialize();

        let main_client = PubkyHttpClient::new().unwrap();

        let client = main_client.clone();
        let channel = encrypted_channel.clone();
        let producer_handle = tokio::spawn(async move {
            channel.produce(&client, &token_bytes).await.unwrap();
        });

        let listener = AuthRelayListener::builder(encrypted_channel.secret().to_owned())
            .relay_base_url(inbox_base)
            .client(main_client.clone())
            .start()
            .unwrap();
        let poll_handle = tokio::spawn(async move {
            let response = listener.await_message().await.unwrap();
            let approval =
                crate::actors::auth::cookie::approval::CookieApproval::decode(&response).unwrap();
            assert_eq!(approval.0, token);
        });

        let (producer_result, poll_result) = tokio::join!(producer_handle, poll_handle);
        producer_result.unwrap();
        poll_result.unwrap();
    }
}
