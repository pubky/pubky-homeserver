pub mod auth_relay_listener;
pub mod http_relay_inbox_channel;
pub mod http_relay_link_channel;

/// Decrypted auth message delivered through the relay channel.
#[derive(Clone)]
pub(crate) struct AuthRelayMessage(zeroize::Zeroizing<Vec<u8>>);

impl AuthRelayMessage {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for AuthRelayMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRelayMessage")
            .field("payload", &"<redacted>")
            .finish()
    }
}
