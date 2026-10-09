use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::crypto::{Hasher, hash};

const HPKE_RELAY_CHANNEL_DOMAIN: &[u8] = b"pubky-grant-relay-channel-v1\0";

/// Relay channel information carried by a grant authorization link.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GrantRelayChannel {
    /// Legacy channel identified by a shared secret and encrypted relay body.
    SharedSecret([u8; 32]),
    /// HPKE channel identified by the recipient's ephemeral public key.
    Hpke {
        /// Ephemeral HPKE public key; also identifies the relay channel.
        ephemeral_public_key: [u8; 32],
    },
}

impl GrantRelayChannel {
    pub(crate) fn http_channel_id(self) -> String {
        match self {
            Self::SharedSecret(secret) => URL_SAFE_NO_PAD.encode(hash(&secret).as_bytes()),
            Self::Hpke {
                ephemeral_public_key,
            } => {
                // Hide `epk` from the relay so it cannot encrypt an approval.
                let mut hasher = Hasher::new();
                hasher.update(HPKE_RELAY_CHANNEL_DOMAIN);
                hasher.update(&ephemeral_public_key);
                URL_SAFE_NO_PAD.encode(hasher.finalize().as_bytes())
            }
        }
    }
}

impl fmt::Debug for GrantRelayChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharedSecret(_) => f.write_str("SharedSecret(<redacted>)"),
            Self::Hpke { .. } => f.write_str("Hpke(<public key>)"),
        }
    }
}
