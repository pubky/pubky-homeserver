use pubky_common::{
    auth::{
        grant::{caps_within, is_exact_callback, parent_grant_ceiling},
        jws::ClientId,
    },
    capabilities::Capabilities,
    crypto::PublicKey,
};
use url::Url;

use super::{
    DeepLinkParseError, GrantRelayChannel,
    query_params::{
        append_grant_params, append_grant_relay_channel, append_relay_params, invalid_query_input,
        parse_capabilities, parse_client_id, parse_client_pk, parse_optional_channel_key,
        parse_relay, reject_repeated_query,
    },
    typed_deep_link::{DeepLinkIntent, DeepLinkParams, TypedDeepLink},
};

/// Intent marker for parent-grant deep links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentGrantIntent;

impl DeepLinkIntent for ParentGrantIntent {
    const NAME: &'static str = "parent_grant";
}

/// Typed parameters for a parent-grant deep link.
///
/// A separate intent makes signers that predate delegation reject the request
/// instead of signing an ordinary grant for the same capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParentGrantParams {
    /// Capabilities requested by the holder, within `/pub/:rwe` and `/priv/:rwe`.
    pub capabilities: Capabilities,
    /// Base HTTP relay URL.
    pub relay: Url,
    /// Temporary HPKE public key the approval is encrypted to.
    pub ephemeral_public_key: [u8; 32],
    /// The holder's exact HTTPS callback URL.
    pub client_id: ClientId,
    /// Public key bound by the parent's `cnf` claim. It signs child grants.
    pub client_pk: PublicKey,
}

impl ParentGrantParams {
    /// Relay channel derived from the recipient's HPKE public key.
    #[must_use]
    pub const fn relay_channel(&self) -> GrantRelayChannel {
        GrantRelayChannel::Hpke {
            ephemeral_public_key: self.ephemeral_public_key,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), DeepLinkParseError> {
        if !caps_within(&parent_grant_ceiling(), self.capabilities.as_slice()) {
            return Err(invalid_query_input(
                "caps",
                "parent grants are limited to /pub/:rwe and /priv/:rwe",
            ));
        }
        if !is_exact_callback(&self.client_id) {
            return Err(invalid_query_input(
                "cid",
                "parent grants require an exact HTTPS callback URL",
            ));
        }
        Ok(())
    }
}

impl DeepLinkParams for ParentGrantParams {
    fn parse(url: &Url) -> Result<Self, DeepLinkParseError> {
        reject_repeated_query(url, &["caps", "relay", "cid", "cpk", "epk"])?;
        let params = Self {
            capabilities: parse_capabilities(url)?,
            relay: parse_relay(url)?,
            ephemeral_public_key: parse_optional_channel_key(url, "epk")?
                .ok_or(DeepLinkParseError::MissingQueryParameter("epk"))?,
            client_id: parse_client_id(url)?,
            client_pk: parse_client_pk(url)?,
        };
        params.validate()?;
        Ok(params)
    }

    fn append_query_pairs(&self, url: &mut Url) {
        append_relay_params(url, &self.capabilities, &self.relay);
        append_grant_params(url, &self.client_id, &self.client_pk);
        append_grant_relay_channel(url, self.relay_channel());
    }
}

/// A deep link asking a signer to approve a parent grant.
pub type ParentGrantDeepLink = TypedDeepLink<ParentGrantIntent, ParentGrantParams>;

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use pubky_common::crypto::Keypair;

    use super::*;
    use crate::actors::auth::deep_links::{DeepLink, DeepLinkScheme};

    const CALLBACK: &str = "https://accounts.example/auth/callback";

    fn url(caps: &str, client_id: &str) -> String {
        format!(
            "pubkyauth://parent_grant?caps={caps}&relay=http://localhost/inbox&cid={client_id}&cpk={}&epk={}",
            Keypair::random().public_key().z32(),
            URL_SAFE_NO_PAD.encode([7; 32]),
        )
    }

    #[test]
    fn round_trips_through_the_generic_parser() {
        let link: ParentGrantDeepLink = url("/pub/:rwe,/priv/:rwe", CALLBACK).parse().unwrap();
        assert_eq!(link.scheme(), DeepLinkScheme::PubkyAuth);
        assert_eq!(link.intent(), "parent_grant");
        let parsed: DeepLink = link.to_string().parse().unwrap();
        assert_eq!(parsed, DeepLink::ParentGrant(link));
    }

    #[test]
    fn rejects_requests_a_parent_can_never_hold() {
        for (caps, client_id) in [
            ("/:rw", CALLBACK),
            ("/pub/:rwe,/:r", CALLBACK),
            ("/pub/:rwe", "accounts.example"),
            ("/pub/:rwe", "http://accounts.example/auth/callback"),
            ("/pub/:rwe", "https://ACCOUNTS.example/auth/callback"),
            // A repeated parameter.
            (
                "/pub/:rwe",
                "https://accounts.example/auth/callback&cid=https://evil.example/cb",
            ),
        ] {
            assert!(
                url(caps, client_id).parse::<ParentGrantDeepLink>().is_err(),
                "{caps} {client_id}"
            );
        }
    }

    #[test]
    fn requires_an_encryption_recipient() {
        let link = format!(
            "pubkyauth://parent_grant?caps=/pub/:rwe&relay=http://localhost/inbox&cid={CALLBACK}&cpk={}",
            Keypair::random().public_key().z32(),
        );
        assert!(matches!(
            link.parse::<ParentGrantDeepLink>().unwrap_err(),
            DeepLinkParseError::MissingQueryParameter("epk")
        ));
    }
}
