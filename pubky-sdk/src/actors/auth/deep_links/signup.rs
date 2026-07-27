use pubky_common::{capabilities::Capabilities, crypto::PublicKey};
use url::Url;

use super::{
    DeepLinkParseError,
    query_params::{
        append_signup_params, optional_query, parse_capabilities, parse_homeserver, parse_relay,
        parse_secret,
    },
    typed_deep_link::{DeepLinkIntent, DeepLinkParams, TypedDeepLink},
};

/// Intent marker for legacy signup deep links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignupIntent;

impl DeepLinkIntent for SignupIntent {
    const NAME: &'static str = "signup";
}

/// Typed parameters for signup deep links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignupParams {
    /// Capabilities requested by the app.
    pub capabilities: Capabilities,
    /// Base HTTP relay URL.
    pub relay: Url,
    /// Secret used to derive the encrypted relay channel.
    pub secret: [u8; 32],
    /// Homeserver public key.
    pub homeserver: PublicKey,
    /// Optional signup token.
    pub signup_token: Option<String>,
}

impl DeepLinkParams for SignupParams {
    fn parse(url: &Url) -> Result<Self, DeepLinkParseError> {
        Ok(Self {
            capabilities: parse_capabilities(url)?,
            relay: parse_relay(url)?,
            secret: parse_secret(url)?,
            homeserver: parse_homeserver(url)?,
            signup_token: optional_query(url, "st"),
        })
    }

    fn append_query_pairs(&self, url: &mut Url) {
        append_signup_params(
            url,
            &self.capabilities,
            &self.relay,
            &self.secret,
            &self.homeserver,
            self.signup_token.as_deref(),
        );
    }
}

/// A deep link for signing up to a Pubky homeserver via the legacy cookie flow.
pub type SignupDeepLink = TypedDeepLink<SignupIntent, SignupParams>;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::actors::auth::deep_links::DeepLinkScheme;

    const HOMESERVER: &str = "5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo";

    #[test]
    fn parses_signup_deep_link_without_signup_token() {
        let deep_link: SignupDeepLink = format!(
            "pubkyauth://signup?caps=/pub/pubky.app/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&hs={HOMESERVER}"
        )
        .parse()
        .unwrap();

        assert_eq!(deep_link.scheme(), DeepLinkScheme::PubkyAuth);
        assert_eq!(deep_link.intent(), "signup");
        assert_eq!(deep_link.params().homeserver.z32(), HOMESERVER);
        assert_eq!(deep_link.params().signup_token, None);
    }

    #[test]
    fn parses_signup_deep_link_with_signup_token() {
        let deep_link: SignupDeepLink = format!(
            "pubkyauth://signup?caps=/pub/pubky.app/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&hs={HOMESERVER}&st=1234567890"
        )
        .parse()
        .unwrap();

        assert_eq!(deep_link.params().signup_token, Some("1234567890".into()));
    }

    #[test]
    fn parses_signup_deep_link_with_extra_query_params() {
        let deep_link: SignupDeepLink = format!(
            "pubkyauth://signup?caps=/pub/pubky.app/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&hs={HOMESERVER}&cid=franky.pubky.app&cpk=not-a-public-key"
        )
        .parse()
        .unwrap();

        assert_eq!(deep_link.intent(), "signup");
    }

    #[test]
    fn creates_signup_deep_link_from_params() {
        let capabilities = Capabilities::builder().read_write("/").unwrap().finish();
        let relay = Url::parse("https://httprelay.pubky.app/inbox/").unwrap();
        let homeserver = PublicKey::from_str(HOMESERVER).unwrap();
        let deep_link = SignupDeepLink::new(
            DeepLinkScheme::PubkyAuth,
            SignupParams {
                capabilities,
                relay,
                secret: [123; 32],
                homeserver,
                signup_token: Some("1234567890".into()),
            },
        );
        let parsed_again = SignupDeepLink::parse_url(&deep_link.to_url()).unwrap();

        assert_eq!(parsed_again, deep_link);
    }

    #[test]
    fn rejects_missing_capabilities() {
        let error = format!(
            "pubkyauth://signup?relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&hs={HOMESERVER}"
        )
        .parse::<SignupDeepLink>()
        .unwrap_err();

        assert!(matches!(
            error,
            DeepLinkParseError::MissingQueryParameter("caps")
        ));
    }

    #[test]
    fn rejects_missing_relay() {
        let error = format!(
            "pubkyauth://signup?caps=/:rw&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&hs={HOMESERVER}"
        )
        .parse::<SignupDeepLink>()
        .unwrap_err();

        assert!(matches!(
            error,
            DeepLinkParseError::MissingQueryParameter("relay")
        ));
    }

    #[test]
    fn rejects_missing_secret() {
        let error = format!(
            "pubkyauth://signup?caps=/:rw&relay=https://httprelay.pubky.app/inbox/&hs={HOMESERVER}"
        )
        .parse::<SignupDeepLink>()
        .unwrap_err();

        assert!(matches!(
            error,
            DeepLinkParseError::MissingQueryParameter("secret")
        ));
    }

    #[test]
    fn rejects_missing_homeserver() {
        let error = "pubkyauth://signup?caps=/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8"
            .parse::<SignupDeepLink>()
            .unwrap_err();

        assert!(matches!(
            error,
            DeepLinkParseError::MissingQueryParameter("hs")
        ));
    }
}
