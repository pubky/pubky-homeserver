use pubky_common::capabilities::Capabilities;
use url::Url;

use super::{
    DeepLinkParseError,
    query_params::{append_signin_params, parse_capabilities, parse_relay, parse_secret},
    typed_deep_link::{DeepLinkIntent, DeepLinkParams, TypedDeepLink},
};

/// Intent marker for legacy signin deep links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigninIntent;

impl DeepLinkIntent for SigninIntent {
    const NAME: &'static str = "signin";
}

/// Typed parameters for legacy signin deep links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigninParams {
    /// Capabilities requested by the app.
    pub capabilities: Capabilities,
    /// Base HTTP relay URL.
    pub relay: Url,
    /// Secret used to derive the encrypted relay channel.
    pub secret: [u8; 32],
}

impl DeepLinkParams for SigninParams {
    fn parse(url: &Url) -> Result<Self, DeepLinkParseError> {
        Ok(Self {
            capabilities: parse_capabilities(url)?,
            relay: parse_relay(url)?,
            secret: parse_secret(url)?,
        })
    }

    fn append_query_pairs(&self, url: &mut Url) {
        append_signin_params(url, &self.capabilities, &self.relay, &self.secret);
    }
}

/// A deep link for signing into a Pubky homeserver via the legacy cookie flow.
pub type SigninDeepLink = TypedDeepLink<SigninIntent, SigninParams>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actors::auth::deep_links::DeepLinkScheme;

    #[test]
    fn parses_signin_deep_link() {
        let deep_link: SigninDeepLink = "pubkyauth://signin?caps=/pub/pubky.app/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8"
            .parse()
            .unwrap();

        assert_eq!(deep_link.scheme(), DeepLinkScheme::PubkyAuth);
        assert_eq!(deep_link.intent(), "signin");
        assert_eq!(
            deep_link.params().capabilities.to_string(),
            "/pub/pubky.app/:rw"
        );
        assert_eq!(
            deep_link.params().relay.as_str(),
            "https://httprelay.pubky.app/inbox/"
        );
    }

    #[test]
    fn parses_signin_deep_link_with_extra_query_params() {
        let deep_link: SigninDeepLink = "pubkyauth://signin?caps=/pub/pubky.app/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&cid=franky.pubky.app&cpk=not-a-public-key"
            .parse()
            .unwrap();

        assert_eq!(deep_link.intent(), "signin");
    }

    #[test]
    fn creates_signin_deep_link_from_params() {
        let capabilities = Capabilities::builder()
            .read_write("/")
            .read("/test")
            .finish();
        let relay = Url::parse("https://httprelay.pubky.app/inbox/").unwrap();
        let secret = [123; 32];
        let deep_link = SigninDeepLink::new(
            DeepLinkScheme::PubkyAuth,
            SigninParams {
                capabilities,
                relay,
                secret,
            },
        );
        let parsed_again = SigninDeepLink::parse_url(&deep_link.to_url()).unwrap();

        assert_eq!(parsed_again, deep_link);
    }

    #[test]
    fn rejects_missing_secret() {
        let error = "pubkyauth://signin?caps=/:rw&relay=https://httprelay.pubky.app/inbox/"
            .parse::<SigninDeepLink>()
            .unwrap_err();

        assert!(matches!(
            error,
            DeepLinkParseError::MissingQueryParameter("secret")
        ));
    }

    #[test]
    fn rejects_invalid_capability_with_context() {
        let error = "pubkyauth://signin?caps=/:rw,invalid:w&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8"
            .parse::<SigninDeepLink>()
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "Invalid query parameter caps: invalid capability at position 2 (`invalid:w`): capability scope must start with `/`"
        );
    }

    #[test]
    fn rejects_wrong_intent() {
        let error = "pubkyauth://signup?caps=/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8"
            .parse::<SigninDeepLink>()
            .unwrap_err();

        assert!(matches!(error, DeepLinkParseError::InvalidIntent("signin")));
    }
}
