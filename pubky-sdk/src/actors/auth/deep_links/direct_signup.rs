use pubky_common::crypto::PublicKey;
use url::Url;

use super::{
    DeepLinkParseError,
    query_params::{append_direct_signup_params, optional_query, parse_homeserver},
    typed_deep_link::{DeepLinkIntent, DeepLinkParams, TypedDeepLink},
};

/// Intent marker for direct signup deep links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectSignupIntent;

impl DeepLinkIntent for DirectSignupIntent {
    const NAME: &'static str = "direct_signup";
}

/// Typed parameters for direct signup deep links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectSignupParams {
    /// Homeserver public key.
    pub homeserver: PublicKey,
    /// Optional signup token.
    pub signup_token: Option<String>,
}

impl DeepLinkParams for DirectSignupParams {
    fn parse(url: &Url) -> Result<Self, DeepLinkParseError> {
        Ok(Self {
            homeserver: parse_homeserver(url)?,
            signup_token: optional_query(url, "st"),
        })
    }

    fn append_query_pairs(&self, url: &mut Url) {
        append_direct_signup_params(url, &self.homeserver, self.signup_token.as_deref());
    }
}

/// A deep link for registering an account directly on a Pubky homeserver.
pub type DirectSignupDeepLink = TypedDeepLink<DirectSignupIntent, DirectSignupParams>;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::actors::auth::deep_links::DeepLinkScheme;

    const HOMESERVER: &str = "5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo";

    #[test]
    fn parses_direct_signup_deep_link() {
        let deep_link: DirectSignupDeepLink = format!("pubkyauth://direct_signup?hs={HOMESERVER}")
            .parse()
            .unwrap();

        assert_eq!(deep_link.scheme(), DeepLinkScheme::PubkyAuth);
        assert_eq!(deep_link.intent(), "direct_signup");
        assert_eq!(deep_link.params().homeserver.z32(), HOMESERVER);
        assert_eq!(deep_link.params().signup_token, None);
    }

    #[test]
    fn parses_direct_signup_deep_link_with_token() {
        let deep_link: DirectSignupDeepLink =
            format!("pubkyauth://direct_signup?hs={HOMESERVER}&st=1234567890")
                .parse()
                .unwrap();

        assert_eq!(deep_link.params().signup_token, Some("1234567890".into()));
    }

    #[test]
    fn direct_signup_deep_link_round_trips() {
        let deep_link = DirectSignupDeepLink::new(
            DeepLinkScheme::PubkyAuth,
            DirectSignupParams {
                homeserver: PublicKey::from_str(HOMESERVER).unwrap(),
                signup_token: None,
            },
        );

        assert_eq!(
            deep_link.to_string(),
            format!("pubkyauth://direct_signup?hs={HOMESERVER}")
        );
        assert_eq!(
            DirectSignupDeepLink::parse_url(&deep_link.to_url()).unwrap(),
            deep_link
        );
    }

    #[test]
    fn rejects_missing_homeserver() {
        let error = "pubkyauth://direct_signup"
            .parse::<DirectSignupDeepLink>()
            .unwrap_err();

        assert!(matches!(
            error,
            DeepLinkParseError::MissingQueryParameter("hs")
        ));
    }
}
