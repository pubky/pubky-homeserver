use std::{fmt::Display, str::FromStr};

use url::Url;

use crate::actors::auth::deep_links::{
    DEEP_LINK_SCHEMES, direct_signup::DirectSignupDeepLink, error::DeepLinkParseError,
    seed_export::SeedExportDeepLink, signin::SigninDeepLink, signin_grant::SigninGrantDeepLink,
    signup::SignupDeepLink, signup_grant::SignupGrantDeepLink, x_callback::XCallbackParams,
};

/// A parsed Pubky deep link.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "Doesn't really matter in this case as this enum is never stored in a large amount of data"
)]
pub enum DeepLink {
    /// A signin deep link (legacy cookie flow).
    Signin(SigninDeepLink),
    /// A signup deep link (legacy cookie flow).
    Signup(SignupDeepLink),
    /// A direct signup deep link.
    DirectSignup(DirectSignupDeepLink),
    /// A signin deep link for the grant flow.
    SigninGrant(SigninGrantDeepLink),
    /// A signup deep link for the grant flow.
    SignupGrant(SignupGrantDeepLink),
    /// A seed export deep link.
    SeedExport(SeedExportDeepLink),
}

impl DeepLink {
    /// Return the optional x-callback-url metadata carried by this deep link.
    #[must_use]
    pub const fn x_callback(&self) -> &XCallbackParams {
        match self {
            DeepLink::Signin(link) => link.x_callback(),
            DeepLink::Signup(link) => link.x_callback(),
            DeepLink::DirectSignup(link) => link.x_callback(),
            DeepLink::SigninGrant(link) => link.x_callback(),
            DeepLink::SignupGrant(link) => link.x_callback(),
            DeepLink::SeedExport(link) => link.x_callback(),
        }
    }

    /// Attach x-callback-url metadata to this deep link.
    #[must_use]
    pub(crate) fn with_x_callback(self, x_callback: XCallbackParams) -> Self {
        match self {
            Self::Signin(link) => Self::Signin(link.with_x_callback(x_callback)),
            Self::Signup(link) => Self::Signup(link.with_x_callback(x_callback)),
            Self::DirectSignup(link) => Self::DirectSignup(link.with_x_callback(x_callback)),
            Self::SigninGrant(link) => Self::SigninGrant(link.with_x_callback(x_callback)),
            Self::SignupGrant(link) => Self::SignupGrant(link.with_x_callback(x_callback)),
            Self::SeedExport(link) => Self::SeedExport(link.with_x_callback(x_callback)),
        }
    }

    /// Convert the deep link to a simple URL.
    #[must_use]
    pub fn to_url(self) -> Url {
        match self {
            DeepLink::Signin(signin) => signin.into(),
            DeepLink::Signup(signup) => signup.into(),
            DeepLink::DirectSignup(signup) => signup.into(),
            DeepLink::SigninGrant(signin) => signin.into(),
            DeepLink::SignupGrant(signup) => signup.into(),
            DeepLink::SeedExport(seed_export) => seed_export.into(),
        }
    }
}

impl Display for DeepLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeepLink::Signin(signin) => write!(f, "{signin}"),
            DeepLink::Signup(signup) => write!(f, "{signup}"),
            DeepLink::DirectSignup(signup) => write!(f, "{signup}"),
            DeepLink::SigninGrant(signin) => write!(f, "{signin}"),
            DeepLink::SignupGrant(signup) => write!(f, "{signup}"),
            DeepLink::SeedExport(seed_export) => write!(f, "{seed_export}"),
        }
    }
}

impl FromStr for DeepLink {
    type Err = DeepLinkParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s)?;
        if !DEEP_LINK_SCHEMES.contains(&url.scheme()) {
            return Err(DeepLinkParseError::InvalidSchema("pubkyauth or pubkyring"));
        }
        let intent = url.host_str().unwrap_or("").to_string();
        match intent.as_str() {
            "signin" => Ok(DeepLink::Signin(SigninDeepLink::parse_url(&url)?)),
            "signup" => Ok(DeepLink::Signup(SignupDeepLink::parse_url(&url)?)),
            "direct_signup" => Ok(DeepLink::DirectSignup(DirectSignupDeepLink::parse_url(
                &url,
            )?)),
            "signin_grant" => Ok(DeepLink::SigninGrant(SigninGrantDeepLink::parse_url(&url)?)),
            "signup_grant" => Ok(DeepLink::SignupGrant(SignupGrantDeepLink::parse_url(&url)?)),
            "secret_export" => Ok(DeepLink::SeedExport(SeedExportDeepLink::parse_url(&url)?)),
            "" => {
                // Backwards compatible with old signin format (no host).
                let mut url = url.clone();
                url.set_host(Some("signin"))?;
                let string_value = url.to_string();
                string_value.parse()
            }
            _ => Err(DeepLinkParseError::InvalidIntent("Intent not recognized.")),
        }
    }
}

impl From<DeepLink> for Url {
    fn from(val: DeepLink) -> Self {
        val.to_url()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_deep_link_signin() {
        let deep_link = "pubkyauth://signin?caps=/pub/pubky.app/:rw&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&relay=https://httprelay.pubky.app/inbox";
        let parsed: DeepLink = deep_link.parse().unwrap();
        assert!(matches!(parsed, DeepLink::Signin(_)));
    }

    #[test]
    fn test_parse_deep_link_signin_old_format() {
        let deep_link = "pubkyauth:///?caps=/pub/pubky.app/:rw&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&relay=https://httprelay.pubky.app/inbox";
        let parsed: DeepLink = deep_link.parse().unwrap();
        assert!(matches!(parsed, DeepLink::Signin(_)));
    }

    #[test]
    fn test_parse_deep_link_signin_grant() {
        let deep_link = "pubkyauth://signin_grant?caps=/pub/pubky.app/:rw&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&relay=https://httprelay.pubky.app/inbox&cid=franky.pubky.app&cpk=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo";
        let parsed: DeepLink = deep_link.parse().unwrap();
        assert!(matches!(parsed, DeepLink::SigninGrant(_)));
    }

    #[test]
    fn test_parse_deep_link_signup() {
        let deep_link = "pubkyauth://signup?caps=/pub/pubky.app/:rw&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&relay=https://httprelay.pubky.app/inbox&hs=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo&st=1234567890";
        let parsed: DeepLink = deep_link.parse().unwrap();
        assert!(matches!(parsed, DeepLink::Signup(_)));
    }

    #[test]
    fn test_parse_deep_link_direct_signup() {
        let deep_link = "pubkyauth://direct_signup?hs=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo&st=1234567890";
        let parsed: DeepLink = deep_link.parse().unwrap();
        assert!(matches!(parsed, DeepLink::DirectSignup(_)));
    }

    #[test]
    fn test_parse_deep_link_signup_grant() {
        let deep_link = "pubkyauth://signup_grant?caps=/pub/pubky.app/:rw&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&relay=https://httprelay.pubky.app/inbox&hs=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo&st=1234567890&cid=franky.pubky.app&cpk=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo";
        let parsed: DeepLink = deep_link.parse().unwrap();
        assert!(matches!(parsed, DeepLink::SignupGrant(_)));
    }

    #[test]
    fn test_parse_deep_link_signin_ignores_extra_grant_params() {
        let deep_link = "pubkyauth://signin?caps=/pub/pubky.app/:rw&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&relay=https://httprelay.pubky.app/inbox&cid=franky.pubky.app";
        let parsed: DeepLink = deep_link.parse().unwrap();

        assert!(matches!(parsed, DeepLink::Signin(_)));
    }

    #[test]
    fn test_parse_deep_link_signin_ignores_malformed_extra_grant_params() {
        let deep_link = "pubkyauth://signin?caps=/pub/pubky.app/:rw&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&relay=https://httprelay.pubky.app/inbox&cid=franky.pubky.app&cpk=not-a-public-key";
        let parsed: DeepLink = deep_link.parse().unwrap();

        assert!(matches!(parsed, DeepLink::Signin(_)));
    }

    #[test]
    fn test_parse_deep_link_signup_ignores_extra_grant_params() {
        let deep_link = "pubkyauth://signup?caps=/pub/pubky.app/:rw&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&relay=https://httprelay.pubky.app/inbox&hs=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo&cid=franky.pubky.app&cpk=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo";
        let parsed: DeepLink = deep_link.parse().unwrap();

        assert!(matches!(parsed, DeepLink::Signup(_)));
    }

    #[test]
    fn test_parse_deep_link_empty_signin_ignores_extra_grant_params() {
        let deep_link = "pubkyauth:///?caps=/pub/pubky.app/:rw&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&relay=https://httprelay.pubky.app/inbox&cid=franky.pubky.app&cpk=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo";
        let parsed: DeepLink = deep_link.parse().unwrap();

        assert!(matches!(parsed, DeepLink::Signin(_)));
    }

    #[test]
    fn test_parse_deep_link_seed_export() {
        let deep_link =
            "pubkyauth://secret_export?secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8";
        let parsed: DeepLink = deep_link.parse().unwrap();
        assert!(matches!(parsed, DeepLink::SeedExport(_)));
    }
}
