use pubky_common::{auth::jws::ClientId, capabilities::Capabilities, crypto::PublicKey};
use url::Url;

use super::{
    DeepLinkParseError,
    query_params::{
        append_grant_params, append_signup_params, optional_query, parse_capabilities,
        parse_client_id, parse_client_pk, parse_homeserver, parse_relay, parse_secret,
    },
    typed_deep_link::{DeepLinkIntent, DeepLinkParams, TypedDeepLink},
};

/// Intent marker for grant-mode signup deep links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignupGrantIntent;

impl DeepLinkIntent for SignupGrantIntent {
    const NAME: &'static str = "signup_grant";
}

/// Typed parameters for grant-mode signup deep links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignupGrantParams {
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
    /// Application identifier carried by this deep link.
    pub client_id: ClientId,
    /// Client public key bound by the grant's `cnf` claim.
    pub client_pk: PublicKey,
}

impl DeepLinkParams for SignupGrantParams {
    fn parse(url: &Url) -> Result<Self, DeepLinkParseError> {
        Ok(Self {
            capabilities: parse_capabilities(url)?,
            relay: parse_relay(url)?,
            secret: parse_secret(url)?,
            homeserver: parse_homeserver(url)?,
            signup_token: optional_query(url, "st"),
            client_id: parse_client_id(url)?,
            client_pk: parse_client_pk(url)?,
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
        append_grant_params(url, &self.client_id, &self.client_pk);
    }
}

/// A deep link for signing up via the grant flow.
pub type SignupGrantDeepLink = TypedDeepLink<SignupGrantIntent, SignupGrantParams>;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pubky_common::crypto::Keypair;

    use super::*;
    use crate::actors::auth::deep_links::DeepLinkScheme;

    const HOMESERVER: &str = "5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo";

    #[test]
    fn parses_signup_grant_deep_link_without_signup_token() {
        let client_pk = Keypair::random().public_key();
        let deep_link: SignupGrantDeepLink = format!(
            "pubkyauth://signup_grant?caps=/pub/pubky.app/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&hs={HOMESERVER}&cid=franky.pubky.app&cpk={}",
            client_pk.z32()
        )
        .parse()
        .unwrap();

        assert_eq!(deep_link.scheme(), DeepLinkScheme::PubkyAuth);
        assert_eq!(deep_link.intent(), "signup_grant");
        assert_eq!(deep_link.params().signup_token, None);
        assert_eq!(deep_link.params().client_pk.z32(), client_pk.z32());
    }

    #[test]
    fn parses_signup_grant_deep_link_with_signup_token() {
        let client_pk = Keypair::random().public_key();
        let deep_link: SignupGrantDeepLink = format!(
            "pubkyauth://signup_grant?caps=/pub/pubky.app/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&hs={HOMESERVER}&st=123&cid=franky.pubky.app&cpk={}",
            client_pk.z32()
        )
        .parse()
        .unwrap();

        assert_eq!(deep_link.params().signup_token, Some("123".into()));
    }

    #[test]
    fn creates_signup_grant_deep_link_from_params() {
        let capabilities = Capabilities::builder().read_write("/").unwrap().finish();
        let relay = Url::parse("https://httprelay.pubky.app/inbox/").unwrap();
        let homeserver = PublicKey::from_str(HOMESERVER).unwrap();
        let client_id = ClientId::new("franky.pubky.app").unwrap();
        let client_pk = Keypair::random().public_key();
        let deep_link = SignupGrantDeepLink::new(
            DeepLinkScheme::PubkyAuth,
            SignupGrantParams {
                capabilities,
                relay,
                secret: [42; 32],
                homeserver,
                signup_token: Some("123".into()),
                client_id,
                client_pk,
            },
        );
        let parsed_again = SignupGrantDeepLink::parse_url(&deep_link.to_url()).unwrap();

        assert_eq!(parsed_again, deep_link);
    }

    #[test]
    fn rejects_missing_cid() {
        let pk = Keypair::random().public_key();
        let url = format!(
            "pubkyauth://signup_grant?caps=/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&hs={HOMESERVER}&cpk={}",
            pk.z32()
        );
        let err = url.parse::<SignupGrantDeepLink>().unwrap_err();

        assert!(matches!(
            err,
            DeepLinkParseError::MissingQueryParameter("cid")
        ));
    }
}
