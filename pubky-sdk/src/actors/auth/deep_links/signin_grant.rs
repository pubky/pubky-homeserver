use pubky_common::{auth::jws::ClientId, capabilities::Capabilities, crypto::PublicKey};
use url::Url;

use super::{
    DeepLinkParseError,
    query_params::{
        append_grant_params, append_signin_params, parse_capabilities, parse_client_id,
        parse_client_pk, parse_relay, parse_secret,
    },
    typed_deep_link::{DeepLinkIntent, DeepLinkParams, TypedDeepLink},
};

/// Intent marker for grant-mode signin deep links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigninGrantIntent;

impl DeepLinkIntent for SigninGrantIntent {
    const NAME: &'static str = "signin_grant";
}

/// Typed parameters for grant-mode signin deep links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigninGrantParams {
    /// Capabilities requested by the app.
    pub capabilities: Capabilities,
    /// Base HTTP relay URL.
    pub relay: Url,
    /// Secret used to derive the encrypted relay channel.
    pub secret: [u8; 32],
    /// Application identifier carried by this deep link.
    pub client_id: ClientId,
    /// Client public key bound by the grant's `cnf` claim.
    pub client_pk: PublicKey,
}

impl DeepLinkParams for SigninGrantParams {
    fn parse(url: &Url) -> Result<Self, DeepLinkParseError> {
        Ok(Self {
            capabilities: parse_capabilities(url)?,
            relay: parse_relay(url)?,
            secret: parse_secret(url)?,
            client_id: parse_client_id(url)?,
            client_pk: parse_client_pk(url)?,
        })
    }

    fn append_query_pairs(&self, url: &mut Url) {
        append_signin_params(url, &self.capabilities, &self.relay, &self.secret);
        append_grant_params(url, &self.client_id, &self.client_pk);
    }
}

/// A deep link for signing in via the grant flow.
pub type SigninGrantDeepLink = TypedDeepLink<SigninGrantIntent, SigninGrantParams>;

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Keypair;

    use super::*;
    use crate::actors::auth::deep_links::DeepLinkScheme;

    #[test]
    fn parses_signin_grant_deep_link() {
        let client_pk = Keypair::random().public_key();
        let deep_link: SigninGrantDeepLink = format!(
            "pubkyauth://signin_grant?caps=/pub/pubky.app/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&cid=franky.pubky.app&cpk={}",
            client_pk.z32()
        )
        .parse()
        .unwrap();

        assert_eq!(deep_link.scheme(), DeepLinkScheme::PubkyAuth);
        assert_eq!(deep_link.intent(), "signin_grant");
        assert_eq!(deep_link.params().client_id.to_string(), "franky.pubky.app");
        assert_eq!(deep_link.params().client_pk.z32(), client_pk.z32());
    }

    #[test]
    fn creates_signin_grant_deep_link_from_params() {
        let capabilities = Capabilities::builder().read_write("/").unwrap().finish();
        let relay = Url::parse("https://httprelay.pubky.app/inbox/").unwrap();
        let client_id = ClientId::new("franky.pubky.app").unwrap();
        let client_pk = Keypair::random().public_key();
        let deep_link = SigninGrantDeepLink::new(
            DeepLinkScheme::PubkyAuth,
            SigninGrantParams {
                capabilities,
                relay,
                secret: [42; 32],
                client_id,
                client_pk,
            },
        );
        let parsed_again = SigninGrantDeepLink::parse_url(&deep_link.to_url()).unwrap();

        assert_eq!(parsed_again, deep_link);
    }

    #[test]
    fn rejects_missing_cpk() {
        let url = "pubkyauth://signin_grant?caps=/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&cid=franky.pubky.app";
        let err = url.parse::<SigninGrantDeepLink>().unwrap_err();

        assert!(matches!(
            err,
            DeepLinkParseError::MissingQueryParameter("cpk")
        ));
    }

    #[test]
    fn rejects_missing_cid() {
        let pk = Keypair::random().public_key();
        let url = format!(
            "pubkyauth://signin_grant?caps=/:rw&relay=https://httprelay.pubky.app/inbox/&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&cpk={}",
            pk.z32()
        );
        let err = url.parse::<SigninGrantDeepLink>().unwrap_err();

        assert!(matches!(
            err,
            DeepLinkParseError::MissingQueryParameter("cid")
        ));
    }
}
