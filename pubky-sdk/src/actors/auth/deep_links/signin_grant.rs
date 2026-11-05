use pubky_common::{auth::jws::ClientId, capabilities::Capabilities, crypto::PublicKey};
use url::Url;

use super::{
    DeepLinkParseError, GrantApprovalFormat, GrantRelayChannel,
    query_params::{
        append_expected_signer, append_grant_approval_format, append_grant_params,
        append_grant_relay_channel, append_relay_params, parse_capabilities, parse_client_id,
        parse_client_pk, parse_expected_signer, parse_grant_approval_format,
        parse_grant_relay_channel, parse_relay,
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
///
/// Construct with [`Self::new`] or obtain from a parsed link. Public fields
/// remain available for customization; future fields may be added.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SigninGrantParams {
    /// Capabilities requested by the app.
    pub capabilities: Capabilities,
    /// Base HTTP relay URL.
    pub relay: Url,
    /// Relay channel key. Signed approvals use an HPKE public key as the
    /// channel ID; legacy grants use a shared secret.
    pub relay_channel: GrantRelayChannel,
    /// Application identifier carried by this deep link.
    pub client_id: ClientId,
    /// Client public key bound by the grant's `cnf` claim.
    pub client_pk: PublicKey,
    /// Relay payload format understood by the requesting client.
    pub approval_format: GrantApprovalFormat,
    /// Expected identity, encoded as `spk`: the public key that must approve.
    ///
    /// Set it only when the app already knows the signed-in user, for example
    /// to re-authorize. It is a constraint: signers approve with that key or
    /// refuse the request, and the grant flow rejects an approval issued by
    /// any other key. Switching accounts takes a request without it.
    pub expected_signer: Option<PublicKey>,
}

impl SigninGrantParams {
    /// Create parameters for a bare-grant deep link.
    ///
    /// For encryption keys, set `approval_format` to
    /// [`GrantApprovalFormat::SignedApprovalV1`] and `relay_channel` to
    /// [`GrantRelayChannel::Hpke`] with the app's temporary recipient public key.
    #[must_use]
    pub fn new(
        capabilities: Capabilities,
        relay: Url,
        secret: [u8; 32],
        client_id: ClientId,
        client_pk: PublicKey,
    ) -> Self {
        Self {
            capabilities,
            relay,
            relay_channel: GrantRelayChannel::SharedSecret(secret),
            client_id,
            client_pk,
            approval_format: GrantApprovalFormat::BareGrant,
            expected_signer: None,
        }
    }
}

impl std::fmt::Debug for SigninGrantParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigninGrantParams")
            .field("capabilities", &self.capabilities)
            .field("relay", &self.relay)
            .field("relay_channel", &self.relay_channel)
            .field("client_id", &self.client_id)
            .field("client_pk", &self.client_pk)
            .field("approval_format", &self.approval_format)
            .field("expected_signer", &self.expected_signer)
            .finish()
    }
}

impl DeepLinkParams for SigninGrantParams {
    fn parse(url: &Url) -> Result<Self, DeepLinkParseError> {
        let approval_format = parse_grant_approval_format(url)?;
        let capabilities = parse_capabilities(url)?;
        approval_format
            .validate_capabilities(&capabilities)
            .map_err(|error| DeepLinkParseError::InvalidQueryParameter("caps", Box::new(error)))?;
        Ok(Self {
            capabilities,
            relay: parse_relay(url)?,
            relay_channel: parse_grant_relay_channel(url, approval_format)?,
            client_id: parse_client_id(url)?,
            client_pk: parse_client_pk(url)?,
            approval_format,
            expected_signer: parse_expected_signer(url)?,
        })
    }

    fn append_query_pairs(&self, url: &mut Url) {
        append_relay_params(url, &self.capabilities, &self.relay);
        append_grant_params(url, &self.client_id, &self.client_pk);
        append_grant_approval_format(url, self.approval_format);
        append_grant_relay_channel(url, self.relay_channel);
        append_expected_signer(url, self.expected_signer.as_ref());
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
        assert_eq!(
            deep_link.params().approval_format,
            GrantApprovalFormat::BareGrant
        );
    }

    #[test]
    fn creates_signin_grant_deep_link_from_params() {
        let capabilities = Capabilities::builder().read_write("/").unwrap().finish();
        let relay = Url::parse("https://httprelay.pubky.app/inbox/").unwrap();
        let client_id = ClientId::new("franky.pubky.app").unwrap();
        let client_pk = Keypair::random().public_key();
        let deep_link = SigninGrantDeepLink::new(
            DeepLinkScheme::PubkyAuth,
            SigninGrantParams::new(capabilities, relay, [42; 32], client_id, client_pk),
        );
        assert_eq!(
            deep_link.params().approval_format,
            GrantApprovalFormat::BareGrant
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
    fn signed_approval_format_round_trips() {
        let client_pk = Keypair::random().public_key();
        let epk =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [7; 32]);
        let link: SigninGrantDeepLink = format!(
            "pubkyauth://signin_grant?caps=/:rw&relay=http://localhost/inbox&cid=test.app&cpk={}&af=v1&epk={epk}",
            client_pk.z32(),
        ).parse().unwrap();
        assert_eq!(
            link.params().approval_format,
            GrantApprovalFormat::SignedApprovalV1
        );
        assert_eq!(
            SigninGrantDeepLink::parse_url(&link.to_url()).unwrap(),
            link
        );
    }

    #[test]
    fn ephemeral_public_key_round_trips() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let public_key = [7; 32];
        let client_pk = Keypair::random().public_key();
        let url = format!(
            "pubkyauth://signin_grant?caps=/:rw&relay=http://localhost/inbox&cid=test.app&cpk={}&epk={}",
            client_pk.z32(),
            URL_SAFE_NO_PAD.encode(public_key),
        );
        let link = url.parse::<SigninGrantDeepLink>().unwrap();
        assert_eq!(
            link.params().relay_channel,
            GrantRelayChannel::Hpke {
                ephemeral_public_key: public_key
            }
        );
        assert_eq!(
            SigninGrantDeepLink::parse_url(&link.to_url()).unwrap(),
            link
        );
    }

    #[test]
    fn signed_approval_requires_epk_and_does_not_include_a_shared_secret() {
        let client_pk = Keypair::random().public_key();
        let without_epk = format!(
            "pubkyauth://signin_grant?caps=/:rw&relay=http://localhost/inbox&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&cid=test.app&cpk={}&af=v1",
            client_pk.z32()
        );
        assert!(matches!(
            without_epk.parse::<SigninGrantDeepLink>(),
            Err(DeepLinkParseError::InvalidQueryParameter("epk", _))
        ));

        let with_both = format!(
            "pubkyauth://signin_grant?caps=/:rw&relay=http://localhost/inbox&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&cid=test.app&cpk={}&af=v1&epk={}",
            client_pk.z32(),
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [7; 32])
        );
        assert!(matches!(
            with_both.parse::<SigninGrantDeepLink>(),
            Err(DeepLinkParseError::InvalidQueryParameter("secret", _))
        ));
    }

    #[test]
    fn unsupported_or_duplicate_approval_formats_are_rejected() {
        let client_pk = Keypair::random().public_key();
        let base = format!(
            "pubkyauth://signin_grant?caps=/:rw&relay=http://localhost/inbox&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&cid=test.app&cpk={}",
            client_pk.z32()
        );
        for query in ["af=v2", "af=", "af=v1&af=v1", "af=v1&af=v2"] {
            assert!(matches!(
                format!("{base}&{query}").parse::<SigninGrantDeepLink>(),
                Err(DeepLinkParseError::InvalidQueryParameter("af", _))
            ));
        }
    }

    #[test]
    fn expected_signer_is_optional() {
        let client_pk = Keypair::random().public_key();
        let link: SigninGrantDeepLink = format!(
            "pubkyauth://signin_grant?caps=/:rw&relay=http://localhost/inbox&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&cid=test.app&cpk={}",
            client_pk.z32()
        )
        .parse()
        .unwrap();

        assert_eq!(link.params().expected_signer, None);
        assert!(!link.to_string().contains("spk="));
    }

    #[test]
    fn expected_signer_round_trips() {
        let user = Keypair::random().public_key();
        let mut params = SigninGrantParams::new(
            Capabilities::builder().read_write("/").unwrap().finish(),
            Url::parse("https://httprelay.pubky.app/inbox/").unwrap(),
            [42; 32],
            ClientId::new("franky.pubky.app").unwrap(),
            Keypair::random().public_key(),
        );
        params.expected_signer = Some(user.clone());
        let link = SigninGrantDeepLink::new(DeepLinkScheme::PubkyAuth, params);

        let url = link.to_url();
        let spk: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key == "spk")
            .map(|(_, value)| value.into_owned())
            .collect();
        assert_eq!(spk, vec![user.z32()]);
        let parsed = SigninGrantDeepLink::parse_url(&url).unwrap();
        assert_eq!(parsed.params().expected_signer, Some(user));
        assert_eq!(parsed, link);
    }

    #[test]
    fn malformed_or_repeated_expected_signer_is_rejected() {
        let client_pk = Keypair::random().public_key();
        let user = Keypair::random().public_key().z32();
        let base = format!(
            "pubkyauth://signin_grant?caps=/:rw&relay=http://localhost/inbox&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&cid=test.app&cpk={}",
            client_pk.z32()
        );
        for query in [
            "spk=".to_string(),
            "spk=not-a-public-key".to_string(),
            format!("spk=pubky{user}"),
            format!("spk={user}&spk={user}"),
        ] {
            assert!(
                matches!(
                    format!("{base}&{query}").parse::<SigninGrantDeepLink>(),
                    Err(DeepLinkParseError::InvalidQueryParameter("spk", _))
                ),
                "{query} should be rejected"
            );
        }
    }

    #[test]
    fn expected_signer_must_be_bare_canonical_z32() {
        let client_pk = Keypair::random().public_key();
        let user = Keypair::random().public_key();
        let z32 = user.z32();
        let base = format!(
            "pubkyauth://signin_grant?caps=/:rw&relay=http://localhost/inbox&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&cid=test.app&cpk={}",
            client_pk.z32()
        );
        let rejects_spk = |value: &str| {
            let mut url = Url::parse(&base).unwrap();
            url.query_pairs_mut().append_pair("spk", value);
            matches!(
                SigninGrantDeepLink::parse_url(&url),
                Err(DeepLinkParseError::InvalidQueryParameter("spk", _))
            )
        };

        let lenient_forms = [
            format!("pk:{z32}"),
            format!("https://{z32}/"),
            format!("https://{z32}"),
        ];
        for value in &lenient_forms {
            assert_eq!(
                PublicKey::try_from_z32(value).ok(),
                Some(user.clone()),
                "Pkarr is expected to accept {value}"
            );
            assert!(rejects_spk(value), "spk={value} should be rejected");
        }
        for value in [
            format!("pubky{z32}"),
            z32.to_uppercase(),
            format!(" {z32}"),
            format!("{z32} "),
            format!("{z32}/"),
        ] {
            assert!(rejects_spk(&value), "spk={value:?} should be rejected");
        }

        let (stem, last) = z32.split_at(z32.len() - 1);
        let mut noncanonical = 0;
        for alt in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
            let candidate = format!("{stem}{alt}");
            if alt.to_string() == last
                || PublicKey::try_from_z32(&candidate).ok() != Some(user.clone())
            {
                continue;
            }
            noncanonical += 1;
            assert!(
                rejects_spk(&candidate),
                "spk={candidate} should be rejected"
            );
        }
        assert!(
            noncanonical > 0,
            "expected a noncanonical encoding of {z32}"
        );

        assert!(!rejects_spk(&z32));
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
