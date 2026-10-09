use reqwest::Method;
use url::Url;
use zeroize::Zeroizing;

use pubky_common::{
    auth::{
        AuthToken,
        grant::GrantClaims,
        jws::{ClientId, GRANT_JWS_TYP, GrantId},
    },
    crypto::{PublicKey, encrypt},
};

use crate::{
    Capabilities,
    actors::auth::{
        deep_links::{DeepLink, DeepLinkParseError, GrantApprovalFormat, GrantRelayChannel},
        grant::approval_encryption,
        grant::{approval_envelope::GrantApprovalEnvelope, constants::DEFAULT_GRANT_LIFETIME_SECS},
    },
    cross_log,
    errors::{AuthError, Result},
};

use super::PubkySigner;

impl PubkySigner {
    /// Approve an auth request from another app (wallet / signer side).
    ///
    /// Signed approval links use their `epk` as the relay channel ID and
    /// encrypt the approval directly with HPKE. Legacy links keep shared-secret
    /// relay encryption.
    /// Grant requests with `af=v1` receive a signed envelope with the grant
    /// and keys only for approved `e` scopes. Requests without that opt-in
    /// retain the bare grant format. Only legacy links contain a relay secret.
    ///
    /// # Typical usage
    ///
    /// 1. The **requesting app** constructs a [`PubkyGrantAuthFlow`](crate::PubkyGrantAuthFlow)
    ///    and displays `authorization_url()` as a QR code or deep link.
    /// 2. The **signer app** (e.g. Pubky Ring) scans the QR and calls `approve_auth`
    ///    with the scanned URL.
    /// 3. The requesting app receives the approval and obtains a session.
    ///
    /// Use [`Self::handle_deeplink`] instead if the URL might be a `direct_signup` link.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Authentication`] if the `pubkyauth://`
    ///   URL is malformed or addresses an intent that `approve_auth` does not
    ///   handle (e.g. `secret_export`).
    /// - Propagates transport failures when posting to the relay or if the
    ///   relay responds with a non-success status.
    pub async fn approve_auth(&self, pubkyauth_url: impl AsRef<str>) -> Result<()> {
        self.approve_auth_deeplink(Self::parse_deeplink(pubkyauth_url)?)
            .await
    }

    /// Executes the action represented by a `pubkyauth://` deep link.
    ///
    /// Authentication links are approved through the relay, while a
    /// [`DeepLink::DirectSignup`] creates the signer's account directly on the
    /// target homeserver.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Authentication`] if the URL is malformed
    ///   or the signer does not handle its intent.
    /// - Propagates signup or authentication-delivery failures for the handled intent.
    pub async fn handle_deeplink(&self, pubkyauth_url: impl AsRef<str>) -> Result<()> {
        match Self::parse_deeplink(pubkyauth_url)? {
            DeepLink::DirectSignup(d) => {
                let params = d.params();
                self.signup(&params.homeserver, params.signup_token.as_deref())
                    .await
            }
            DeepLink::SeedExport(_) => Err(AuthError::Validation(
                "handle_deeplink does not handle seed_export deep links".into(),
            )
            .into()),
            deep_link => self.approve_auth_deeplink(deep_link).await,
        }
    }

    fn parse_deeplink(pubkyauth_url: impl AsRef<str>) -> Result<DeepLink> {
        pubkyauth_url
            .as_ref()
            .parse()
            .map_err(|e: DeepLinkParseError| {
                AuthError::Validation(format!("invalid pubkyauth URL: {e}")).into()
            })
    }

    async fn approve_auth_deeplink(&self, deep_link: DeepLink) -> Result<()> {
        let (relay, relay_channel, encrypted_payload) =
            match &deep_link {
                DeepLink::Signin(d) => {
                    let params = d.params();
                    cross_log!(
                        info,
                        "Approving legacy signin via relay {} (caps={:?})",
                        params.relay,
                        params.capabilities
                    );
                    let payload =
                        self.build_encrypted_token(params.capabilities.clone(), &params.secret);
                    (
                        params.relay.clone(),
                        GrantRelayChannel::SharedSecret(params.secret),
                        payload,
                    )
                }
                DeepLink::Signup(d) => {
                    let params = d.params();
                    cross_log!(
                        info,
                        "Approving legacy signup via relay {} (caps={:?})",
                        params.relay,
                        params.capabilities
                    );
                    let payload =
                        self.build_encrypted_token(params.capabilities.clone(), &params.secret);
                    (
                        params.relay.clone(),
                        GrantRelayChannel::SharedSecret(params.secret),
                        payload,
                    )
                }
                DeepLink::DirectSignup(_) => return Err(AuthError::Validation(
                    "direct_signup links create an account; use handle_deeplink or signup instead"
                        .into(),
                )
                .into()),
                DeepLink::SigninGrant(d) => {
                    let params = d.params();
                    cross_log!(
                        info,
                        "Approving grant signin via relay {} (client_id={}, caps={:?})",
                        params.relay,
                        params.client_id,
                        params.capabilities
                    );
                    let payload = self.build_encrypted_grant(
                        &params.capabilities,
                        params.client_id.clone(),
                        params.client_pk.clone(),
                        params.approval_format,
                        params.relay_channel,
                    )?;
                    (params.relay.clone(), params.relay_channel, payload)
                }
                DeepLink::SignupGrant(d) => {
                    let params = d.params();
                    cross_log!(
                        info,
                        "Approving grant signup via relay {} (client_id={}, caps={:?})",
                        params.relay,
                        params.client_id,
                        params.capabilities
                    );
                    let payload = self.build_encrypted_grant(
                        &params.capabilities,
                        params.client_id.clone(),
                        params.client_pk.clone(),
                        params.approval_format,
                        params.relay_channel,
                    )?;
                    (params.relay.clone(), params.relay_channel, payload)
                }
                DeepLink::SeedExport(_) => {
                    return Err(AuthError::Validation(
                        "approve_auth does not handle seed_export deep links".into(),
                    )
                    .into());
                }
            };

        let callback_url = Self::derive_callback_url(&relay, &relay_channel.http_channel_id())?;
        cross_log!(
            info,
            "Posting encrypted auth payload to relay channel {}",
            callback_url
        );

        let response = self
            .client
            .cross_request(Method::POST, callback_url)
            .await?
            .body(encrypted_payload)
            .send()
            .await?;

        self.client.check_http_status(response).await?;
        cross_log!(info, "Auth payload delivered successfully");
        Ok(())
    }

    fn build_encrypted_grant(
        &self,
        capabilities: &Capabilities,
        client_id: ClientId,
        client_pk: PublicKey,
        format: GrantApprovalFormat,
        relay_channel: GrantRelayChannel,
    ) -> Result<Vec<u8>> {
        format.validate_capabilities(capabilities)?;
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let claims = GrantClaims {
            iss: self.keypair.public_key(),
            client_id,
            caps: capabilities.as_slice().to_vec(),
            cnf: client_pk,
            jti: GrantId::generate(),
            iat: now,
            exp: now + DEFAULT_GRANT_LIFETIME_SECS,
        };
        let payload =
            match format {
                GrantApprovalFormat::BareGrant => Zeroizing::new(
                    pubky_common::auth::jws::sign_jws(&self.keypair, GRANT_JWS_TYP, &claims),
                ),
                GrantApprovalFormat::SignedApprovalV1 => {
                    GrantApprovalEnvelope::sign(&self.keypair, &claims)
                }
            };
        match relay_channel {
            GrantRelayChannel::SharedSecret(secret) => Ok(encrypt(payload.as_bytes(), &secret)),
            GrantRelayChannel::Hpke {
                ephemeral_public_key,
            } => approval_encryption::seal(&ephemeral_public_key, payload.as_bytes()),
        }
    }

    fn build_encrypted_token(
        &self,
        capabilities: Capabilities,
        client_secret: &[u8; 32],
    ) -> Vec<u8> {
        let token = AuthToken::sign(&self.keypair, capabilities);
        encrypt(&token.serialize(), client_secret)
    }

    fn derive_callback_url(relay: &Url, channel_id: &str) -> Result<Url> {
        let mut callback_url = relay.clone();
        let mut path_segments = callback_url
            .path_segments_mut()
            .map_err(|()| url::ParseError::RelativeUrlWithCannotBeABaseBase)?;
        path_segments.pop_if_empty();
        path_segments.push(channel_id);
        drop(path_segments);
        Ok(callback_url)
    }
}

#[cfg(test)]
mod tests {
    use crate::actors::auth::deep_links::{
        DeepLinkScheme, SigninGrantDeepLink, SigninGrantParams, SignupGrantDeepLink,
        SignupGrantParams,
    };
    use crate::actors::auth::grant::approval_encryption::ApprovalRecipientSecret;
    use crate::{Capability, Error, Keypair, Pubky, PubkyHttpClient};
    use httpmock::{Method::POST, MockServer};
    use pubky_common::auth::jws::decode_jws_payload;
    use pubky_common::crypto::decrypt;

    use super::*;

    #[tokio::test]
    async fn grant_signin_and_signup_deliver_the_negotiated_format_to_the_relay() {
        let signer = Pubky::with_client(PubkyHttpClient::new().unwrap()).signer(Keypair::random());
        let client_pk = Keypair::random().public_key();
        let caps = Capabilities::builder()
            .read_write("/priv/chat/")
            .unwrap()
            .finish();
        let secret = [42; 32];
        for approval_format in [
            GrantApprovalFormat::BareGrant,
            GrantApprovalFormat::SignedApprovalV1,
        ] {
            let (approval_recipient, relay_channel) =
                if approval_format == GrantApprovalFormat::SignedApprovalV1 {
                    let (secret, public_key) = ApprovalRecipientSecret::generate();
                    (
                        Some(secret),
                        GrantRelayChannel::Hpke {
                            ephemeral_public_key: public_key,
                        },
                    )
                } else {
                    (None, GrantRelayChannel::SharedSecret(secret))
                };
            let caps = if approval_format == GrantApprovalFormat::SignedApprovalV1 {
                Capabilities::builder()
                    .extend(caps.to_vec())
                    .encryption_keys("/priv/chat/")
                    .unwrap()
                    .read("/priv/backup/")
                    .unwrap()
                    .finish()
            } else {
                caps.clone()
            };
            for relay_path in ["inbox", "link"] {
                for signup in [false, true] {
                    let server = MockServer::start_async().await;
                    let relay = Url::parse(&server.url(&format!("/{relay_path}/"))).unwrap();
                    let channel_id = relay_channel.http_channel_id();
                    let callback = PubkySigner::derive_callback_url(&relay, &channel_id).unwrap();
                    let link = if signup {
                        SignupGrantDeepLink::new(
                            DeepLinkScheme::PubkyAuth,
                            SignupGrantParams {
                                capabilities: caps.clone(),
                                relay,
                                relay_channel,
                                homeserver: Keypair::random().public_key(),
                                signup_token: None,
                                client_id: ClientId::new("test.app").unwrap(),
                                client_pk: client_pk.clone(),
                                approval_format,
                            },
                        )
                        .to_string()
                    } else {
                        SigninGrantDeepLink::new(
                            DeepLinkScheme::PubkyAuth,
                            SigninGrantParams {
                                capabilities: caps.clone(),
                                relay,
                                relay_channel,
                                client_id: ClientId::new("test.app").unwrap(),
                                client_pk: client_pk.clone(),
                                approval_format,
                            },
                        )
                        .to_string()
                    };
                    let issuer = signer.public_key();
                    let expected_client = client_pk.clone();
                    let expected_caps = caps.clone();
                    let approval_recipient = approval_recipient.clone();
                    let delivery = server
                        .mock_async(move |when, then| {
                            when.method(POST)
                                .path(callback.path())
                                .is_true(move |request| {
                                    let plaintext = match &approval_recipient {
                                        Some(recipient) => {
                                            let Ok(plaintext) = recipient.open(request.body_ref())
                                            else {
                                                return false;
                                            };
                                            plaintext
                                        }
                                        None => {
                                            let Ok(plaintext) =
                                                decrypt(request.body_ref(), &secret)
                                            else {
                                                return false;
                                            };
                                            zeroize::Zeroizing::new(plaintext)
                                        }
                                    };
                                    let Ok(text) = std::str::from_utf8(&plaintext) else {
                                        return false;
                                    };
                                    let claims = match approval_format {
                                        GrantApprovalFormat::BareGrant => GrantClaims::decode(text),
                                        GrantApprovalFormat::SignedApprovalV1 => {
                                            let Ok(envelope) =
                                                decode_jws_payload::<GrantApprovalEnvelope>(text)
                                            else {
                                                return false;
                                            };
                                            if envelope.encryption_keys.scopes().collect::<Vec<_>>()
                                                != expected_caps
                                                    .iter()
                                                    .filter(|cap| cap.grants_encryption_keys())
                                                    .map(Capability::scope)
                                                    .collect::<Vec<_>>()
                                            {
                                                return false;
                                            }
                                            GrantClaims::decode(&envelope.grant)
                                        }
                                    };
                                    claims.is_ok_and(|claims| {
                                        claims.iss == issuer
                                            && claims.cnf == expected_client
                                            && claims.client_id.as_str() == "test.app"
                                            && claims.caps == expected_caps.to_vec()
                                    })
                                });
                            then.status(200);
                        })
                        .await;
                    signer.approve_auth(link).await.unwrap();
                    delivery.assert_async().await;
                }
            }
        }
    }

    #[test]
    fn unversioned_grant_clients_keep_the_bare_jws_payload() {
        let signer = Pubky::with_client(PubkyHttpClient::new().unwrap()).signer(Keypair::random());
        let payload = signer
            .build_encrypted_grant(
                &Capabilities::default(),
                ClientId::new("test.app").unwrap(),
                Keypair::random().public_key(),
                GrantApprovalFormat::BareGrant,
                GrantRelayChannel::SharedSecret([42; 32]),
            )
            .unwrap();
        let plaintext = decrypt(&payload, &[42; 32]).unwrap();
        let claims = GrantClaims::decode(std::str::from_utf8(&plaintext).unwrap()).unwrap();
        assert_eq!(claims.iss, signer.public_key());
    }

    #[tokio::test]
    async fn approve_auth_rejects_direct_signup_links() {
        let signer = Pubky::with_client(PubkyHttpClient::new().unwrap()).signer(Keypair::random());

        let error = signer
            .approve_auth(
                "pubkyauth://direct_signup?hs=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo",
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            Error::Authentication(AuthError::Validation(message)) if message.contains("handle_deeplink")
        ));
    }
}
