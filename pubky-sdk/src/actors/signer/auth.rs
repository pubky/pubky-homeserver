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
    /// Approve all requested capabilities from another app (wallet / signer side).
    ///
    /// Use [`Self::approve_auth_with_capabilities`] to approve fewer capabilities.
    ///
    /// Signed approval links use a domain-separated hash of `epk` as the relay
    /// channel ID and encrypt the approval directly with HPKE. Legacy links
    /// keep shared-secret relay encryption.
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
        self.approve_auth_deeplink(Self::parse_deeplink(pubkyauth_url)?, None)
            .await
    }

    /// Approve an auth request with capabilities selected by the user.
    ///
    /// Supports grant and legacy signin/signup links. Approved scopes and
    /// actions must be covered by the request; scopes can be narrowed and
    /// actions removed. An empty set approves no capabilities. Separate
    /// requested capabilities can cover different actions of one approval.
    /// Signed V1 approvals include keys only for approved `e` scopes.
    /// The request URL and its client identity, relay, and format are preserved.
    ///
    /// # Errors
    /// Returns [`crate::errors::Error::Authentication`] for malformed or
    /// unsupported links, or capabilities exceeding the request, before
    /// posting an approval. Propagates approval construction and relay errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn approve(signer: &pubky::PubkySigner, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    /// // The app requested `/pub/example.app/:rwe`; approve only read access.
    /// let approved = pubky::Capabilities::builder()
    ///     .read("/pub/example.app/")?
    ///     .finish();
    /// signer.approve_auth_with_capabilities(url, &approved).await?;
    /// # Ok(()) }
    /// ```
    pub async fn approve_auth_with_capabilities(
        &self,
        pubkyauth_url: impl AsRef<str>,
        approved_capabilities: &Capabilities,
    ) -> Result<()> {
        self.approve_auth_deeplink(
            Self::parse_deeplink(pubkyauth_url)?,
            Some(approved_capabilities),
        )
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
            deep_link => self.approve_auth_deeplink(deep_link, None).await,
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

    async fn approve_auth_deeplink(
        &self,
        deep_link: DeepLink,
        approved: Option<&Capabilities>,
    ) -> Result<()> {
        let (relay, relay_channel, encrypted_payload) =
            match &deep_link {
                DeepLink::Signin(d) => {
                    let params = d.params();
                    let caps = select_capabilities(&params.capabilities, approved)?;
                    cross_log!(
                        info,
                        "Approving legacy signin via relay {} (caps={:?})",
                        params.relay,
                        caps
                    );
                    (
                        params.relay.clone(),
                        GrantRelayChannel::SharedSecret(params.secret),
                        self.build_encrypted_token(caps.clone(), &params.secret),
                    )
                }
                DeepLink::Signup(d) => {
                    let params = d.params();
                    let caps = select_capabilities(&params.capabilities, approved)?;
                    cross_log!(
                        info,
                        "Approving legacy signup via relay {} (caps={:?})",
                        params.relay,
                        caps
                    );
                    (
                        params.relay.clone(),
                        GrantRelayChannel::SharedSecret(params.secret),
                        self.build_encrypted_token(caps.clone(), &params.secret),
                    )
                }
                DeepLink::DirectSignup(_) => return Err(AuthError::Validation(
                    "direct_signup links create an account; use handle_deeplink or signup instead"
                        .into(),
                )
                .into()),
                DeepLink::SigninGrant(d) => {
                    let params = d.params();
                    let caps = select_capabilities(&params.capabilities, approved)?;
                    cross_log!(
                        info,
                        "Approving grant signin via relay {} (client_id={}, caps={:?})",
                        params.relay,
                        params.client_id,
                        caps
                    );
                    let payload = self.build_encrypted_grant(
                        caps,
                        params.client_id.clone(),
                        params.client_pk.clone(),
                        params.approval_format,
                        params.relay_channel,
                    )?;
                    (params.relay.clone(), params.relay_channel, payload)
                }
                DeepLink::SignupGrant(d) => {
                    let params = d.params();
                    let caps = select_capabilities(&params.capabilities, approved)?;
                    cross_log!(
                        info,
                        "Approving grant signup via relay {} (client_id={}, caps={:?})",
                        params.relay,
                        params.client_id,
                        caps
                    );
                    let payload = self.build_encrypted_grant(
                        caps,
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

fn select_capabilities<'a>(
    requested: &'a Capabilities,
    approved: Option<&'a Capabilities>,
) -> Result<&'a Capabilities> {
    let Some(approved) = approved else {
        return Ok(requested);
    };
    // Check actions separately so split read/write requests can cover one approval.
    for capability in approved.iter() {
        for action in capability.actions() {
            if !requested.iter().any(|requested| {
                requested.scope_covers_path(capability.scope())
                    && requested.actions().contains(action)
            }) {
                return Err(AuthError::Validation(
                    "approved capabilities exceed the pending request".into(),
                )
                .into());
            }
        }
    }
    Ok(approved)
}

#[cfg(test)]
mod tests {
    use crate::actors::auth::deep_links::{
        DeepLinkScheme, SigninGrantDeepLink, SigninGrantParams, SignupGrantDeepLink,
        SignupGrantParams,
    };
    use crate::actors::auth::grant::approval::GrantApproval;
    use crate::actors::auth::grant::approval_encryption::ApprovalRecipientSecret;
    use crate::{Error, Keypair, Pubky, PubkyHttpClient};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use httpmock::{Method::POST, MockServer};
    use pubky_common::crypto::decrypt;

    use super::*;

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "The test covers both formats, relay paths, and signup modes."
    )]
    async fn grant_approvals_deliver_selected_capabilities_and_keys_in_the_negotiated_format() {
        let signer = Pubky::with_client(PubkyHttpClient::new().unwrap()).signer(Keypair::random());
        let client_pk = Keypair::random().public_key();
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
            let requested = match approval_format {
                GrantApprovalFormat::BareGrant => "/priv/chat/:rw",
                GrantApprovalFormat::SignedApprovalV1 => {
                    "/priv/chat/:rw,/priv/chat/:e,/priv/backup/:r"
                }
            };
            let caps: Capabilities = requested.parse().unwrap();
            let approvals: &[Option<&str>] = match approval_format {
                GrantApprovalFormat::BareGrant => &[None, Some("/priv/chat/file:r"), Some("")],
                GrantApprovalFormat::SignedApprovalV1 => &[
                    None,
                    Some("/priv/chat/file:r"),
                    Some(""),
                    Some("/priv/chat/selected/:e"),
                ],
            };
            for relay_path in ["inbox", "link"] {
                for signup in [false, true] {
                    for &approved in approvals {
                        let approved = approved.map(|caps| caps.parse::<Capabilities>().unwrap());
                        let server = MockServer::start_async().await;
                        let relay = Url::parse(&server.url(format!("/{relay_path}/"))).unwrap();
                        let channel_id = relay_channel.http_channel_id();
                        let callback =
                            PubkySigner::derive_callback_url(&relay, &channel_id).unwrap();
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
                        let expected_caps = approved.as_ref().unwrap_or(&caps).clone();
                        let approval_recipient = approval_recipient.clone();
                        let delivery = server
                            .mock_async(move |when, then| {
                                when.method(POST)
                                    .path(callback.path())
                                    .is_true(move |request| {
                                        let plaintext = match &approval_recipient {
                                            Some(recipient) => {
                                                recipient.open(request.body_ref()).ok()
                                            }
                                            None => decrypt(request.body_ref(), &secret)
                                                .ok()
                                                .map(Zeroizing::new),
                                        };
                                        let Some(plaintext) = plaintext else {
                                            return false;
                                        };
                                        let Ok(text) = std::str::from_utf8(&plaintext) else {
                                            return false;
                                        };
                                        GrantApproval::decode_text(text, approval_format).is_ok_and(
                                            |approval| {
                                                let claims = approval.claims;
                                                claims.iss == issuer
                                                    && claims.cnf == expected_client
                                                    && claims.client_id.as_str() == "test.app"
                                                    && claims.caps == expected_caps.to_vec()
                                            },
                                        )
                                    });
                                then.status(200);
                            })
                            .await;
                        if let Some(approved) = &approved {
                            signer
                                .approve_auth_with_capabilities(link, approved)
                                .await
                                .unwrap();
                        } else {
                            signer.approve_auth(link).await.unwrap();
                        }
                        delivery.assert_async().await;
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn selective_approval_validates_all_auth_intents_before_delivery() {
        let server = MockServer::start_async().await;
        let secret = [42; 32];
        let signer = Pubky::with_client(PubkyHttpClient::new().unwrap()).signer(Keypair::random());
        for intent in ["signin", "signup", "signin_grant", "signup_grant"] {
            let mut url = Url::parse(&format!("pubkyauth://{intent}")).unwrap();
            url.query_pairs_mut()
                .append_pair("caps", "/pub/app/:r,/pub/app/:w")
                .append_pair("relay", &server.url("/inbox"))
                .append_pair("secret", &URL_SAFE_NO_PAD.encode(secret))
                .append_pair("cid", "test.app")
                .append_pair("cpk", &Keypair::random().public_key().to_z32())
                .append_pair("hs", &Keypair::random().public_key().to_z32());
            let issuer = signer.public_key();
            let expected: Capabilities = "/pub/app/file:rw".parse().unwrap();
            let delivery = server
                .mock_async(move |when, then| {
                    when.method(POST).is_true(move |request| {
                        let Ok(plaintext) = decrypt(request.body_ref(), &secret) else {
                            return false;
                        };
                        if intent.ends_with("_grant") {
                            let Ok(text) = std::str::from_utf8(&plaintext) else {
                                return false;
                            };
                            GrantClaims::decode(text).is_ok_and(|claims| {
                                claims.iss == issuer && claims.caps == expected.to_vec()
                            })
                        } else {
                            AuthToken::verify(&plaintext).is_ok_and(|token| {
                                token.public_key() == &issuer && token.capabilities() == &expected
                            })
                        }
                    });
                    then.status(200);
                })
                .await;
            for caps in ["/:r", "/pub/other/:r", "/pub/application/:r", "/pub/app/:e"] {
                let error = signer
                    .approve_auth_with_capabilities(url.as_str(), &caps.parse().unwrap())
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, Error::Authentication(AuthError::Validation(message))
                    if message == "approved capabilities exceed the pending request")
                );
            }
            delivery.assert_calls_async(0).await;
            // Separate requested read and write actions can cover one approval.
            signer
                .approve_auth_with_capabilities(url.as_str(), &"/pub/app/file:rw".parse().unwrap())
                .await
                .unwrap();
            delivery.assert_calls_async(1).await;
            delivery.delete_async().await;
        }
    }

    #[tokio::test]
    async fn selective_approval_rejects_malformed_and_non_auth_links() {
        let signer = Pubky::with_client(PubkyHttpClient::new().unwrap()).signer(Keypair::random());
        for url in [
            "not a URL",
            "pubkyauth://direct_signup?hs=5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo",
            "pubkyauth://secret_export?secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8",
        ] {
            let error = signer
                .approve_auth_with_capabilities(url, &Capabilities::default())
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                Error::Authentication(AuthError::Validation(_))
            ));
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
