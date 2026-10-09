//! Grant + `PoP` auth flow — QR/deeplink → signer approval → self-refreshing session.
//!
//! ## Sign in
//! ```no_run
//! # use pubky::{Capabilities, PubkyGrantAuthFlow, AuthFlowKind, ClientId};
//! # async fn run() -> pubky::Result<()> {
//! let caps = Capabilities::default();
//! let client_id = ClientId::new("my.app").unwrap();
//! let flow = PubkyGrantAuthFlow::start(&caps, AuthFlowKind::signin(), client_id)?;
//! println!("Scan to sign in: {}", flow.authorization_url());
//!
//! let session = flow.await_approval().await?;
//! println!("Signed in as {}", session.info().public_key());
//! # Ok(()) }
//! ```
//!
//! ## Sign in (credential-level, for persistence or inspection)
//! ```no_run
//! # use pubky::{Capabilities, PubkyGrantAuthFlow, AuthFlowKind, ClientId, PubkyHttpClient, PubkySession};
//! # async fn run() -> pubky::Result<()> {
//! let client = PubkyHttpClient::new()?;
//! let client_id = ClientId::new("my.app").unwrap();
//! let flow = PubkyGrantAuthFlow::builder(&Capabilities::default(), AuthFlowKind::signin(), client_id)
//!     .client(client.clone())
//!     .start()?;
//! let credential = flow.await_credential().await?;
//! // ... store or inspect the credential ...
//! let session = PubkySession::from_grant_credential(client, credential);
//! # Ok(()) }
//! ```
//!
//! ## Custom relay / non-blocking UI
//! ```no_run
//! # use pubky::{Capabilities, PubkyGrantAuthFlow, AuthFlowKind, ClientId};
//! # use std::time::Duration;
//! # async fn ui() -> pubky::Result<()> {
//! let client_id = ClientId::new("my.app").unwrap();
//! let flow = PubkyGrantAuthFlow::builder(&Capabilities::default(), AuthFlowKind::signin(), client_id)
//!     .relay(url::Url::parse("http://localhost:8080/inbox/")?)
//!     .start()?;
//!
//! loop {
//!     if let Some(_session) = flow.try_poll_once().await? {
//!         break;
//!     }
//!     tokio::time::sleep(Duration::from_millis(300)).await;
//! }
//! # Ok(()) }
//! ```

use std::{fmt, str::FromStr};

use pubky_common::{
    auth::jws::ClientId,
    crypto::{Keypair, PublicKey},
};
use url::Url;

use crate::actors::Pkdns;
use crate::actors::auth::deep_links::{DeepLink, GrantRelayChannel};
use crate::actors::auth::grant::approval::GrantApproval;
use crate::actors::auth::grant::approval_encryption::ApprovalRecipientSecret;
use crate::actors::auth::grant::builder::GrantAuthFlowBuilder;
use crate::actors::auth::grant::credential::GrantCredential;
use crate::actors::auth::grant::grant_exchange::credential_from_grant_exchange;
use crate::actors::auth::grant::pop_signer::{DelegatedSignFn, GrantPopSigner};
use crate::actors::auth::kind::AuthFlowKind;
use crate::actors::auth::relay::{AuthRelayMessage, auth_relay_listener::AuthRelayListener};
use crate::errors::{AuthError, Result};
use crate::{Capabilities, PubkyHttpClient, PubkySession};

/// Serializable state for resuming a pending grant auth flow.
///
/// This is not a session credential. It only preserves enough local state to
/// continue polling an unapproved grant auth flow after the original
/// [`PubkyGrantAuthFlow`] handle was dropped. Treat it as sensitive temporary
/// data: it contains the `PoP` client private key and, for legacy relay
/// channels, the shared secret in [`Self::authorization_url`]. Signed
/// approval flows instead include the public `epk` in the URL and keep its
/// matching private key here.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
pub struct GrantAuthFlowState {
    /// Original grant authorization URL shown to the signer.
    pub authorization_url: String,
    /// Secret bytes for the `PoP` client keypair bound by the deep link `cpk`.
    pub client_key_secret: [u8; 32],
    /// Temporary HPKE recipient secret for a signed approval flow, when used.
    #[cfg_attr(feature = "json", serde(default))]
    pub approval_key_secret: Option<[u8; 32]>,
}

/// Serializable state for resuming a pending delegated browser grant auth flow.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
pub struct DelegatedGrantAuthFlowState {
    /// Original grant authorization URL shown to the signer.
    pub authorization_url: String,
    /// `IndexedDB` key id for the non-extractable private `CryptoKey`.
    pub key_id: String,
    /// Public key for the delegated `PoP` signer bound by the deep link `cpk`.
    pub client_pk: PublicKey,
    /// Temporary HPKE recipient secret for a signed approval flow, when used.
    #[cfg_attr(feature = "json", serde(default))]
    pub approval_key_secret: Option<[u8; 32]>,
}

impl fmt::Debug for DelegatedGrantAuthFlowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelegatedGrantAuthFlowState")
            .field("authorization_url", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("client_pk", &self.client_pk)
            .field("approval_key_secret", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for GrantAuthFlowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantAuthFlowState")
            .field("authorization_url", &"<redacted>")
            .field("client_key_secret", &"<redacted>")
            .field("approval_key_secret", &"<redacted>")
            .finish()
    }
}

/// End-to-end **Grant + `PoP` auth flow** handle.
///
/// 1. Construct with [`PubkyGrantAuthFlow::start`] or
///    [`PubkyGrantAuthFlow::builder`].
/// 2. Display [`authorization_url`](Self::authorization_url) (QR/deeplink) to
///    the signer.
/// 3. Complete with [`await_approval`](Self::await_approval) for a ready
///    [`PubkySession`], or [`await_credential`](Self::await_credential) for
///    a raw [`GrantCredential`]. Non-blocking companions:
///    [`try_poll_once`](Self::try_poll_once),
///    [`try_poll_credential_once`](Self::try_poll_credential_once).
///
/// Background polling **starts immediately** at construction. Dropping this
/// value cancels the background task; the relay channel itself expires
/// server-side after its TTL.
pub struct PubkyGrantAuthFlow {
    relay_listener: AuthRelayListener,
    client: PubkyHttpClient,
    auth_url: Url,
    client_signer: GrantPopSigner,
    approval_key_secret: Option<ApprovalRecipientSecret>,
}

impl fmt::Debug for PubkyGrantAuthFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PubkyGrantAuthFlow")
            .field("relay_listener", &self.relay_listener)
            .field("client", &self.client)
            .field("auth_url", &"<redacted>")
            .field("client_signer", &self.client_signer)
            .field("approval_key_secret", &self.approval_key_secret)
            .finish()
    }
}

impl PubkyGrantAuthFlow {
    pub(crate) fn new(
        relay_listener: AuthRelayListener,
        client: PubkyHttpClient,
        auth_url: Url,
        client_signer: GrantPopSigner,
        approval_key_secret: Option<ApprovalRecipientSecret>,
    ) -> Self {
        Self {
            relay_listener,
            client,
            auth_url,
            client_signer,
            approval_key_secret,
        }
    }

    /// Start a grant flow with the default HTTP relay.
    ///
    /// The resulting [`PubkySession`] is grant-backed and self-refreshes.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error`] if constructing the backing
    ///   [`PubkyHttpClient`] or generating the relay URL fails.
    pub fn start(
        caps: &Capabilities,
        auth_kind: AuthFlowKind,
        client_id: ClientId,
    ) -> Result<Self> {
        GrantAuthFlowBuilder::new(caps.clone(), auth_kind, client_id).start()
    }

    /// Create a builder to override the **relay**, provide a custom **client**,
    /// or pin a specific **`PoP` keypair**.
    #[must_use]
    pub fn builder(
        caps: &Capabilities,
        auth_kind: AuthFlowKind,
        client_id: ClientId,
    ) -> GrantAuthFlowBuilder {
        GrantAuthFlowBuilder::new(caps.clone(), auth_kind, client_id)
    }

    /// The `pubkyauth://` deep link you display (QR/URL) to the signer.
    #[must_use]
    pub fn authorization_url(&self) -> Url {
        self.auth_url.clone()
    }

    /// Save the sensitive state required to restore this pending local grant flow.
    ///
    /// The returned state is only useful while the relay inbox still exists.
    /// It should be stored temporarily and deleted once the flow completes,
    /// expires, or is abandoned.
    ///
    #[must_use]
    pub fn save_local(&self) -> Option<GrantAuthFlowState> {
        Some(GrantAuthFlowState {
            authorization_url: self.authorization_url().to_string(),
            client_key_secret: self.client_signer.local_secret()?,
            approval_key_secret: self
                .approval_key_secret
                .as_ref()
                .map(ApprovalRecipientSecret::to_bytes),
        })
    }

    /// Save sensitive state required to resume a pending delegated grant flow.
    ///
    /// This does not export the delegated private key, but it includes the relay
    /// secret in [`DelegatedGrantAuthFlowState::authorization_url`]. Store it only
    /// temporarily and delete it once the flow completes or is abandoned.
    #[must_use]
    pub fn save_delegated(&self) -> Option<DelegatedGrantAuthFlowState> {
        let signer = self.client_signer.delegated_state()?;
        Some(DelegatedGrantAuthFlowState {
            authorization_url: self.authorization_url().to_string(),
            key_id: signer.key_id,
            client_pk: signer.public_key,
            approval_key_secret: self
                .approval_key_secret
                .as_ref()
                .map(ApprovalRecipientSecret::to_bytes),
        })
    }

    /// Restore a pending grant auth flow from state produced by [`Self::save_local`].
    ///
    /// This re-subscribes to the relay channel encoded in the authorization URL
    /// and validates that the saved `PoP` client key matches the `cpk` in the
    /// grant deep link.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Authentication`] if the saved URL is
    ///   not a grant auth deep link or the saved client key does not match it.
    /// - Propagates failures from starting the relay listener.
    pub fn restore(state: GrantAuthFlowState, client: PubkyHttpClient) -> Result<Self> {
        let GrantAuthFlowState {
            authorization_url,
            client_key_secret,
            approval_key_secret,
        } = state;
        let auth_url = DeepLink::from_str(&authorization_url).map_err(|e| {
            AuthError::Validation(format!("failed to parse grant auth flow state URL: {e}"))
        })?;
        let (relay, relay_channel, client_pk) = grant_deep_link_parts(&auth_url)?;
        let approval_key_secret = restore_approval_key_secret(relay_channel, approval_key_secret)?;
        let client_keypair = Keypair::from_secret(&client_key_secret);

        if &client_keypair.public_key() != client_pk {
            return Err(AuthError::Validation(
                "saved grant auth flow client key does not match the deep link client public key"
                    .into(),
            )
            .into());
        }

        let relay_listener = AuthRelayListener::builder_for_channel(relay_channel)
            .relay_base_url(relay.clone())
            .client(client.clone())
            .start()?;

        Ok(Self::new(
            relay_listener,
            client,
            auth_url.into(),
            GrantPopSigner::local(client_keypair),
            approval_key_secret,
        ))
    }

    /// Restore a pending delegated grant auth flow from browser state.
    #[doc(hidden)]
    pub fn restore_delegated(
        state: DelegatedGrantAuthFlowState,
        client: PubkyHttpClient,
        sign: DelegatedSignFn,
    ) -> Result<Self> {
        let DelegatedGrantAuthFlowState {
            authorization_url,
            key_id,
            client_pk,
            approval_key_secret,
        } = state;
        let auth_url = DeepLink::from_str(&authorization_url).map_err(|e| {
            AuthError::Validation(format!("failed to parse grant auth flow state URL: {e}"))
        })?;
        let (relay, relay_channel, expected_client_pk) = grant_deep_link_parts(&auth_url)?;
        let approval_key_secret = restore_approval_key_secret(relay_channel, approval_key_secret)?;

        if &client_pk != expected_client_pk {
            return Err(AuthError::Validation(
                "saved delegated grant auth flow client key does not match the deep link client public key"
                    .into(),
            )
            .into());
        }

        let relay_listener = AuthRelayListener::builder_for_channel(relay_channel)
            .relay_base_url(relay.clone())
            .client(client.clone())
            .start()?;

        Ok(Self::new(
            relay_listener,
            client,
            auth_url.into(),
            GrantPopSigner::delegated(key_id, client_pk, sign),
            approval_key_secret,
        ))
    }

    /// Block until the signer approves and return a ready-to-use
    /// [`PubkySession`].
    ///
    /// Composes [`await_credential`](Self::await_credential) +
    /// [`PubkySession::from_grant_credential`]. Use
    /// [`await_credential`](Self::await_credential) directly if you need to
    /// inspect or persist the credential before building a session.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Authentication`] if the relay channel
    ///   expires before approval.
    /// - Propagates HTTP/transport failures while polling the relay or
    ///   exchanging the grant for a bearer.
    /// - Returns [`crate::errors::Error::Authentication`] if the issuer's
    ///   homeserver cannot be resolved via PKARR (sign-in only).
    pub async fn await_approval(self) -> Result<PubkySession> {
        let client = self.client.clone();
        let credential = self.await_credential().await?;
        Ok(PubkySession::from_grant_credential(client, credential))
    }

    /// Block until the signer approves and the homeserver issues a
    /// [`GrantCredential`].
    ///
    /// The credential can be inspected, persisted, or lifted into a full
    /// [`PubkySession`] via [`PubkySession::from_grant_credential`].
    ///
    /// # Errors
    /// - See [`await_approval`](Self::await_approval).
    pub async fn await_credential(self) -> Result<GrantCredential> {
        let Self {
            relay_listener,
            client,
            client_signer,
            auth_url,
            approval_key_secret,
        } = self;
        let approval =
            Self::await_decoded_approval(relay_listener, &auth_url, approval_key_secret.as_ref())
                .await?;
        Self::exchange_for_credential(&client, approval, client_signer).await
    }

    /// Non-blocking probe (single step) that **consumes any ready grant** and
    /// returns:
    /// - `Ok(Some(session))` when a grant was delivered and the session was
    ///   established at the homeserver.
    /// - `Ok(None)` if no payload yet (keep polling later).
    /// - `Err(e)` on transport/server errors or if the channel expired.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error::Authentication`] if the relay channel
    ///   expired before a grant arrived.
    /// - Propagates HTTP/transport failures from establishing the session.
    pub async fn try_poll_once(&self) -> Result<Option<PubkySession>> {
        let Some(credential) = self.try_poll_credential_once().await? else {
            return Ok(None);
        };
        Ok(Some(PubkySession::from_grant_credential(
            self.client.clone(),
            credential,
        )))
    }

    /// Non-blocking variant of [`await_credential`](Self::await_credential).
    ///
    /// Returns `Ok(Some(credential))` when a grant has been delivered and
    /// the homeserver has issued a credential; `Ok(None)` if no payload yet;
    /// `Err` on transport/server errors.
    ///
    /// # Errors
    /// - See [`try_poll_once`](Self::try_poll_once).
    pub async fn try_poll_credential_once(&self) -> Result<Option<GrantCredential>> {
        let Some(approval) = self.try_decoded_approval()? else {
            return Ok(None);
        };
        let credential =
            Self::exchange_for_credential(&self.client, approval, self.client_signer.clone())
                .await?;
        Ok(Some(credential))
    }

    async fn exchange_for_credential(
        client: &PubkyHttpClient,
        approval: GrantApproval,
        client_signer: GrantPopSigner,
    ) -> Result<GrantCredential> {
        let GrantApproval {
            grant_jws,
            claims,
            verified_approval,
        } = approval;

        let pkdns = Pkdns::with_client(client.clone());
        let hs_pk = pkdns.require_homeserver_of(&claims.iss).await?;
        let mut credential =
            credential_from_grant_exchange(client, grant_jws, claims, client_signer, hs_pk).await?;
        credential.retain_verified_approval(verified_approval);
        Ok(credential)
    }

    async fn await_decoded_approval(
        relay_listener: AuthRelayListener,
        auth_url: &Url,
        approval_key_secret: Option<&ApprovalRecipientSecret>,
    ) -> Result<GrantApproval> {
        let message = relay_listener.await_message().await?;
        decode_relay_approval(&message, auth_url, approval_key_secret)
    }

    fn try_decoded_approval(&self) -> Result<Option<GrantApproval>> {
        let Some(message) = self.relay_listener.try_message() else {
            return Ok(None);
        };
        Ok(Some(decode_relay_approval(
            &message?,
            &self.auth_url,
            self.approval_key_secret.as_ref(),
        )?))
    }
}

fn decode_relay_approval(
    message: &AuthRelayMessage,
    auth_url: &Url,
    approval_key_secret: Option<&ApprovalRecipientSecret>,
) -> Result<GrantApproval> {
    let request = DeepLink::from_str(auth_url.as_str())
        .map_err(|_err| AuthError::Validation("invalid grant request URL".into()))?;
    decode_and_validate_approval(message, &request, approval_key_secret)
}

/// Authenticate a received approval, then bind it to the pending app request.
fn decode_and_validate_approval(
    message: &AuthRelayMessage,
    request: &DeepLink,
    approval_key_secret: Option<&ApprovalRecipientSecret>,
) -> Result<GrantApproval> {
    let (client_id, client_pk, capabilities, format, relay_channel) = match request {
        DeepLink::SigninGrant(link) => {
            let params = link.params();
            (
                &params.client_id,
                &params.client_pk,
                &params.capabilities,
                params.approval_format,
                params.relay_channel,
            )
        }
        DeepLink::SignupGrant(link) => {
            let params = link.params();
            (
                &params.client_id,
                &params.client_pk,
                &params.capabilities,
                params.approval_format,
                params.relay_channel,
            )
        }
        _ => {
            return Err(
                AuthError::Validation("approval requires a grant auth deep link".into()).into(),
            );
        }
    };
    validate_approval_key(relay_channel, approval_key_secret)?;
    let decrypted;
    let message = if let Some(secret) = approval_key_secret {
        decrypted = AuthRelayMessage::from_zeroizing(secret.open(message.as_bytes())?);
        &decrypted
    } else {
        message
    };
    let approval = GrantApproval::decode(message, format)?;
    if &approval.claims.cnf != client_pk || &approval.claims.client_id != client_id {
        return Err(AuthError::Validation(
            "approved grant does not match the requesting client".into(),
        )
        .into());
    }
    // The homeserver decides expiry using its own clock during exchange.
    // A different app clock must not reject a grant the homeserver can accept.
    if approval.claims.iat >= approval.claims.exp {
        return Err(AuthError::Validation("approved grant has invalid timestamps".into()).into());
    }
    // Signers may narrow scopes or actions. Each approved action must be
    // covered by a requested capability, including split read/write requests.
    for approved in &approval.claims.caps {
        for action in approved.actions() {
            if !capabilities.iter().any(|requested| {
                requested.scope_covers_path(approved.scope())
                    && requested.actions().contains(action)
            }) {
                return Err(AuthError::Validation(
                    "approved capabilities exceed the pending request".into(),
                )
                .into());
            }
        }
    }
    Ok(approval)
}

fn grant_deep_link_parts(deep_link: &DeepLink) -> Result<(&Url, GrantRelayChannel, &PublicKey)> {
    match deep_link {
        DeepLink::SigninGrant(link) => Ok((
            &link.params().relay,
            link.params().relay_channel,
            &link.params().client_pk,
        )),
        DeepLink::SignupGrant(link) => Ok((
            &link.params().relay,
            link.params().relay_channel,
            &link.params().client_pk,
        )),
        _ => Err(AuthError::Validation(
            "saved grant auth flow state must contain a grant signin or signup deep link".into(),
        )
        .into()),
    }
}

fn restore_approval_key_secret(
    channel: GrantRelayChannel,
    secret: Option<[u8; 32]>,
) -> Result<Option<ApprovalRecipientSecret>> {
    let secret = secret.map(ApprovalRecipientSecret::from_bytes);
    validate_approval_key(channel, secret.as_ref())?;
    Ok(secret)
}

/// The recipient secret must exist exactly when the request uses HPKE,
/// and must belong to the public key in that request.
fn validate_approval_key(
    channel: GrantRelayChannel,
    secret: Option<&ApprovalRecipientSecret>,
) -> Result<()> {
    let error = match (channel, secret) {
        (GrantRelayChannel::SharedSecret(_), None) => return Ok(()),
        (GrantRelayChannel::SharedSecret(_), Some(_)) => {
            "saved HPKE key has no matching grant request"
        }
        (GrantRelayChannel::Hpke { .. }, None) => "saved grant auth flow is missing its HPKE key",
        (
            GrantRelayChannel::Hpke {
                ephemeral_public_key,
            },
            Some(secret),
        ) => {
            if secret.matches_public_key(&ephemeral_public_key) {
                return Ok(());
            }
            "saved HPKE key does not match the grant request"
        }
    };
    Err(AuthError::Validation(error.into()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actors::auth::deep_links::{
        DeepLinkScheme, GrantApprovalFormat, SigninDeepLink, SigninGrantDeepLink,
        SigninGrantParams, SigninParams, XCallbackParams,
    };
    use crate::actors::auth::grant::approval_encryption;

    use super::super::{approval_envelope::GrantApprovalEnvelope, credential::now_unix};
    use pubky_common::{
        auth::{grant::GrantClaims, jws::GrantId},
        capabilities::Capability,
    };

    fn request(format: GrantApprovalFormat) -> SigninGrantParams {
        let relay_channel = match format {
            GrantApprovalFormat::BareGrant => GrantRelayChannel::SharedSecret([9; 32]),
            GrantApprovalFormat::SignedApprovalV1 => GrantRelayChannel::Hpke {
                ephemeral_public_key: ApprovalRecipientSecret::from_bytes([9; 32]).public_key(),
            },
        };
        SigninGrantParams {
            client_id: ClientId::new("test.app").unwrap(),
            client_pk: Keypair::from_secret(&[8; 32]).public_key(),
            capabilities: if format == GrantApprovalFormat::SignedApprovalV1 {
                "/pub/app/:rwe".parse().unwrap()
            } else {
                "/pub/app/:rw".parse().unwrap()
            },
            relay: Url::parse("http://localhost/inbox").unwrap(),
            relay_channel,
            approval_format: format,
        }
    }

    fn claims(user: &Keypair) -> GrantClaims {
        let request = request(GrantApprovalFormat::SignedApprovalV1);
        GrantClaims {
            iss: user.public_key(),
            client_id: request.client_id,
            caps: request.capabilities.to_vec(),
            cnf: request.client_pk,
            jti: GrantId::generate(),
            iat: now_unix(),
            exp: now_unix() + 3600,
        }
    }

    fn message(user: &Keypair, claims: &GrantClaims) -> AuthRelayMessage {
        AuthRelayMessage::new(
            GrantApprovalEnvelope::sign(user, claims)
                .as_bytes()
                .to_vec(),
        )
    }

    fn decode_request(
        message: &AuthRelayMessage,
        request: &SigninGrantParams,
    ) -> Result<GrantApproval> {
        let deep_link = DeepLink::SigninGrant(SigninGrantDeepLink::new(
            DeepLinkScheme::PubkyAuth,
            request.clone(),
        ));
        match request.relay_channel {
            GrantRelayChannel::SharedSecret(_) => {
                decode_and_validate_approval(message, &deep_link, None)
            }
            GrantRelayChannel::Hpke { .. } => {
                let recipient = ApprovalRecipientSecret::from_bytes([9; 32]);
                let ciphertext =
                    approval_encryption::seal(&recipient.public_key(), message.as_bytes())?;
                let encrypted = AuthRelayMessage::new(ciphertext);
                decode_and_validate_approval(&encrypted, &deep_link, Some(&recipient))
            }
        }
    }

    fn decode_signed_approval(message: &AuthRelayMessage) -> Result<GrantApproval> {
        decode_request(message, &request(GrantApprovalFormat::SignedApprovalV1))
    }

    #[test]
    fn key_requests_reject_bare_grant_responses() {
        let user = Keypair::random();
        let claims = claims(&user);
        let bare = AuthRelayMessage::new(
            claims
                .sign(&user, pubky_common::auth::jws::GRANT_JWS_TYP)
                .into_bytes(),
        );
        assert!(decode_signed_approval(&bare).is_err());
    }

    #[test]
    fn signer_may_decline_keys_but_cannot_expand_key_scopes() {
        let user = Keypair::random();
        let mut request = request(GrantApprovalFormat::SignedApprovalV1);
        request.capabilities = "/:rw,/pub/chat/:e".parse().unwrap();
        let mut claims = claims(&user);
        claims.caps = "/:rw".parse::<Capabilities>().unwrap().to_vec();
        let approval = decode_request(&message(&user, &claims), &request).unwrap();
        assert_eq!(
            approval
                .verified_approval
                .unwrap()
                .encryption_keys
                .scopes()
                .len(),
            0
        );

        claims.caps = "/:rwe".parse::<Capabilities>().unwrap().to_vec();
        decode_request(&message(&user, &claims), &request).unwrap_err();
    }

    #[test]
    fn approvals_reject_client_scope_action_and_timestamp_mismatches() {
        let user = Keypair::random();
        let original = claims(&user);
        for (label, changed) in [
            (
                "client id",
                GrantClaims {
                    client_id: ClientId::new("other.app").unwrap(),
                    ..original.clone()
                },
            ),
            (
                "client key",
                GrantClaims {
                    cnf: Keypair::random().public_key(),
                    ..original.clone()
                },
            ),
            (
                "broader scope",
                GrantClaims {
                    caps: vec![Capability::root()],
                    ..original.clone()
                },
            ),
            (
                "sibling scope",
                GrantClaims {
                    caps: vec![Capability::read("/pub/app-evil/").unwrap()],
                    ..original.clone()
                },
            ),
            (
                "invalid timestamps",
                GrantClaims {
                    iat: original.exp,
                    ..original.clone()
                },
            ),
        ] {
            assert!(
                decode_signed_approval(&message(&user, &changed)).is_err(),
                "{label}"
            );
        }
        let mut read_only = request(GrantApprovalFormat::SignedApprovalV1);
        read_only.capabilities = Capabilities::from(vec![Capability::read("/pub/app/").unwrap()]);
        decode_request(&message(&user, &original), &read_only).unwrap_err();
    }

    #[test]
    fn approval_expiry_is_left_to_the_homeserver() {
        let user = Keypair::random();
        let now = now_unix();
        for format in [
            GrantApprovalFormat::BareGrant,
            GrantApprovalFormat::SignedApprovalV1,
        ] {
            let request = request(format);
            // Both past and future timestamps can disagree with the app clock.
            for (iat, exp) in [(1, 2), (now + 3600, now + 7200)] {
                let claims = GrantClaims {
                    caps: request.capabilities.to_vec(),
                    iat,
                    exp,
                    ..claims(&user)
                };
                let message = match format {
                    GrantApprovalFormat::BareGrant => AuthRelayMessage::new(
                        claims
                            .sign(&user, pubky_common::auth::jws::GRANT_JWS_TYP)
                            .into_bytes(),
                    ),
                    GrantApprovalFormat::SignedApprovalV1 => message(&user, &claims),
                };
                let approval = decode_request(&message, &request).unwrap();
                assert_eq!(approval.claims, claims);
            }
        }
    }

    #[test]
    fn narrowed_and_empty_approvals_are_valid() {
        let user = Keypair::random();
        for caps in [vec!["/pub/app/file:re".parse().unwrap()], vec![]] {
            let claims = GrantClaims {
                caps,
                ..claims(&user)
            };
            let approval = decode_signed_approval(&message(&user, &claims)).unwrap();
            assert_eq!(
                approval
                    .verified_approval
                    .unwrap()
                    .encryption_keys
                    .scopes()
                    .len(),
                claims.caps.len()
            );
        }
        let mut split_request = request(GrantApprovalFormat::SignedApprovalV1);
        split_request.capabilities = Capabilities::from(vec![
            Capability::read("/pub/app/").unwrap(),
            Capability::write("/pub/app/").unwrap(),
            Capability::encryption_keys("/pub/app/").unwrap(),
        ]);
        decode_request(&message(&user, &claims(&user)), &split_request).unwrap();
    }

    #[tokio::test]
    async fn builder_requires_signed_approval_for_key_requests() {
        let caps = "/pub/app/:rwe".parse().unwrap();
        let rejected = PubkyGrantAuthFlow::builder(
            &caps,
            AuthFlowKind::signin(),
            ClientId::new("test.app").unwrap(),
        )
        .start();
        assert!(rejected.unwrap_err().to_string().contains("af=v1"));
        let relay = http_relay::HttpRelay::builder()
            .http_port(0)
            .run()
            .await
            .unwrap();
        for kind in [
            AuthFlowKind::signin(),
            AuthFlowKind::signup(Keypair::random().public_key(), None),
        ] {
            let flow = PubkyGrantAuthFlow::builder(&caps, kind, ClientId::new("test.app").unwrap())
                .approval_format(GrantApprovalFormat::SignedApprovalV1)
                .relay(relay.local_url().join("inbox").unwrap())
                .start()
                .unwrap();
            let url = flow.authorization_url();
            assert!(!url.query_pairs().any(|(name, _)| name == "secret"));
            assert!(
                url.query_pairs()
                    .any(|(name, value)| name == "af" && value == "v1")
            );
            assert!(
                url.query_pairs()
                    .any(|(name, value)| name == "epk" && !value.is_empty())
            );
            assert!(flow.save_local().unwrap().approval_key_secret.is_some());
        }
    }

    #[tokio::test]
    async fn oversized_approvals_return_413_to_the_signer_without_reaching_the_app() {
        use crate::{Error, Pubky, errors::RequestError};
        use std::time::Duration;

        let relay = http_relay::HttpRelay::builder()
            .http_port(0)
            .run()
            .await
            .unwrap();
        let client = PubkyHttpClient::new().unwrap();
        let signer = Pubky::with_client(client.clone()).signer(Keypair::random());
        let mut capabilities = Capabilities::builder();
        for index in 0..32 {
            capabilities = capabilities
                .encryption_keys(format!("/pub/app{index}.example/"))
                .unwrap();
        }
        let capabilities = capabilities.finish();

        for relay_path in ["link", "inbox"] {
            let flow = PubkyGrantAuthFlow::builder(
                &capabilities,
                AuthFlowKind::signin(),
                ClientId::new("oversized.test").unwrap(),
            )
            .approval_format(GrantApprovalFormat::SignedApprovalV1)
            .relay(relay.local_url().join(relay_path).unwrap())
            .client(client.clone())
            .start()
            .unwrap();

            let error = tokio::time::timeout(
                Duration::from_secs(5),
                signer.approve_auth(flow.authorization_url()),
            )
            .await
            .expect("the signer POST must finish within the test deadline")
            .unwrap_err();
            assert!(
                matches!(error, Error::Request(RequestError::Server { status, .. })
                    if status == reqwest::StatusCode::PAYLOAD_TOO_LARGE),
                "{relay_path}: {error}"
            );

            // Observe relay delivery directly, before any homeserver exchange.
            // Bound the wait because the rejected POST never delivers a message.
            let received = tokio::time::timeout(
                Duration::from_millis(250),
                flow.relay_listener.await_message(),
            )
            .await;
            assert!(received.is_err(), "{relay_path}: the app must keep waiting");
        }
    }

    #[tokio::test]
    async fn save_restore_round_trips_authorization_url() {
        let relay = http_relay::HttpRelay::builder()
            .http_port(0)
            .run()
            .await
            .unwrap();
        let relay_url = relay.local_url().join("inbox").unwrap();
        let client = PubkyHttpClient::new().unwrap();
        let client_id = ClientId::new("save-restore.test").unwrap();
        let x_callback = XCallbackParams {
            x_success: Some("bitkit://auth/success?nonce=resume-grant".into()),
            ..XCallbackParams::default()
        };
        let flow = PubkyGrantAuthFlow::builder(
            &"/pub/app/:rwe".parse().unwrap(),
            AuthFlowKind::signin(),
            client_id,
        )
        .approval_format(GrantApprovalFormat::SignedApprovalV1)
        .relay(relay_url)
        .client(client.clone())
        .x_callback(x_callback.clone())
        .start()
        .unwrap();

        let restored = PubkyGrantAuthFlow::restore(flow.save_local().unwrap(), client).unwrap();

        assert_eq!(restored.authorization_url(), flow.authorization_url());
        let user = Keypair::random();
        let claims = pubky_common::auth::grant::GrantClaims {
            iss: user.public_key(),
            client_id: ClientId::new("save-restore.test").unwrap(),
            caps: vec![],
            cnf: flow.client_signer.public_key(),
            jti: pubky_common::auth::jws::GrantId::generate(),
            iat: super::super::credential::now_unix(),
            exp: super::super::credential::now_unix() + 3600,
        };
        let signed_approval =
            super::super::approval_envelope::GrantApprovalEnvelope::sign(&user, &claims);
        let request = DeepLink::from_str(restored.authorization_url().as_str()).unwrap();
        let public_key = match &request {
            DeepLink::SigninGrant(link) => match link.params().relay_channel {
                GrantRelayChannel::Hpke {
                    ephemeral_public_key,
                } => ephemeral_public_key,
                GrantRelayChannel::SharedSecret(_) => unreachable!(),
            },
            _ => unreachable!(),
        };
        let encrypted_approval =
            super::super::approval_encryption::seal(&public_key, signed_approval.as_bytes())
                .unwrap();
        let message = crate::actors::auth::relay::AuthRelayMessage::new(encrypted_approval);
        decode_and_validate_approval(&message, &request, restored.approval_key_secret.as_ref())
            .unwrap();
        let legacy_message =
            crate::actors::auth::relay::AuthRelayMessage::new(signed_approval.as_bytes().to_vec());
        assert!(
            decode_and_validate_approval(
                &legacy_message,
                &request,
                restored.approval_key_secret.as_ref(),
            )
            .is_err()
        );
        assert_eq!(
            DeepLink::from_str(restored.authorization_url().as_str())
                .unwrap()
                .x_callback(),
            &x_callback
        );
    }

    #[tokio::test]
    async fn save_local_is_only_available_for_local_signers() {
        let relay = http_relay::HttpRelay::builder()
            .http_port(0)
            .run()
            .await
            .unwrap();
        let relay_url = relay.local_url().join("inbox").unwrap();
        let keypair = Keypair::random();
        let delegated_signer = std::sync::Arc::new(|_| Box::pin(async { Ok(vec![0_u8; 64]) }) as _);
        let client_id = ClientId::new("save-local.test").unwrap();

        let local_flow = PubkyGrantAuthFlow::builder(
            &Capabilities::default(),
            AuthFlowKind::signin(),
            client_id.clone(),
        )
        .relay(relay_url.clone())
        .client_keypair(keypair.clone())
        .start()
        .unwrap();
        let delegated_flow = PubkyGrantAuthFlow::builder(
            &Capabilities::default(),
            AuthFlowKind::signin(),
            client_id,
        )
        .relay(relay_url)
        .delegated_client_signer("key-1".into(), keypair.public_key(), delegated_signer)
        .start()
        .unwrap();

        assert_eq!(
            local_flow.save_local().unwrap().client_key_secret,
            keypair.secret()
        );
        assert!(delegated_flow.save_local().is_none());
        assert!(delegated_flow.save_delegated().is_some());
    }

    #[tokio::test]
    async fn signup_builder_attaches_x_callback_metadata() {
        let relay = http_relay::HttpRelay::builder()
            .http_port(0)
            .run()
            .await
            .unwrap();
        let x_callback = XCallbackParams {
            x_success: Some("bitkit://signup/success?nonce=grant-signup".into()),
            ..XCallbackParams::default()
        };
        let flow = PubkyGrantAuthFlow::builder(
            &Capabilities::default(),
            AuthFlowKind::signup(Keypair::random().public_key(), Some("signup-token".into())),
            ClientId::new("grant-signup-callback.test").unwrap(),
        )
        .relay(relay.local_url().join("inbox").unwrap())
        .x_callback(x_callback.clone())
        .start()
        .unwrap();

        let deep_link = DeepLink::from_str(flow.authorization_url().as_str()).unwrap();
        assert!(matches!(&deep_link, DeepLink::SignupGrant(_)));
        assert_eq!(deep_link.x_callback(), &x_callback);
    }

    #[tokio::test]
    async fn delegated_save_restore_preserves_x_callback_metadata() {
        let relay = http_relay::HttpRelay::builder()
            .http_port(0)
            .run()
            .await
            .unwrap();
        let client = PubkyHttpClient::new().unwrap();
        let keypair = Keypair::random();
        let sign: DelegatedSignFn =
            std::sync::Arc::new(|_| Box::pin(async { Ok(vec![0_u8; 64]) }) as _);
        let x_callback = XCallbackParams {
            x_success: Some("bitkit://auth/success?nonce=delegated".into()),
            ..XCallbackParams::default()
        };
        let flow = PubkyGrantAuthFlow::builder(
            &Capabilities::default(),
            AuthFlowKind::signin(),
            ClientId::new("delegated-callback.test").unwrap(),
        )
        .relay(relay.local_url().join("inbox").unwrap())
        .delegated_client_signer(
            "key-1".into(),
            keypair.public_key(),
            std::sync::Arc::clone(&sign),
        )
        .x_callback(x_callback.clone())
        .start()
        .unwrap();

        let restored =
            PubkyGrantAuthFlow::restore_delegated(flow.save_delegated().unwrap(), client, sign)
                .unwrap();

        assert_eq!(restored.authorization_url(), flow.authorization_url());
        assert_eq!(
            DeepLink::from_str(restored.authorization_url().as_str())
                .unwrap()
                .x_callback(),
            &x_callback
        );
    }

    #[test]
    fn restore_rejects_cookie_auth_url() {
        let auth_url = SigninDeepLink::new(
            DeepLinkScheme::PubkyAuth,
            SigninParams {
                capabilities: Capabilities::default(),
                relay: Url::parse("http://localhost/inbox").unwrap(),
                secret: [7; 32],
            },
        )
        .to_string();
        let state = GrantAuthFlowState {
            authorization_url: auth_url,
            client_key_secret: Keypair::random().secret(),
            approval_key_secret: None,
        };

        let error = PubkyGrantAuthFlow::restore(state, PubkyHttpClient::new().unwrap())
            .unwrap_err()
            .to_string();

        assert!(error.contains("grant signin or signup deep link"));
    }

    #[test]
    fn restore_rejects_mismatched_client_key() {
        let expected_client = Keypair::random();
        let actual_client = Keypair::random();
        let auth_url = SigninGrantDeepLink::new(
            DeepLinkScheme::PubkyAuth,
            SigninGrantParams {
                capabilities: Capabilities::default(),
                relay: Url::parse("http://localhost/inbox").unwrap(),
                relay_channel: GrantRelayChannel::SharedSecret([7; 32]),
                client_id: ClientId::new("mismatch.test").unwrap(),
                client_pk: expected_client.public_key(),
                approval_format: GrantApprovalFormat::BareGrant,
            },
        )
        .to_string();
        let state = GrantAuthFlowState {
            authorization_url: auth_url,
            client_key_secret: actual_client.secret(),
            approval_key_secret: None,
        };

        let error = PubkyGrantAuthFlow::restore(state, PubkyHttpClient::new().unwrap())
            .unwrap_err()
            .to_string();

        assert!(error.contains("does not match"));
    }

    #[cfg(feature = "json")]
    #[test]
    fn state_serializes_round_trip() {
        let state = GrantAuthFlowState {
            authorization_url: "pubkyauth://signin?caps=&relay=http://localhost/inbox".into(),
            client_key_secret: [42; 32],
            approval_key_secret: None,
        };

        let json = serde_json::to_string(&state).unwrap();
        let restored: GrantAuthFlowState = serde_json::from_str(&json).unwrap();

        assert_eq!(restored, state);
    }
}
