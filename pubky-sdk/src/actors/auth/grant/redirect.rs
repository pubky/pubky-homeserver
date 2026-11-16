//! Redirect sign-in through a parent grant holder, such as Pubky Accounts.

use std::{fmt, str::FromStr, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::{
    auth::{
        grant::{GrantClaims, caps_within, is_exact_callback, parent_grant_ceiling},
        jws::ClientId,
    },
    crypto::{Keypair, PublicKey, random_bytes},
};
use url::{Url, form_urlencoded};
use zeroize::Zeroizing;

use super::{
    approval::{ChildApproval, VerifiedApproval},
    approval_encryption::ApprovalRecipientSecret,
    credential::{GrantChain, GrantCredential, now_unix},
    grant_exchange::credential_from_grant_exchange,
    pop_signer::{DelegatedSignFn, GrantPopSigner},
};
use crate::{
    Capabilities, PubkyHttpClient, PubkySession,
    actors::{Pkdns, auth::deep_links::ChildGrantRequest},
    errors::{AuthError, RedirectDenial, Result},
};

/// How long a pending request accepts its callback, unless the builder sets another.
pub const DEFAULT_REDIRECT_FLOW_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// The longest a pending request may wait for its callback.
const MAX_REDIRECT_FLOW_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// The largest callback fragment accepted. Approvals are far smaller.
const MAX_CALLBACK_FRAGMENT_BYTES: usize = 16 * 1024;

/// Query parameters the request adds to the Accounts URL.
const REQUEST_PARAMETERS: [&str; 5] = ["cid", "caps", "cpk", "epk", "state"];

fn invalid(message: &str) -> crate::Error {
    AuthError::Validation(message.to_owned()).into()
}

/// Builder for a [`PubkyRedirectAuthFlow`].
#[derive(Clone)]
pub struct RedirectAuthFlowBuilder {
    caps: Capabilities,
    callback: ClientId,
    accounts_url: Url,
    client: Option<PubkyHttpClient>,
    client_signer: GrantPopSigner,
    lifetime: Duration,
}

impl fmt::Debug for RedirectAuthFlowBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedirectAuthFlowBuilder")
            .field("caps", &self.caps)
            .field("callback", &self.callback)
            .field("accounts_url", &self.accounts_url)
            .field("client_signer", &self.client_signer)
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

impl RedirectAuthFlowBuilder {
    /// Provide a custom `PubkyHttpClient`, for example one wired to a testnet.
    #[must_use]
    pub fn client(mut self, client: PubkyHttpClient) -> Self {
        self.client = Some(client);
        self
    }

    /// Pin the keypair that the child grant's `cnf` binds. Defaults to a fresh key.
    #[must_use]
    pub fn client_keypair(mut self, keypair: Keypair) -> Self {
        self.client_signer = GrantPopSigner::local(keypair);
        self
    }

    /// How long the request accepts its callback. Defaults to
    /// [`DEFAULT_REDIRECT_FLOW_LIFETIME`], and can't exceed one hour.
    #[must_use]
    pub const fn lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Use a signing key held outside the SDK, such as a browser `CryptoKey`.
    #[must_use]
    #[doc(hidden)]
    pub fn delegated_client_signer(
        mut self,
        key_id: String,
        public_key: PublicKey,
        sign: DelegatedSignFn,
    ) -> Self {
        self.client_signer = GrantPopSigner::delegated(key_id, public_key, sign);
        self
    }

    /// Generate the request's single-use state and temporary HPKE key.
    ///
    /// # Errors
    /// Returns [`AuthError::Validation`] if the callback isn't an exact HTTPS URL,
    /// the Accounts URL isn't HTTPS, has credentials or a fragment, or already
    /// carries a request parameter, the capabilities reach beyond `/pub/` and
    /// `/priv/`, or the lifetime is zero or over an hour.
    pub fn start(self) -> Result<PubkyRedirectAuthFlow> {
        let Self {
            caps,
            callback,
            accounts_url,
            client,
            client_signer,
            lifetime,
        } = self;
        if !is_exact_callback(&callback) {
            return Err(invalid(
                "the callback must be an exact HTTPS URL without credentials or a fragment",
            ));
        }
        validate_accounts_url(&accounts_url)?;
        // Children can't exceed a parent, and no parent exceeds this ceiling.
        if !caps_within(&parent_grant_ceiling(), caps.as_slice()) {
            return Err(invalid(
                "redirect sign-in can only request capabilities under /pub/ and /priv/",
            ));
        }
        if lifetime.is_zero() || lifetime > MAX_REDIRECT_FLOW_LIFETIME {
            return Err(invalid(
                "a redirect sign-in must last between one second and one hour",
            ));
        }
        let client = match client {
            Some(client) => client,
            None => PubkyHttpClient::new()?,
        };

        let (recipient, ephemeral_public_key) = ApprovalRecipientSecret::generate();
        let state = URL_SAFE_NO_PAD.encode(random_bytes::<32>());
        let request = ChildGrantRequest::new(
            caps,
            callback,
            client_signer.public_key(),
            ephemeral_public_key,
            state,
        );
        let created_at = now_unix();
        Ok(PubkyRedirectAuthFlow {
            client,
            authorization_url: request_url(&accounts_url, &request),
            request,
            client_signer,
            recipient,
            created_at,
            expires_at: created_at + lifetime.as_secs(),
        })
    }
}

fn validate_accounts_url(url: &Url) -> Result<()> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "the Accounts URL must be HTTPS, without credentials or a fragment",
        ));
    }
    if url
        .query_pairs()
        .any(|(key, _)| REQUEST_PARAMETERS.contains(&key.as_ref()))
    {
        return Err(invalid(
            "the Accounts URL can't set cid, caps, cpk, epk or state",
        ));
    }
    Ok(())
}

/// The Accounts URL with the request appended to its existing query.
fn request_url(accounts_url: &Url, request: &ChildGrantRequest) -> Url {
    let mut url = accounts_url.clone();
    url.query_pairs_mut()
        .append_pair("cid", request.callback().as_str())
        .append_pair("caps", &request.capabilities().to_string())
        .append_pair("cpk", &request.client_pk().z32())
        .append_pair(
            "epk",
            &URL_SAFE_NO_PAD.encode(request.ephemeral_public_key()),
        )
        .append_pair("state", request.state());
    url
}

/// Saved state of a pending redirect sign-in whose signing key the SDK holds.
///
/// Contains the signing key and the temporary HPKE key. Store it only until the
/// flow completes, expires or is cancelled, and keep it out of logs.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
pub struct RedirectAuthFlowState {
    /// The authorization URL, which records the request's parameters.
    pub authorization_url: String,
    /// Secret bytes of the signing key that the request's `cpk` names.
    pub client_key_secret: [u8; 32],
    /// The temporary HPKE secret for the request's `epk`.
    pub approval_key_secret: [u8; 32],
    /// When the request started, in Unix seconds.
    pub created_at: u64,
    /// When the request stops accepting its callback, in Unix seconds.
    pub expires_at: u64,
}

impl fmt::Debug for RedirectAuthFlowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedirectAuthFlowState")
            .field("authorization_url", &"<redacted>")
            .field("client_key_secret", &"<redacted>")
            .field("approval_key_secret", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Saved state of a pending redirect sign-in whose signing key is held outside
/// the SDK, such as a browser `CryptoKey`.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
pub struct DelegatedRedirectAuthFlowState {
    /// The authorization URL, which records the request's parameters.
    pub authorization_url: String,
    /// The id of the externally held signing key.
    pub key_id: String,
    /// The public key that the request's `cpk` names.
    pub client_pk: PublicKey,
    /// The temporary HPKE secret for the request's `epk`.
    pub approval_key_secret: [u8; 32],
    /// When the request started, in Unix seconds.
    pub created_at: u64,
    /// When the request stops accepting its callback, in Unix seconds.
    pub expires_at: u64,
}

impl fmt::Debug for DelegatedRedirectAuthFlowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelegatedRedirectAuthFlowState")
            .field("authorization_url", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("client_pk", &self.client_pk)
            .field("approval_key_secret", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A redirect sign-in using caller-provided Accounts and callback URLs.
/// Save its state before navigating; it contains secret keys.
pub struct PubkyRedirectAuthFlow {
    client: PubkyHttpClient,
    request: ChildGrantRequest,
    authorization_url: Url,
    client_signer: GrantPopSigner,
    recipient: ApprovalRecipientSecret,
    created_at: u64,
    expires_at: u64,
}

impl fmt::Debug for PubkyRedirectAuthFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PubkyRedirectAuthFlow")
            .field("callback", self.request.callback())
            .field("authorization_url", &"<redacted>")
            .field("client_signer", &self.client_signer)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl PubkyRedirectAuthFlow {
    /// Build a request for `caps`, answered at `callback` by the holder at `accounts_url`.
    ///
    /// `callback` must be the app's exact registered HTTPS callback: it becomes
    /// the child grant's `client_id`. Existing query parameters of `accounts_url`
    /// are kept.
    #[must_use]
    pub fn builder(
        caps: &Capabilities,
        callback: ClientId,
        accounts_url: Url,
    ) -> RedirectAuthFlowBuilder {
        RedirectAuthFlowBuilder {
            caps: caps.clone(),
            callback,
            accounts_url,
            client: None,
            client_signer: GrantPopSigner::local(Keypair::random()),
            lifetime: DEFAULT_REDIRECT_FLOW_LIFETIME,
        }
    }

    /// The URL to send the user to. It holds only public keys and request parameters.
    #[must_use]
    pub const fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    /// The app's exact callback, which becomes the child grant's `client_id`.
    #[must_use]
    pub const fn callback(&self) -> &ClientId {
        self.request.callback()
    }

    /// The requested capabilities.
    pub const fn capabilities(&self) -> &Capabilities {
        self.request.capabilities()
    }

    /// When the request started, in Unix seconds.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// When the request stops accepting its callback, in Unix seconds.
    ///
    /// An approval accepted before this time can still be exchanged after it.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Whether the request no longer accepts its callback.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        now_unix() >= self.expires_at
    }

    /// Save the state needed to finish this flow after a reload.
    ///
    /// Returns `None` when the signing key is held outside the SDK.
    #[must_use]
    pub fn save_local(&self) -> Option<RedirectAuthFlowState> {
        Some(RedirectAuthFlowState {
            authorization_url: self.authorization_url.to_string(),
            client_key_secret: self.client_signer.local_secret()?,
            approval_key_secret: self.recipient.to_bytes(),
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }

    /// Save the state of a flow whose signing key is held outside the SDK.
    #[must_use]
    pub fn save_delegated(&self) -> Option<DelegatedRedirectAuthFlowState> {
        let signer = self.client_signer.delegated_state()?;
        Some(DelegatedRedirectAuthFlowState {
            authorization_url: self.authorization_url.to_string(),
            key_id: signer.key_id,
            client_pk: signer.public_key,
            approval_key_secret: self.recipient.to_bytes(),
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }

    /// Restore a flow from [`Self::save_local`].
    ///
    /// # Errors
    /// Returns [`AuthError::Validation`] if the saved URL isn't a valid request or
    /// the saved keys don't match it.
    pub fn restore(state: RedirectAuthFlowState, client: PubkyHttpClient) -> Result<Self> {
        let RedirectAuthFlowState {
            authorization_url,
            client_key_secret,
            approval_key_secret,
            created_at,
            expires_at,
        } = state;
        let signer = GrantPopSigner::local(Keypair::from_secret(&client_key_secret));
        Self::from_saved(
            &authorization_url,
            signer,
            approval_key_secret,
            created_at,
            expires_at,
            client,
        )
    }

    /// Restore a flow from [`Self::save_delegated`].
    ///
    /// # Errors
    /// Fails like [`Self::restore`].
    #[doc(hidden)]
    pub fn restore_delegated(
        state: DelegatedRedirectAuthFlowState,
        client: PubkyHttpClient,
        sign: DelegatedSignFn,
    ) -> Result<Self> {
        let signer = GrantPopSigner::delegated(state.key_id, state.client_pk, sign);
        Self::from_saved(
            &state.authorization_url,
            signer,
            state.approval_key_secret,
            state.created_at,
            state.expires_at,
            client,
        )
    }

    fn from_saved(
        authorization_url: &str,
        client_signer: GrantPopSigner,
        approval_key_secret: [u8; 32],
        created_at: u64,
        expires_at: u64,
        client: PubkyHttpClient,
    ) -> Result<Self> {
        let authorization_url = Url::parse(authorization_url)
            .ok()
            .filter(|url| url.scheme() == "https")
            .ok_or_else(|| invalid("invalid saved redirect request"))?;
        let request = ChildGrantRequest::parse(&authorization_url)
            .map_err(|_error| invalid("invalid saved redirect request"))?;
        let recipient = ApprovalRecipientSecret::from_bytes(approval_key_secret);
        if &client_signer.public_key() != request.client_pk()
            || !recipient.matches_public_key(request.ephemeral_public_key())
            || created_at >= expires_at
        {
            return Err(invalid(
                "the saved redirect state doesn't match its request",
            ));
        }
        Ok(Self {
            client,
            request,
            authorization_url,
            client_signer,
            recipient,
            created_at,
            expires_at,
        })
    }

    /// Verify a callback and the child grant it delivers.
    ///
    /// Checks that the callback is this request's exact callback and carries its
    /// state, that the request hasn't expired, and then everything
    /// [`Self::accept_signed_approval`] checks. Nothing is consumed: a callback
    /// that fails these checks leaves the request able to accept the real one.
    ///
    /// # Errors
    /// - [`AuthError::RedirectDeclined`] if the holder declined the request.
    /// - [`AuthError::RequestExpired`] if the request has expired.
    /// - [`AuthError::Validation`] for any other mismatch or invalid approval.
    pub fn accept(&self, callback: &RedirectCallback) -> Result<ChildGrantApproval> {
        if callback.callback != self.request.callback().as_str() {
            return Err(invalid(
                "the callback URL doesn't match the pending sign-in",
            ));
        }
        if callback.state != self.request.state() {
            return Err(invalid(
                "the callback doesn't belong to the pending sign-in",
            ));
        }
        if self.is_expired() {
            return Err(AuthError::RequestExpired.into());
        }
        match &callback.response {
            RedirectResponse::Declined(denial) => Err(AuthError::RedirectDeclined(*denial).into()),
            RedirectResponse::Approved(sealed) => {
                let plain = self.recipient.open(sealed)?;
                let text = std::str::from_utf8(&plain)
                    .map_err(|_error| invalid("invalid approval encoding"))?;
                self.accept_signed_approval(text)
            }
        }
    }

    /// Verify a decrypted child approval against this request.
    ///
    /// Use it to resume from an approval saved with
    /// [`ChildGrantApproval::signed_approval`] after [`Self::accept`] returned it.
    /// It doesn't check the request's expiry, so a saved approval can still be
    /// exchanged.
    ///
    /// Verifies the parent, child and approval signatures, the chain's delegation
    /// rules, that the approval names this request's recipient key, state, signing
    /// key and callback, that the child stays within the requested capabilities,
    /// and that the keys cover exactly the child's `e` scopes.
    ///
    /// # Errors
    /// Returns [`AuthError::Validation`] if any check fails.
    pub fn accept_signed_approval(&self, signed_approval: &str) -> Result<ChildGrantApproval> {
        let approval = ChildApproval::decode(signed_approval)?;
        let child = &approval.child_claims.grant;
        let request = &self.request;
        if approval.recipient != URL_SAFE_NO_PAD.encode(request.ephemeral_public_key())
            || approval.state != request.state()
            || &child.cnf != request.client_pk()
            || &child.client_id != request.callback()
        {
            return Err(invalid("the approval doesn't match the pending sign-in"));
        }
        // Holders may narrow the request, never widen it.
        if !caps_within(request.capabilities(), &child.caps) {
            return Err(invalid("approved capabilities exceed the pending request"));
        }
        Ok(ChildGrantApproval(approval))
    }

    /// Exchange an accepted child grant for a session credential.
    ///
    /// Sends the public parent, the child and a fresh proof of possession. The
    /// homeserver never receives the approval or its keys. Repeating the exchange
    /// with the same approval, for example after a lost response, replaces the
    /// child's bearer instead of creating another child.
    ///
    /// # Errors
    /// - Rejects an approval that [`Self::accept`] returned for another request.
    /// - Propagates homeserver lookup, transport and server errors.
    /// - Returns [`AuthError::Validation`] if the session doesn't match the child.
    pub async fn exchange(&self, approval: &ChildGrantApproval) -> Result<GrantCredential> {
        let approval = &approval.0;
        let claims = approval.child_claims.grant.clone();
        if approval.state != self.request.state() || claims.cnf != self.client_signer.public_key() {
            return Err(invalid("the approval belongs to another sign-in"));
        }
        let homeserver = Pkdns::with_client(self.client.clone())
            .require_homeserver_of(&claims.iss)
            .await?;
        let mut credential = credential_from_grant_exchange(
            &self.client,
            approval.child_jws.clone(),
            claims,
            self.client_signer.clone(),
            homeserver,
            GrantChain::Child {
                parent_jws: approval.parent_jws.clone(),
            },
        )
        .await?;
        credential.retain_verified_approval(Some(VerifiedApproval {
            encryption_keys: approval.encryption_keys.clone(),
            signed_approval: approval.signed_approval.clone(),
        }));
        Ok(credential)
    }

    /// Parse, accept and exchange a callback in one step.
    ///
    /// # Errors
    /// Fails like [`RedirectCallback::parse`], [`Self::accept`] and [`Self::exchange`].
    pub async fn complete(self, callback_url: &Url) -> Result<PubkySession> {
        let approval = self.accept(&RedirectCallback::parse(callback_url)?)?;
        let credential = self.exchange(&approval).await?;
        Ok(PubkySession::from_grant_credential(self.client, credential))
    }
}

/// The response a parent grant holder put in the fragment of an app's callback.
///
/// Parsing checks only the format. [`PubkyRedirectAuthFlow::accept`] checks that
/// it belongs to the pending request.
pub struct RedirectCallback {
    callback: String,
    state: String,
    response: RedirectResponse,
}

enum RedirectResponse {
    Approved(Zeroizing<Vec<u8>>),
    Declined(RedirectDenial),
}

impl fmt::Debug for RedirectCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let response = match self.response {
            RedirectResponse::Approved(_) => "approved",
            RedirectResponse::Declined(denial) => denial.as_str(),
        };
        f.debug_struct("RedirectCallback")
            .field("callback", &self.callback)
            .field("response", &response)
            .finish_non_exhaustive()
    }
}

impl RedirectCallback {
    /// Parse the URL the holder redirected to, such as the page's location.
    ///
    /// The fragment must hold `state` and exactly one of `approval` or `error`,
    /// each once, and nothing else. `error` must be `access_denied`, `cancelled` or
    /// `insufficient_permissions`. Error messages never include the fragment.
    ///
    /// # Errors
    /// Returns [`AuthError::Validation`] for any other fragment.
    pub fn parse(url: &Url) -> Result<Self> {
        let fragment = url
            .fragment()
            .ok_or_else(|| invalid("the callback has no response"))?;
        if fragment.len() > MAX_CALLBACK_FRAGMENT_BYTES {
            return Err(invalid("the callback response is too large"));
        }
        let (mut approval, mut error, mut state) = (None, None, None);
        for (key, value) in form_urlencoded::parse(fragment.as_bytes()) {
            let slot = match key.as_ref() {
                "approval" => &mut approval,
                "error" => &mut error,
                "state" => &mut state,
                _ => return Err(invalid("the callback has an unknown parameter")),
            };
            if slot.replace(value.into_owned()).is_some() {
                return Err(invalid("the callback repeats a parameter"));
            }
        }
        let state = state
            .filter(|state| !state.is_empty() && state.len() <= 128)
            .ok_or_else(|| invalid("the callback has no valid state"))?;
        let response = match (approval, error) {
            (Some(sealed), None) => RedirectResponse::Approved(Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(sealed)
                    .map_err(|_error| invalid("invalid approval encoding"))?,
            )),
            (None, Some(code)) => RedirectResponse::Declined(
                RedirectDenial::from_str(&code)
                    .map_err(|()| invalid("the callback has an unknown error code"))?,
            ),
            _ => {
                return Err(invalid(
                    "the callback must hold either an approval or an error",
                ));
            }
        };
        let mut callback = url.clone();
        callback.set_fragment(None);
        Ok(Self {
            callback: callback.into(),
            state,
            response,
        })
    }

    /// The callback URL without its fragment.
    #[must_use]
    pub fn callback(&self) -> &str {
        &self.callback
    }

    /// Why the holder declined, or `None` for an approval.
    #[must_use]
    pub const fn denial(&self) -> Option<RedirectDenial> {
        match self.response {
            RedirectResponse::Approved(_) => None,
            RedirectResponse::Declined(denial) => Some(denial),
        }
    }
}

/// A child grant approval verified against its pending redirect request.
///
/// Holds the child's keys. Debug output leaves out the approval and keys.
#[derive(Clone)]
pub struct ChildGrantApproval(ChildApproval);

impl fmt::Debug for ChildGrantApproval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChildGrantApproval")
            .field("claims", &self.0.child_claims)
            .finish_non_exhaustive()
    }
}

impl ChildGrantApproval {
    /// The verified child grant's claims.
    #[must_use]
    pub const fn claims(&self) -> &GrantClaims {
        &self.0.child_claims.grant
    }

    /// The verified parent grant's claims.
    #[must_use]
    pub const fn parent_claims(&self) -> &GrantClaims {
        &self.0.parent_claims
    }

    /// The public child grant JWS.
    #[must_use]
    pub fn child_grant(&self) -> &str {
        &self.0.child_jws
    }

    /// The public parent grant JWS.
    #[must_use]
    pub fn parent_grant(&self) -> &str {
        &self.0.parent_jws
    }

    /// The confidential signed child approval. It contains the keys.
    ///
    /// Persist it to resume an interrupted exchange with
    /// [`PubkyRedirectAuthFlow::accept_signed_approval`]. Keep it out of logs and URLs.
    #[must_use]
    pub fn signed_approval(&self) -> &str {
        self.0.signed_approval.as_str()
    }
}

#[cfg(test)]
mod tests;
