//! Grant credential — grant + Proof-of-Possession + opaque session bearer.
//!
//! This is the **default** session credential. A user-signed grant JWS is
//! exchanged at the homeserver for a short-lived opaque bearer and a session
//! record. The SDK refreshes the bearer transparently using the stored grant
//! and a fresh `PoP` proof.

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::{
    auth::{
        grant::GrantClaims,
        grant_session_responses::{GrantSessionInfo, GrantSessionResponse},
        jws::{POP_JWS_TYP, PopNonce},
        pop::PopProofClaims,
    },
    crypto::{Keypair, PublicKey},
    encryption_keys::ScopedEncryptionKeyBundle,
};

use reqwest::{Method, RequestBuilder, StatusCode};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::{
    approval::{GrantApproval, SignedApproval, VerifiedApproval},
    grant_exchange::{credential_from_grant_exchange, post_grant_session},
    pop_signer::{DelegatedSignFn, GrantPopSigner},
    shared_session::GrantSessionCoordinator,
};
use crate::actors::session::core::PubkySession;
use crate::actors::session::credential::{SessionCredential, credential_session_missing};
use crate::{
    PubkyHttpClient,
    actors::session::SessionInfo,
    cross_log,
    errors::{AuthError, Error, RequestError, Result},
};

/// Refresh the bearer proactively when it has less than this many seconds left.
pub(crate) const REFRESH_SLACK_SECS: u64 = 300;

const GRANT_SESSION_PATH: &str = "/auth/grant/session";
const STORED_GRANT_CREDENTIAL_PREFIX: &str = "pubky-grant-credential-v1";
const STORED_GRANT_CREDENTIAL_APPROVAL_PREFIX: &str = "pubky-grant-credential-v2";
const STORED_GRANT_CREDENTIAL_PREFIX_FAMILY: &str = "pubky-grant-credential-";

/// Current Unix timestamp in seconds, cross-target.
pub(crate) fn now_unix() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .expect("System time duration_since should always valid")
}

/// Mutable grant credential state. Always wrapped in `Arc<Mutex<...>>`.
///
/// Refresh paths take the mutex and hold it across the HTTP call so
/// concurrent refreshes don't run into a race condition.
#[derive(Debug)]
pub(crate) struct GrantCredentialState {
    /// Current opaque bearer token (homeserver-issued).
    pub bearer: String,
    /// The grant JWS used to mint this and future bearers (refresh material).
    pub grant_jws: String,
    /// Decoded grant claims — exposes `iss`, `client_id`, `cnf`, `jti`, …
    pub grant_claims: GrantClaims,
    /// `PoP` signer bound to the grant's `cnf` claim. Signs refresh proofs.
    pub client_signer: GrantPopSigner,
    /// Homeserver public key (`PoP` audience).
    pub homeserver_pk: PublicKey,
    /// Latest server-reported session metadata.
    pub session: GrantSessionInfo,
    pub coordinator: Option<Arc<dyn GrantSessionCoordinator>>,
}

impl GrantCredentialState {
    pub(super) fn needs_refresh(&self, now: u64, slack: u64) -> bool {
        // Refresh cannot extend a valid bearer that already reaches grant expiry.
        self.session.token_expires_at <= now
            || (self.session.token_expires_at < self.grant_claims.exp
                && self.session.token_expires_at.saturating_sub(slack) <= now)
    }
}

/// Cheap-to-clone grant credential. The mutable token state is shared across
/// clones via `Arc<Mutex<…>>` so every `PubkySession` clone observes the
/// same refreshes. Session info is derived from the immutable grant and
/// never changes.
#[derive(Clone, Debug)]
pub struct GrantCredential {
    pub(crate) state: Arc<Mutex<GrantCredentialState>>,
    pub(crate) info: SessionInfo,
    /// None for bare grants; Some for signed approvals, even with no `e` scopes.
    /// Retaining an empty bundle preserves the approval format during export.
    verified_approval: Option<Arc<VerifiedApproval>>,
}

/// Validated restore inputs, including keys verified against the stored grant.
#[derive(Debug)]
struct GrantRestoreMaterial {
    grant_jws: String,
    grant_claims: GrantClaims,
    client_signer: GrantPopSigner,
    homeserver_pk: PublicKey,
    verified_approval: Option<VerifiedApproval>,
}

/// Durable refresh material for restoring a grant-backed session.
///
/// Portable restore material without a bearer or cached session metadata.
/// Generic restore exchanges it for a fresh bearer; browser restore can reuse
/// the bearer saved separately in `IndexedDB`. Encryption keys can also be
/// recovered offline.
///
/// Treat values of this type as bearer-equivalent secrets. Embedded encryption
/// keys remain confidential after the underlying grant expires or is revoked.
#[derive(Clone)]
struct StoredGrantCredential {
    /// User-signed grant JWS.
    grant_jws: String,
    /// Secret bytes for the `PoP` client keypair bound by the grant `cnf`.
    client_key_secret: [u8; 32],
    /// Homeserver public key used as the `PoP` audience.
    homeserver_pk: PublicKey,
    signed_approval: Option<SignedApproval>,
}

/// Non-secret durable metadata for browser delegated grant restore.
#[derive(Clone, PartialEq, Eq)]
pub struct DelegatedGrantCredentialState {
    /// User-signed grant JWS.
    pub grant_jws: String,
    /// Homeserver public key used as the `PoP` audience.
    pub homeserver_pk: PublicKey,
    /// `IndexedDB` key id for the non-extractable private `CryptoKey`.
    pub key_id: String,
    /// Public key for the delegated `PoP` signer.
    pub client_pk: PublicKey,
}

impl fmt::Debug for DelegatedGrantCredentialState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelegatedGrantCredentialState")
            .field("grant_jws", &"<redacted>")
            .field("homeserver_pk", &self.homeserver_pk)
            .field("key_id", &self.key_id)
            .field("client_pk", &self.client_pk)
            .finish()
    }
}

impl fmt::Debug for StoredGrantCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredGrantCredential")
            .field("grant_jws", &"<redacted>")
            .field("client_key_secret", &"<redacted>")
            .field("homeserver_pk", &self.homeserver_pk)
            .field("signed_approval", &self.signed_approval)
            .finish()
    }
}

impl StoredGrantCredential {
    /// Encode this credential as a compact token suitable for secure storage.
    fn encode(&self) -> String {
        let secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(self.client_key_secret));
        match &self.signed_approval {
            Some(approval) => format!(
                "{STORED_GRANT_CREDENTIAL_APPROVAL_PREFIX}:{}:{}:{}:{}",
                self.homeserver_pk.z32(),
                secret.as_str(),
                self.grant_jws,
                approval.as_str(),
            ),
            None => format!(
                "{STORED_GRANT_CREDENTIAL_PREFIX}:{}:{}:{}",
                self.homeserver_pk.z32(),
                secret.as_str(),
                self.grant_jws,
            ),
        }
    }

    /// Decode a compact token produced by [`Self::encode`].
    ///
    /// # Errors
    /// Returns validation errors when the token is malformed or contains an
    /// unsupported version, invalid homeserver key, or invalid client secret.
    fn decode(token: &str) -> Result<Self> {
        // V1 remains authentication-only. V2 appends the confidential signed
        // approval; compact JWS values contain no colon separators.
        let (prefix, rest) = token.split_once(':').ok_or_else(invalid_stored_grant)?;
        if prefix != STORED_GRANT_CREDENTIAL_PREFIX
            && prefix != STORED_GRANT_CREDENTIAL_APPROVAL_PREFIX
        {
            return Err(RequestError::Validation {
                message: "unsupported grant credential token version".into(),
            }
            .into());
        }

        let (homeserver, rest) = rest.split_once(':').ok_or_else(invalid_stored_grant)?;
        let (secret, grant_jws) = rest.split_once(':').ok_or_else(invalid_stored_grant)?;
        let (grant_jws, signed_approval) = if prefix == STORED_GRANT_CREDENTIAL_APPROVAL_PREFIX {
            let (grant, approval) = grant_jws.split_once(':').ok_or_else(invalid_stored_grant)?;
            if approval.is_empty() {
                return Err(invalid_stored_grant().into());
            }
            (grant, Some(SignedApproval::new(approval)))
        } else {
            (grant_jws, None)
        };
        if grant_jws.is_empty() {
            return Err(invalid_stored_grant().into());
        }

        let homeserver_pk =
            PublicKey::try_from_z32(homeserver).map_err(|_err| RequestError::Validation {
                message: "invalid stored grant credential homeserver public key".into(),
            })?;
        let secret = Zeroizing::new(URL_SAFE_NO_PAD.decode(secret).map_err(|_err| {
            RequestError::Validation {
                message: "invalid stored grant credential client secret".into(),
            }
        })?);
        let client_key_secret =
            <[u8; 32]>::try_from(secret.as_slice()).map_err(|_err| RequestError::Validation {
                message: "stored grant credential client secret must be 32 bytes".into(),
            })?;

        Ok(Self {
            grant_jws: grant_jws.to_string(),
            client_key_secret,
            homeserver_pk,
            signed_approval,
        })
    }
}

impl GrantCredential {
    /// Build a grant credential from a `GrantSessionResponse` returned by
    /// `POST /auth/grant/session` or `POST /auth/grant/signup`.
    pub(crate) fn from_response(
        response: GrantSessionResponse,
        grant_jws: String,
        grant_claims: GrantClaims,
        client_signer: GrantPopSigner,
        homeserver_pk: PublicKey,
    ) -> Self {
        let info = to_session_info(&response.session);
        let state = GrantCredentialState {
            bearer: response.token,
            grant_jws,
            grant_claims,
            client_signer,
            homeserver_pk,
            session: response.session,
            coordinator: None,
        };
        Self {
            state: Arc::new(Mutex::new(state)),
            info,
            verified_approval: None,
        }
    }

    /// Read browser restore material without issuing a bearer.
    /// Expired grants remain usable for finishing a pending logout.
    #[doc(hidden)]
    pub fn from_shared_secret(token: &str) -> Result<Self> {
        let material = restore_material(StoredGrantCredential::decode(token)?, true)?;
        Ok(Self::from_shared_material(material))
    }

    /// Read browser-held restore material, including expired grants for logout.
    #[doc(hidden)]
    pub fn from_shared_delegated_state(
        state: DelegatedGrantCredentialState,
        sign: DelegatedSignFn,
    ) -> Result<Self> {
        Self::from_shared_delegated_state_with_approval(state, sign, None)
    }

    /// Read browser-held restore material and verify its confidential approval.
    /// Retains keys without issuing a bearer; expired grants remain usable for logout.
    #[doc(hidden)]
    pub fn from_shared_delegated_state_with_approval(
        state: DelegatedGrantCredentialState,
        sign: DelegatedSignFn,
        signed_approval: Option<&str>,
    ) -> Result<Self> {
        Ok(Self::from_shared_material(restore_delegated_material(
            state,
            sign,
            true,
            signed_approval,
        )?))
    }

    fn from_shared_material(material: GrantRestoreMaterial) -> Self {
        let GrantRestoreMaterial {
            grant_jws,
            grant_claims: claims,
            client_signer: signer,
            homeserver_pk: homeserver,
            verified_approval,
        } = material;
        let response = GrantSessionResponse {
            token: String::new(),
            session: GrantSessionInfo {
                homeserver: homeserver.clone(),
                pubky: claims.iss.clone(),
                client_id: claims.client_id.clone(),
                capabilities: claims.caps.clone(),
                grant_id: claims.jti.clone(),
                token_expires_at: 0,
                grant_expires_at: claims.exp,
                created_at: 0,
            },
        };
        let mut credential = Self::from_response(response, grant_jws, claims, signer, homeserver);
        credential.retain_verified_approval(verified_approval);
        credential
    }

    async fn exchange_restored_material(
        material: GrantRestoreMaterial,
        client: &PubkyHttpClient,
    ) -> Result<Self> {
        let mut credential = credential_from_grant_exchange(
            client,
            material.grant_jws,
            material.grant_claims,
            material.client_signer,
            material.homeserver_pk,
        )
        .await?;
        credential.retain_verified_approval(material.verified_approval);
        Ok(credential)
    }

    /// Retain scoped keys and their signed recovery approval together.
    pub(crate) fn retain_verified_approval(&mut self, approval: Option<VerifiedApproval>) {
        self.verified_approval = approval.map(Arc::new);
    }

    /// Verified scoped keys received with this approval, if any.
    ///
    /// Bare grants return `None`. Signed approvals return `Some`, with an empty
    /// bundle when no `e` scopes were approved. Storage V1 exports have no bundle;
    /// storage V2 preserves it. Clones share the same zeroizing key storage.
    pub fn encryption_keys(&self) -> Option<&ScopedEncryptionKeyBundle> {
        self.verified_approval
            .as_ref()
            .map(|approval| &approval.encryption_keys)
    }

    /// Snapshot of the current bearer token (released immediately).
    pub(crate) async fn current_bearer(&self) -> String {
        self.state.lock().await.bearer.clone()
    }

    /// Export the portable local secret material needed to restore this credential.
    ///
    /// Sessions with a signed approval export V2 tokens, even if the approved
    /// key bundle is empty. Bare-grant sessions retain the compatible V1 format.
    /// Delivered keys remain sensitive after the grant expires or is revoked.
    ///
    /// Returns `None` for delegated/browser-held `PoP` signers because their
    /// private key material is intentionally not extractable.
    pub async fn export_local_secret(&self) -> Option<String> {
        let state = self.state.lock().await;
        let client_key_secret = state.client_signer.local_secret()?;
        Some(
            StoredGrantCredential {
                grant_jws: state.grant_jws.clone(),
                client_key_secret,
                homeserver_pk: state.homeserver_pk.clone(),
                signed_approval: self
                    .verified_approval
                    .as_ref()
                    .map(|approval| approval.signed_approval.clone()),
            }
            .encode(),
        )
    }

    /// Borrow the confidential signed approval for secure key persistence.
    ///
    /// This may contain raw scoped secrets and must stay outside public metadata.
    /// Persist it alongside delegated restore metadata and pass it to
    /// [`Self::import_delegated_state_with_approval`] to restore authentication
    /// too, or [`Self::restore_delegated_encryption_keys`] for offline recovery.
    pub fn signed_approval(&self) -> Option<&str> {
        self.verified_approval
            .as_ref()
            .map(|approval| approval.signed_approval.as_str())
    }

    /// Export non-secret delegated restore metadata for browser-held keys.
    ///
    /// This metadata omits scoped encryption keys; restoring it only restores
    /// authentication.
    pub async fn export_delegated_restore_state(&self) -> Option<DelegatedGrantCredentialState> {
        let state = self.state.lock().await;
        let signer = state.client_signer.delegated_state()?;
        Some(DelegatedGrantCredentialState {
            grant_jws: state.grant_jws.clone(),
            homeserver_pk: state.homeserver_pk.clone(),
            key_id: signer.key_id,
            client_pk: signer.public_key,
        })
    }

    pub(crate) fn is_secret_token(token: &str) -> bool {
        token.starts_with(STORED_GRANT_CREDENTIAL_PREFIX_FAMILY)
    }

    /// Recover scoped encryption keys from a local secret token entirely offline.
    ///
    /// Verifies the signed approval, its exact grant binding, and key scopes.
    /// Bare-grant (storage V1) tokens return `None`. Signed approvals without
    /// `e` scopes return `Some` with an empty bundle. Grant expiry and revocation
    /// do not invalidate previously delivered keys. This method
    /// performs no network I/O and does not create an authenticated session.
    ///
    /// # Errors
    /// Rejects malformed tokens, invalid approvals, and mismatched grants.
    pub fn restore_encryption_keys(token: &str) -> Result<Option<ScopedEncryptionKeyBundle>> {
        Ok(Self::restore_encryption_keys_with_claims(token)?.map(|(_, keys)| keys))
    }

    /// Recover keys together with the grant claims authenticated by the approval.
    ///
    /// Like [`Self::restore_encryption_keys`], but also returns authenticated
    /// claims so callers can check `iss` and `jti` against the expected record.
    ///
    /// # Errors
    /// Rejects malformed tokens, invalid approvals, and mismatched grants.
    pub fn restore_encryption_keys_with_claims(
        token: &str,
    ) -> Result<Option<(GrantClaims, ScopedEncryptionKeyBundle)>> {
        let saved = StoredGrantCredential::decode(token)?;
        Self::restore_encryption_keys_from_approval(
            &saved.grant_jws,
            saved.signed_approval.as_ref().map(SignedApproval::as_str),
        )
    }

    /// Recover delegated session keys entirely offline, without a `PoP` signer.
    ///
    /// Verifies the confidential signed approval against the exact saved grant.
    /// `None` restores no keys for authentication-only records. Neither grant
    /// expiry nor the availability of the homeserver or delegated signing key
    /// affects recovery. The returned keys confer no authenticated access.
    ///
    /// # Errors
    /// Rejects invalid approvals, inconsistent scopes, and mismatched grants.
    pub fn restore_delegated_encryption_keys(
        state: &DelegatedGrantCredentialState,
        signed_approval: Option<&str>,
    ) -> Result<Option<ScopedEncryptionKeyBundle>> {
        let recovered =
            Self::restore_encryption_keys_from_approval(&state.grant_jws, signed_approval)?;
        Ok(recovered.map(|(_, keys)| keys))
    }

    /// Recover keys and authenticated claims from an approval bound to `grant_jws`.
    ///
    /// Works offline, without a signing key or valid grant. No approval returns
    /// `None`. Check `claims.iss` and `claims.jti` against the expected record
    /// before using the returned `(claims, keys)`.
    ///
    /// # Errors
    /// Rejects invalid approvals, inconsistent scopes, and mismatched grants.
    pub fn restore_encryption_keys_from_approval(
        grant_jws: &str,
        signed_approval: Option<&str>,
    ) -> Result<Option<(GrantClaims, ScopedEncryptionKeyBundle)>> {
        let approval = restore_verified_approval(signed_approval, grant_jws)?;
        Ok(approval.map(|(claims, verified)| (claims, verified.encryption_keys)))
    }

    /// Restore a grant credential from an exported secret token.
    ///
    /// This validates the token locally, then exchanges its grant and `PoP`
    /// key with the homeserver for a fresh short-lived bearer. For offline key
    /// recovery without authentication, use [`Self::restore_encryption_keys`].
    ///
    /// # Errors
    /// - Returns validation errors for malformed tokens, expired grants, or
    ///   mismatched `PoP` keys.
    /// - Propagates HTTP/server errors from `POST /auth/grant/session`.
    pub async fn import_secret(token: &str, client: &PubkyHttpClient) -> Result<Self> {
        let saved = StoredGrantCredential::decode(token)?;
        Self::exchange_restored_material(restore_material(saved, false)?, client).await
    }

    /// Restore a delegated grant credential from origin-bound browser metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the delegated grant metadata is invalid, if the
    /// grant claims cannot be verified, or if the homeserver rejects the grant
    /// session exchange.
    pub async fn import_delegated_state(
        state: DelegatedGrantCredentialState,
        client: &PubkyHttpClient,
        sign: DelegatedSignFn,
    ) -> Result<Self> {
        Self::import_delegated_state_with_approval(state, client, sign, None).await
    }

    /// Restore browser-held authentication and optionally its confidential keys.
    ///
    /// The separate approval must be securely persisted; delegated state remains
    /// non-secret. An approval is verified and must bind the exact stored grant.
    /// `None` restores legacy authentication-only sessions.
    ///
    /// # Errors
    /// Rejects invalid approvals or a different inner grant before network I/O.
    /// Otherwise propagates the errors from [`Self::import_delegated_state`].
    pub async fn import_delegated_state_with_approval(
        state: DelegatedGrantCredentialState,
        client: &PubkyHttpClient,
        sign: DelegatedSignFn,
        signed_approval: Option<&str>,
    ) -> Result<Self> {
        let material = restore_delegated_material(state, sign, false, signed_approval)?;
        Self::exchange_restored_material(material, client).await
    }

    /// Refresh the credential by exchanging the stored grant for a new bearer.
    ///
    /// Holds the credential mutex for the entire refresh so concurrent
    /// refreshes serialize on the same `Arc<Mutex<…>>`.
    pub(crate) async fn refresh(&self, client: &PubkyHttpClient) -> Result<()> {
        if let Some(coordinator) = self.coordinator().await {
            return self
                .refresh_shared(client, coordinator.as_ref(), None)
                .await;
        }
        cross_log!(info, "Refreshing grant credential");
        let mut state = self.state.lock().await;

        // Another caller may have refreshed while we waited for the lock.
        if !state.needs_refresh(now_unix(), REFRESH_SLACK_SECS / 2) {
            return Ok(());
        }

        let parsed = post_grant_session(
            client,
            &state.grant_jws,
            &state.grant_claims,
            &state.client_signer,
            &state.homeserver_pk,
        )
        .await?;

        state.bearer = parsed.token;
        state.session = parsed.session;
        Ok(())
    }

    async fn grant_session_request(
        &self,
        client: &PubkyHttpClient,
        method: Method,
    ) -> Result<RequestBuilder> {
        let (homeserver, user) = {
            let state = self.state.lock().await;
            (state.homeserver_pk.clone(), state.grant_claims.iss.clone())
        };
        client
            .cross_request_via_homeserver(method, &homeserver, &user, GRANT_SESSION_PATH)
            .await
    }
}

// Mirrors the cfg pair on the trait definition: native gets `Send` bounds
// for tokio, WASM uses `?Send` because `wasm-bindgen-futures` are not
// `Send`. See [`crate::actors::session::credential::SessionCredential`] for
// the full rationale.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SessionCredential for GrantCredential {
    fn info(&self) -> SessionInfo {
        self.info.clone()
    }

    async fn signout(&self, client: &PubkyHttpClient) -> Result<()> {
        let lease = match self.coordinator().await {
            Some(coordinator) => Some(coordinator.acquire(true).await?),
            None => None,
        };
        if let Some(lease) = &lease {
            let Some(mut shared) = lease.load().await? else {
                return Ok(());
            };
            self.state.lock().await.adopt(shared.response.clone())?;
            shared.logout_pending = true;
            lease.store(&shared).await?;
        }
        let request = self.grant_session_request(client, Method::DELETE).await?;
        let homeserver = self.state.lock().await.homeserver_pk.clone();
        let supports_proof_logout = client
            .features
            .supports(
                client,
                &homeserver,
                pubky_common::constants::features::GRANT_PROOF_LOGOUT,
            )
            .await;
        let proof = {
            let state = self.state.lock().await;
            if supports_proof_logout {
                let pop = sign_pop_for_grant(
                    &state.client_signer,
                    &state.homeserver_pk,
                    &state.grant_claims.jti,
                )
                .await?;
                Some(serde_json::json!({ "grant": state.grant_jws, "pop": pop }))
            } else {
                None
            }
        };
        // Older servers only understand bearer-authenticated logout.
        let request = match proof {
            Some(proof) => request.json(&proof),
            None => request.bearer_auth(self.current_bearer().await),
        };
        let response = request.send().await?;
        client.check_http_status(response).await?;
        if let Some(lease) = lease {
            lease.remove().await?;
        }
        Ok(())
    }

    async fn send(
        &self,
        rb: RequestBuilder,
        client: &PubkyHttpClient,
    ) -> Result<reqwest::Response> {
        if let Some(coordinator) = self.coordinator().await {
            return self.send_shared(rb, client, coordinator.as_ref()).await;
        }
        Ok(self.attach(rb, client).await?.send().await?)
    }

    async fn attach(&self, rb: RequestBuilder, client: &PubkyHttpClient) -> Result<RequestBuilder> {
        // Snapshot expiry quickly so we don't hold the lock across the
        // network call when no refresh is needed.
        let needs_refresh = {
            let grant_state = self.state.lock().await;
            grant_state.needs_refresh(now_unix(), REFRESH_SLACK_SECS)
        };
        if needs_refresh {
            self.refresh(client).await?;
        }
        let bearer = self.state.lock().await.bearer.clone();
        Ok(rb.bearer_auth(bearer))
    }

    async fn can_attach_to(&self, homeserver: &PublicKey) -> bool {
        &self.state.lock().await.homeserver_pk == homeserver
    }

    async fn revalidate(
        &self,
        client: &PubkyHttpClient,
        _user: &PublicKey,
    ) -> Result<Option<SessionInfo>> {
        let request = self.grant_session_request(client, Method::GET).await?;
        let response = if let Some(coordinator) = self.coordinator().await {
            match self
                .send_shared(request, client, coordinator.as_ref())
                .await
            {
                Err(Error::Request(RequestError::Server {
                    status: StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND,
                    ..
                })) => return Ok(None),
                result => result?,
            }
        } else {
            request
                .bearer_auth(self.current_bearer().await)
                .send()
                .await?
        };
        if credential_session_missing(&response) {
            return Ok(None);
        }
        let response = client.check_http_status(response).await?;
        let session: GrantSessionInfo =
            response
                .json()
                .await
                .map_err(|e| RequestError::DecodeJson {
                    message: format!("decoding /auth/grant/session response: {e}"),
                })?;
        Ok(Some(to_session_info(&session)))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PubkySession {
    /// Build a grant-backed [`PubkySession`] from a [`GrantCredential`].
    ///
    /// Typical use: after
    /// [`PubkyGrantAuthFlow::await_credential`](crate::PubkyGrantAuthFlow::await_credential)
    /// returns a credential you want to hold separately, this lifts it into
    /// a full session bound to the given HTTP client.
    #[must_use]
    pub fn from_grant_credential(client: PubkyHttpClient, credential: GrantCredential) -> Self {
        Self::from_credential(client, Arc::new(credential))
    }

    /// Restore a grant-backed [`PubkySession`] from an exported secret token.
    ///
    /// This mints a fresh bearer from the token's grant and `PoP` key instead
    /// of replaying an old short-lived bearer. The token should come from
    /// [`GrantSessionView::export_local_secret`](crate::GrantSessionView::export_local_secret)
    /// or [`GrantCredential::export_local_secret`].
    ///
    /// # Errors
    /// - See [`GrantCredential::import_secret`].
    pub async fn import_grant_secret(token: &str, client: Option<PubkyHttpClient>) -> Result<Self> {
        let client = match client {
            Some(client) => client,
            None => PubkyHttpClient::new()?,
        };
        let credential = GrantCredential::import_secret(token, &client).await?;
        Ok(Self::from_grant_credential(client, credential))
    }
}

/// Build a minimal [`SessionInfo`] from a [`GrantSessionInfo`].
fn to_session_info(session: &GrantSessionInfo) -> SessionInfo {
    SessionInfo::new(session.pubky.clone(), session.capabilities.clone())
}

fn restore_material(
    saved: StoredGrantCredential,
    allow_expired: bool,
) -> Result<GrantRestoreMaterial> {
    let verified_approval = restore_verified_approval(
        saved.signed_approval.as_ref().map(SignedApproval::as_str),
        &saved.grant_jws,
    )?
    .map(|(_, approval)| approval);
    let grant_claims = GrantClaims::decode(&saved.grant_jws).map_err(|err| {
        AuthError::Validation(format!("invalid stored grant credential grant JWS: {err}"))
    })?;
    if !allow_expired && grant_claims.exp <= now_unix() {
        return Err(AuthError::Validation("stored grant credential has expired".into()).into());
    }

    let client_keypair = Keypair::from_secret(&saved.client_key_secret);
    if client_keypair.public_key() != grant_claims.cnf {
        return Err(AuthError::Validation(
            "stored grant credential client key does not match the grant cnf".into(),
        )
        .into());
    }

    Ok(GrantRestoreMaterial {
        grant_jws: saved.grant_jws,
        grant_claims,
        client_signer: GrantPopSigner::local(client_keypair),
        homeserver_pk: saved.homeserver_pk,
        verified_approval,
    })
}

fn restore_verified_approval(
    signed: Option<&str>,
    grant_jws: &str,
) -> Result<Option<(GrantClaims, VerifiedApproval)>> {
    let Some(signed) = signed else {
        return Ok(None);
    };
    let approval = GrantApproval::decode_text(
        signed,
        crate::actors::auth::deep_links::GrantApprovalFormat::SignedApprovalV1,
    )?;
    if approval.grant_jws != grant_jws {
        return Err(AuthError::Validation(
            "stored approval does not match the stored grant".into(),
        )
        .into());
    }
    Ok(approval
        .verified_approval
        .map(|verified| (approval.claims, verified)))
}

fn restore_delegated_material(
    saved: DelegatedGrantCredentialState,
    sign: DelegatedSignFn,
    allow_expired: bool,
    signed_approval: Option<&str>,
) -> Result<GrantRestoreMaterial> {
    let verified_approval =
        restore_verified_approval(signed_approval, &saved.grant_jws)?.map(|(_, approval)| approval);
    let grant_claims = GrantClaims::decode(&saved.grant_jws).map_err(|err| {
        AuthError::Validation(format!(
            "invalid delegated grant credential grant JWS: {err}"
        ))
    })?;
    if !allow_expired && grant_claims.exp <= now_unix() {
        return Err(AuthError::Validation("delegated grant credential has expired".into()).into());
    }

    if saved.client_pk != grant_claims.cnf {
        return Err(AuthError::Validation(
            "delegated grant credential client key does not match the grant cnf".into(),
        )
        .into());
    }

    Ok(GrantRestoreMaterial {
        grant_jws: saved.grant_jws,
        grant_claims,
        client_signer: GrantPopSigner::delegated(saved.key_id, saved.client_pk, sign),
        homeserver_pk: saved.homeserver_pk,
        verified_approval,
    })
}

fn invalid_stored_grant() -> AuthError {
    AuthError::Validation(format!(
        "invalid stored grant credential: expected `{STORED_GRANT_CREDENTIAL_PREFIX}:<homeserver>:<client_secret>:<grant_jws>`"
    ))
}

/// Sign a Proof-of-Possession proof JWS for a given grant.
///
/// Builds the canonical `pubky-pop` claims (`aud`, `gid`, `nonce`, `iat`)
/// and signs them with the client keypair via
/// [`pubky_common::auth::jws::sign_jws`].
pub(crate) async fn sign_pop_for_grant(
    client_signer: &GrantPopSigner,
    homeserver_pk: &PublicKey,
    grant_id: &pubky_common::auth::jws::GrantId,
) -> Result<String> {
    let claims = PopProofClaims {
        aud: homeserver_pk.clone(),
        gid: grant_id.clone(),
        nonce: PopNonce::generate(),
        iat: now_unix(),
    };
    client_signer
        .sign_jws(POP_JWS_TYP, &claims)
        .await
        .map_err(|error| AuthError::Validation(error.to_string()).into())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use pkarr::{Cache, InMemoryCache};
    use pubky_common::{
        auth::jws::{ClientId, GRANT_JWS_TYP, GrantId},
        capabilities::Capability,
    };
    use pubky_testnet::EphemeralTestnet;

    use super::*;

    #[tokio::test]
    #[pubky_testnet::test]
    async fn capped_bearer_requests_and_legacy_logout_do_not_refresh() {
        let testnet = EphemeralTestnet::builder().build().await.unwrap();
        let user = Keypair::random();
        let homeserver = testnet.homeserver_app().public_key();
        testnet
            .sdk()
            .unwrap()
            .signer(user.clone())
            .signup(&homeserver, None)
            .await
            .unwrap();
        let mut builder = PubkyHttpClient::builder();
        builder.pkarr(|b| {
            *b = testnet.pkarr_client_builder();
            b
        });
        let client = builder.build().unwrap();
        client.features.insert(&homeserver, &[]);
        let pop_key = Keypair::random();
        let now = now_unix();
        let grant = GrantClaims {
            iss: user.public_key(),
            client_id: ClientId::new("refresh.test").unwrap(),
            caps: vec![Capability::root()],
            cnf: pop_key.public_key(),
            jti: GrantId::generate(),
            iat: now,
            exp: now + 120,
        };
        let jws = grant.sign(&user, GRANT_JWS_TYP);
        let signer = GrantPopSigner::local(pop_key);
        let response = post_grant_session(&client, &jws, &grant, &signer, &homeserver)
            .await
            .unwrap();
        let bearer = response.token.clone();
        assert_eq!(response.session.token_expires_at, grant.exp);
        let credential = GrantCredential::from_response(response, jws, grant, signer, homeserver);
        for _ in 0..3 {
            credential.refresh(&client).await.unwrap();
            let request = credential
                .grant_session_request(&client, Method::GET)
                .await
                .unwrap();
            let response = credential
                .attach(request, &client)
                .await
                .unwrap()
                .send()
                .await
                .unwrap();
            client.check_http_status(response).await.unwrap();
            assert_eq!(credential.current_bearer().await, bearer);
        }

        // Logout must also work when the cached bearer would normally need a refresh.
        credential.state.lock().await.session.token_expires_at = now_unix() + 60;
        credential.signout(&client).await.unwrap();
        assert!(
            credential
                .revalidate(&client, &user.public_key())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn refresh_policy_preserves_capped_bearers_until_expiry() {
        let (stored, claims) = stored_credential(5_000);
        let signer = GrantPopSigner::local(Keypair::from_secret(&stored.client_key_secret));
        let credential = test_credential(stored, claims, signer);
        let mut state = credential.state.blocking_lock();
        let now = 1_000;
        for (bearer_exp, grant_exp, slack, expected) in [
            (1_301, 5_000, 300, false),
            (1_300, 5_000, 300, true),
            (1_151, 5_000, 150, false),
            (1_150, 5_000, 150, true),
            (1_120, 1_120, 150, false),
            (1_120, 1_100, 150, false),
            (1_000, 1_000, 150, true),
            (999, 999, 150, true),
            (0, 1_120, 150, true),
        ] {
            state.session.token_expires_at = bearer_exp;
            state.grant_claims.exp = grant_exp;
            assert_eq!(
                state.needs_refresh(now, slack),
                expected,
                "bearer_exp={bearer_exp}, grant_exp={grant_exp}, slack={slack}"
            );
        }
    }

    #[test]
    fn stored_grant_credential_encode_decode_round_trips() {
        let (stored, _claims) = stored_credential(now_unix() + 3600);

        let encoded = stored.encode();
        let decoded = StoredGrantCredential::decode(&encoded).unwrap();

        assert_eq!(decoded.grant_jws, stored.grant_jws);
        assert_eq!(decoded.client_key_secret, stored.client_key_secret);
        assert_eq!(decoded.homeserver_pk, stored.homeserver_pk);
        assert!(decoded.signed_approval.is_none());
    }

    #[test]
    fn key_bearing_secret_round_trip_verifies_approval_and_preserves_keys() {
        let identity = Keypair::random();
        let (mut stored, mut claims) = stored_credential(now_unix() + 3600);
        claims.iss = identity.public_key();
        claims.caps = vec!["/pub/chat/:re".parse().unwrap()];
        stored.grant_jws = claims.sign(&identity, GRANT_JWS_TYP);
        let signed =
            super::super::approval_envelope::GrantApprovalEnvelope::sign(&identity, &claims);
        stored.signed_approval = Some(SignedApproval::new(&signed));

        let encoded = Zeroizing::new(stored.encode());
        assert!(encoded.starts_with(STORED_GRANT_CREDENTIAL_APPROVAL_PREFIX));
        let decoded = StoredGrantCredential::decode(&encoded).unwrap();
        let (_, approval) = restore_verified_approval(
            decoded.signed_approval.as_ref().map(SignedApproval::as_str),
            &decoded.grant_jws,
        )
        .unwrap()
        .unwrap();
        let keys = approval.encryption_keys;
        let path = pubky_common::StoragePath::new("/pub/chat/message").unwrap();
        let expected = ScopedEncryptionKeyBundle::from_identity_secret(&identity.secret(), [&path]);
        assert_eq!(
            *keys.derive_for_path(&path).unwrap(),
            *expected.derive_for_path(&path).unwrap()
        );
        assert!(
            keys.derive_for_path(&pubky_common::StoragePath::new("/pub/other/file").unwrap())
                .is_err()
        );
        assert!(!format!("{decoded:?}").contains(signed.as_str()));

        let (other, _) = stored_credential(now_unix() + 3600);
        assert!(restore_verified_approval(Some(&signed), &other.grant_jws).is_err());
        let mut tampered = signed.as_bytes().to_vec();
        let signature_start = signed.rfind('.').unwrap() + 1;
        tampered[signature_start] = if tampered[signature_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert!(
            restore_verified_approval(
                Some(std::str::from_utf8(&tampered).unwrap()),
                &stored.grant_jws
            )
            .is_err()
        );
    }

    fn expired_key_credential() -> (
        StoredGrantCredential,
        DelegatedGrantCredentialState,
        Keypair,
    ) {
        let identity = Keypair::random();
        let (mut saved, mut claims) = stored_credential(1);
        claims.iat = 0;
        claims.iss = identity.public_key();
        claims.caps = vec!["/pub/chat/:re".parse().unwrap()];
        saved.grant_jws = claims.sign(&identity, GRANT_JWS_TYP);
        let signed =
            super::super::approval_envelope::GrantApprovalEnvelope::sign(&identity, &claims);
        saved.signed_approval = Some(SignedApproval::new(&signed));
        let delegated = DelegatedGrantCredentialState {
            grant_jws: saved.grant_jws.clone(),
            homeserver_pk: saved.homeserver_pk.clone(),
            key_id: "missing-browser-key".into(),
            client_pk: claims.cnf,
        };
        (saved, delegated, identity)
    }

    #[test]
    fn offline_key_recovery_accepts_expiry_without_relaxing_session_restore() {
        let (saved, delegated, identity) = expired_key_credential();
        let token = Zeroizing::new(saved.encode());
        let local_keys = GrantCredential::restore_encryption_keys(&token)
            .unwrap()
            .unwrap();
        let delegated_keys = GrantCredential::restore_delegated_encryption_keys(
            &delegated,
            saved.signed_approval.as_ref().map(SignedApproval::as_str),
        )
        .unwrap()
        .unwrap();
        let path = pubky_common::StoragePath::new("/pub/chat/message").unwrap();
        let expected = ScopedEncryptionKeyBundle::from_identity_secret(&identity.secret(), [&path]);
        let shared_local = GrantCredential::from_shared_secret(&token).unwrap();
        let shared_delegated = GrantCredential::from_shared_delegated_state_with_approval(
            delegated.clone(),
            test_delegated_signer(),
            saved.signed_approval.as_ref().map(SignedApproval::as_str),
        )
        .unwrap();
        assert!(shared_local.signed_approval().is_some());
        assert!(shared_delegated.signed_approval().is_some());
        for keys in [
            &local_keys,
            &delegated_keys,
            shared_local.encryption_keys().unwrap(),
            shared_delegated.encryption_keys().unwrap(),
        ] {
            assert_eq!(
                *keys.derive_for_path(&path).unwrap(),
                *expected.derive_for_path(&path).unwrap()
            );
            assert!(
                keys.derive_for_path(&pubky_common::StoragePath::new("/pub/other/file").unwrap())
                    .is_err()
            );
            assert!(
                keys.derive_for_path(&pubky_common::StoragePath::new("/pub/chat/").unwrap())
                    .is_err()
            );
        }
        assert!(
            restore_material(saved, false)
                .unwrap_err()
                .to_string()
                .contains("has expired")
        );
        assert!(
            restore_delegated_material(delegated, test_delegated_signer(), false, None)
                .unwrap_err()
                .to_string()
                .contains("has expired")
        );
    }

    #[test]
    fn offline_key_recovery_rejects_tampering_and_mismatched_grants() {
        let (mut saved, mut delegated, _) = expired_key_credential();
        let signed = saved.signed_approval.clone().unwrap();
        let (other, _) = stored_credential(now_unix() + 3600);
        delegated.grant_jws = other.grant_jws.clone();
        assert!(
            GrantCredential::restore_delegated_encryption_keys(&delegated, Some(signed.as_str()))
                .is_err()
        );
        let original_grant = std::mem::replace(&mut saved.grant_jws, other.grant_jws);
        assert!(GrantCredential::restore_encryption_keys(&saved.encode()).is_err());
        saved.grant_jws = original_grant;
        delegated.grant_jws = saved.grant_jws.clone();

        let mut tampered = signed.as_str().as_bytes().to_vec();
        let signature_start = signed.as_str().rfind('.').unwrap() + 1;
        tampered[signature_start] = if tampered[signature_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let tampered = Zeroizing::new(String::from_utf8(tampered).unwrap());
        saved.signed_approval = Some(SignedApproval::new(&tampered));
        assert!(GrantCredential::from_shared_secret(&saved.encode()).is_err());
        assert!(
            GrantCredential::from_shared_delegated_state_with_approval(
                delegated.clone(),
                test_delegated_signer(),
                Some(&tampered),
            )
            .is_err()
        );
        assert!(GrantCredential::restore_encryption_keys(&saved.encode()).is_err());
        assert!(
            GrantCredential::restore_delegated_encryption_keys(&delegated, Some(&tampered))
                .is_err()
        );
        assert!(GrantCredential::restore_encryption_keys("malformed").is_err());
    }

    #[test]
    fn offline_legacy_restore_returns_no_keys() {
        let (saved, _) = stored_credential(1);
        assert!(
            GrantCredential::restore_encryption_keys(&saved.encode())
                .unwrap()
                .is_none()
        );
        let (_, delegated, _) = expired_key_credential();
        assert!(
            GrantCredential::restore_delegated_encryption_keys(&delegated, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn v2_secret_rejects_missing_approval() {
        let (stored, _) = stored_credential(now_unix() + 3600);
        let token = stored.encode().replacen(
            STORED_GRANT_CREDENTIAL_PREFIX,
            STORED_GRANT_CREDENTIAL_APPROVAL_PREFIX,
            1,
        );
        assert!(StoredGrantCredential::decode(&token).is_err());
        assert!(StoredGrantCredential::decode(&format!("{token}:")).is_err());
    }

    #[test]
    fn restore_material_rejects_mismatched_client_key() {
        let (mut stored, _claims) = stored_credential(now_unix() + 3600);
        stored.client_key_secret = Keypair::random().secret();

        let error = restore_material(stored, false).unwrap_err().to_string();

        assert!(error.contains("client key does not match"));
    }

    #[test]
    fn restore_delegated_material_rejects_mismatched_client_key() {
        let (stored, _claims) = stored_credential(now_unix() + 3600);
        let saved = DelegatedGrantCredentialState {
            grant_jws: stored.grant_jws,
            homeserver_pk: stored.homeserver_pk,
            key_id: "delegated-test-key".into(),
            client_pk: Keypair::random().public_key(),
        };

        let error = restore_delegated_material(saved, test_delegated_signer(), false, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("client key does not match"));
    }

    #[test]
    fn restore_delegated_material_rejects_expired_grant() {
        let (stored, claims) = stored_credential(now_unix().saturating_sub(1));
        let saved = DelegatedGrantCredentialState {
            grant_jws: stored.grant_jws,
            homeserver_pk: stored.homeserver_pk,
            key_id: "delegated-test-key".into(),
            client_pk: claims.cnf,
        };

        let error = restore_delegated_material(saved, test_delegated_signer(), false, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("has expired"));
    }

    #[tokio::test]
    async fn export_local_secret_is_only_available_for_local_signers() {
        let (stored, claims) = stored_credential(now_unix() + 3600);
        let local_signer = GrantPopSigner::local(Keypair::from_secret(&stored.client_key_secret));
        let delegated_signer = GrantPopSigner::delegated(
            "delegated-test-key".into(),
            claims.cnf.clone(),
            test_delegated_signer(),
        );

        let local = test_credential(stored.clone(), claims.clone(), local_signer);
        let delegated = test_credential(stored, claims, delegated_signer);

        assert!(local.export_local_secret().await.is_some());
        assert!(delegated.export_local_secret().await.is_none());
        assert!(delegated.export_delegated_restore_state().await.is_some());
    }

    #[test]
    fn restore_material_rejects_expired_grant() {
        let (stored, _claims) = stored_credential(now_unix().saturating_sub(1));

        let error = restore_material(stored, false).unwrap_err().to_string();

        assert!(error.contains("has expired"));
    }

    #[test]
    fn shared_restore_keeps_expired_material_for_logout() {
        let (stored, claims) = stored_credential(now_unix().saturating_sub(1));
        GrantCredential::from_shared_secret(&stored.encode()).unwrap();
        let delegated = DelegatedGrantCredentialState {
            grant_jws: stored.grant_jws,
            homeserver_pk: stored.homeserver_pk,
            key_id: "delegated-test-key".into(),
            client_pk: claims.cnf,
        };
        GrantCredential::from_shared_delegated_state(delegated, test_delegated_signer()).unwrap();
    }

    #[test]
    fn stored_grant_credential_decode_rejects_wrong_prefix() {
        let error = StoredGrantCredential::decode("wrong:v:secret:grant")
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsupported grant credential token version"));
    }

    fn stored_credential(exp: u64) -> (StoredGrantCredential, GrantClaims) {
        let user_keypair = Keypair::random();
        let client_keypair = Keypair::random();
        let homeserver_keypair = Keypair::random();
        let claims = GrantClaims {
            iss: user_keypair.public_key(),
            client_id: ClientId::new("stored-grant.test").unwrap(),
            caps: vec![Capability::root()],
            cnf: client_keypair.public_key(),
            jti: GrantId::generate(),
            iat: now_unix(),
            exp,
        };
        let grant_jws = claims.sign(&user_keypair, GRANT_JWS_TYP);
        let stored = StoredGrantCredential {
            grant_jws,
            client_key_secret: client_keypair.secret(),
            homeserver_pk: homeserver_keypair.public_key(),
            signed_approval: None,
        };
        (stored, claims)
    }

    fn test_credential(
        stored: StoredGrantCredential,
        claims: GrantClaims,
        client_signer: GrantPopSigner,
    ) -> GrantCredential {
        let now = now_unix();
        GrantCredential::from_response(
            GrantSessionResponse {
                token: "test-bearer".into(),
                session: GrantSessionInfo {
                    homeserver: stored.homeserver_pk.clone(),
                    pubky: claims.iss.clone(),
                    client_id: claims.client_id.clone(),
                    capabilities: claims.caps.clone(),
                    grant_id: claims.jti.clone(),
                    token_expires_at: now + 300,
                    grant_expires_at: claims.exp,
                    created_at: now,
                },
            },
            stored.grant_jws,
            claims,
            client_signer,
            stored.homeserver_pk,
        )
    }

    fn test_delegated_signer() -> DelegatedSignFn {
        super::super::pop_signer::delegated_sign_callback(|_| async { Ok(vec![0; 64]) })
    }

    #[tokio::test]
    async fn can_attach_to_only_matches_bound_homeserver() {
        let bound = Keypair::random().public_key();
        let other = Keypair::random().public_key();
        let (mut stored, claims) = stored_credential(now_unix() + 3600);
        stored.homeserver_pk = bound.clone();
        let client_signer = GrantPopSigner::local(Keypair::from_secret(&stored.client_key_secret));
        let credential = test_credential(stored, claims, client_signer);

        assert!(
            credential.can_attach_to(&bound).await,
            "grant credential must attach to the homeserver it was minted for"
        );
        assert!(
            !credential.can_attach_to(&other).await,
            "grant credential must NOT attach to a homeserver it was not minted for"
        );
    }

    #[tokio::test]
    async fn grant_session_request_routes_through_bound_homeserver() {
        use pkarr::{SignedPacket, dns::rdata::SVCB};

        let (mut stored, claims) = stored_credential(now_unix() + 3600);
        let homeserver_keypair = pkarr::Keypair::random();
        stored.homeserver_pk =
            PublicKey::try_from_z32(&homeserver_keypair.public_key().to_string()).unwrap();
        let icann = SVCB::new(10, "example.com".try_into().unwrap());
        let homeserver_packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), icann, 3600)
            .sign(&homeserver_keypair)
            .unwrap();
        let client_signer = GrantPopSigner::local(Keypair::from_secret(&stored.client_key_secret));
        let credential = test_credential(stored, claims.clone(), client_signer);

        let cache = Arc::new(InMemoryCache::new(NonZeroUsize::MIN));
        let mut builder = PubkyHttpClient::builder();
        builder
            .isolated_pkarr_test()
            .pkarr(|b| b.cache(Arc::<InMemoryCache>::clone(&cache)));
        let client = builder.build().unwrap();
        cache.put(&homeserver_keypair.public_key().into(), &homeserver_packet);

        let request = credential
            .grant_session_request(&client, Method::POST)
            .await
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(request.url().host_str(), Some("example.com"));
        assert_eq!(request.url().path(), "/auth/grant/session");
        assert_eq!(
            request.headers().get("pubky-host").unwrap(),
            &claims.iss.z32()
        );
    }
}
