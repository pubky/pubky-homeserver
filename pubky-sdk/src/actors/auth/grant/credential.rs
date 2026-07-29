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
};

use reqwest::{Method, RequestBuilder};
use tokio::sync::Mutex;

use super::{
    grant_exchange::credential_from_grant_exchange,
    pop_signer::{DelegatedSignFn, GrantPopSigner},
};
use crate::actors::session::core::PubkySession;
use crate::actors::session::credential::{SessionCredential, credential_session_missing};
use crate::{
    PubkyHttpClient,
    actors::session::SessionInfo,
    cross_log,
    errors::{AuthError, RequestError, Result},
    util::check_http_status,
};

/// Refresh the bearer proactively when it has less than this many seconds left.
pub(crate) const REFRESH_SLACK_SECS: u64 = 300;

const GRANT_SESSION_PATH: &str = "/auth/grant/session";
const STORED_GRANT_CREDENTIAL_PREFIX: &str = "pubky-grant-credential-v1";
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
    /// Unix seconds at which `bearer` expires. Drives proactive refresh.
    pub token_expires_at: u64,
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
}

impl GrantCredentialState {
    fn is_near_expiry(&self, now: u64, slack: u64) -> bool {
        self.token_expires_at.saturating_sub(slack) <= now
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
}

/// Durable refresh material for restoring a grant-backed session.
///
/// This is the part of [`GrantCredential`] that is worth persisting. It omits
/// the short-lived bearer token and cached session metadata; restoring always
/// exchanges the stored grant for a fresh bearer.
///
/// Treat values of this type as bearer-equivalent secrets until the underlying
/// grant expires or is revoked.
#[derive(Clone, PartialEq, Eq)]
struct StoredGrantCredential {
    /// User-signed grant JWS.
    grant_jws: String,
    /// Secret bytes for the `PoP` client keypair bound by the grant `cnf`.
    client_key_secret: [u8; 32],
    /// Homeserver public key used as the `PoP` audience.
    homeserver_pk: PublicKey,
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
            .finish()
    }
}

impl StoredGrantCredential {
    /// Encode this credential as a compact token suitable for secure storage.
    #[must_use]
    fn encode(&self) -> String {
        let secret = URL_SAFE_NO_PAD.encode(self.client_key_secret);
        format!(
            "{STORED_GRANT_CREDENTIAL_PREFIX}:{}:{secret}:{}",
            self.homeserver_pk.z32(),
            self.grant_jws
        )
    }

    /// Decode a compact token produced by [`Self::encode`].
    ///
    /// # Errors
    /// Returns validation errors when the token is malformed or contains an
    /// unsupported version, invalid homeserver key, or invalid client secret.
    fn decode(token: &str) -> Result<Self> {
        // Manual decoding without serde to keep serde_json out of the required dependencies of the sdk to
        // not unnecessarily bloat the lib.
        let (prefix, rest) = token.split_once(':').ok_or_else(invalid_stored_grant)?;
        if prefix != STORED_GRANT_CREDENTIAL_PREFIX {
            return Err(RequestError::Validation {
                message: "unsupported grant credential token version".into(),
            }
            .into());
        }

        let (homeserver, rest) = rest.split_once(':').ok_or_else(invalid_stored_grant)?;
        let (secret, grant_jws) = rest.split_once(':').ok_or_else(invalid_stored_grant)?;
        if grant_jws.is_empty() {
            return Err(invalid_stored_grant().into());
        }

        let homeserver_pk =
            PublicKey::try_from_z32(homeserver).map_err(|_err| RequestError::Validation {
                message: "invalid stored grant credential homeserver public key".into(),
            })?;
        let secret = URL_SAFE_NO_PAD
            .decode(secret)
            .map_err(|_err| RequestError::Validation {
                message: "invalid stored grant credential client secret".into(),
            })?;
        let client_key_secret =
            <[u8; 32]>::try_from(secret.as_slice()).map_err(|_err| RequestError::Validation {
                message: "stored grant credential client secret must be 32 bytes".into(),
            })?;

        Ok(Self {
            grant_jws: grant_jws.to_string(),
            client_key_secret,
            homeserver_pk,
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
            token_expires_at: response.session.token_expires_at,
            grant_jws,
            grant_claims,
            client_signer,
            homeserver_pk,
            session: response.session,
        };
        Self {
            state: Arc::new(Mutex::new(state)),
            info,
        }
    }

    /// Snapshot of the current bearer token (released immediately).
    pub(crate) async fn current_bearer(&self) -> String {
        self.state.lock().await.bearer.clone()
    }

    /// Export the portable local secret material needed to restore this credential.
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
            }
            .encode(),
        )
    }

    /// Export non-secret delegated restore metadata for browser-held keys.
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

    /// Restore a grant credential from an exported secret token.
    ///
    /// This validates the token locally, then exchanges its grant and `PoP`
    /// key with the homeserver for a fresh short-lived bearer.
    ///
    /// # Errors
    /// - Returns validation errors for malformed tokens, expired grants, or
    ///   mismatched `PoP` keys.
    /// - Propagates HTTP/server errors from `POST /auth/grant/session`.
    pub async fn import_secret(token: &str, client: &PubkyHttpClient) -> Result<Self> {
        let saved = StoredGrantCredential::decode(token)?;
        let (grant_jws, grant_claims, client_signer, homeserver_pk) = restore_material(saved)?;
        credential_from_grant_exchange(
            client,
            grant_jws,
            grant_claims,
            client_signer,
            homeserver_pk,
        )
        .await
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
        let (grant_jws, grant_claims, client_signer, homeserver_pk) =
            restore_delegated_material(state, sign)?;
        credential_from_grant_exchange(
            client,
            grant_jws,
            grant_claims,
            client_signer,
            homeserver_pk,
        )
        .await
    }

    /// Refresh the credential by exchanging the stored grant for a new bearer.
    ///
    /// Holds the credential mutex for the entire refresh so concurrent
    /// refreshes serialize on the same `Arc<Mutex<…>>`.
    pub(crate) async fn refresh(&self, client: &PubkyHttpClient) -> Result<()> {
        cross_log!(info, "Refreshing grant credential");
        let mut state = self.state.lock().await;

        // Double-check pattern: by the time we acquired the lock, another
        // task may have already refreshed. Skip the network call if the
        // bearer is comfortably fresh now.
        if !state.is_near_expiry(now_unix(), REFRESH_SLACK_SECS / 2) {
            return Ok(());
        }

        let pop_jws = sign_pop_for_grant(
            &state.client_signer,
            &state.homeserver_pk,
            &state.grant_claims.jti,
        )
        .await?;
        let body = serde_json::json!({ "grant": &state.grant_jws, "pop": pop_jws });

        let resp = client
            .cross_request_via_homeserver(
                Method::POST,
                &state.homeserver_pk,
                &state.grant_claims.iss,
                GRANT_SESSION_PATH,
            )
            .await?
            .json(&body)
            .send()
            .await?;
        let resp = check_http_status(resp).await?;
        let parsed: GrantSessionResponse =
            resp.json().await.map_err(|e| RequestError::DecodeJson {
                message: format!("decoding /auth/grant/session response: {e}"),
            })?;

        state.bearer = parsed.token;
        state.token_expires_at = parsed.session.token_expires_at;
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
        let bearer = self.current_bearer().await;
        let response = self
            .grant_session_request(client, Method::DELETE)
            .await?
            .bearer_auth(&bearer)
            .send()
            .await
            .map_err(crate::Error::from)?;
        check_http_status(response).await?;
        Ok(())
    }

    async fn attach(&self, rb: RequestBuilder, client: &PubkyHttpClient) -> Result<RequestBuilder> {
        // Snapshot expiry quickly so we don't hold the lock across the
        // network call when no refresh is needed.
        let needs_refresh = {
            let grant_state = self.state.lock().await;
            grant_state.is_near_expiry(now_unix(), REFRESH_SLACK_SECS)
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
        let bearer = self.current_bearer().await;
        let response = self
            .grant_session_request(client, Method::GET)
            .await?
            .bearer_auth(&bearer)
            .send()
            .await
            .map_err(crate::Error::from)?;
        if credential_session_missing(&response) {
            return Ok(None);
        }
        let response = check_http_status(response).await?;
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
) -> Result<(String, GrantClaims, GrantPopSigner, PublicKey)> {
    let grant_claims = GrantClaims::decode(&saved.grant_jws).map_err(|err| {
        AuthError::Validation(format!("invalid stored grant credential grant JWS: {err}"))
    })?;
    if grant_claims.exp <= now_unix() {
        return Err(AuthError::Validation("stored grant credential has expired".into()).into());
    }

    let client_keypair = Keypair::from_secret(&saved.client_key_secret);
    if client_keypair.public_key() != grant_claims.cnf {
        return Err(AuthError::Validation(
            "stored grant credential client key does not match the grant cnf".into(),
        )
        .into());
    }

    Ok((
        saved.grant_jws,
        grant_claims,
        GrantPopSigner::local(client_keypair),
        saved.homeserver_pk,
    ))
}

fn restore_delegated_material(
    saved: DelegatedGrantCredentialState,
    sign: DelegatedSignFn,
) -> Result<(String, GrantClaims, GrantPopSigner, PublicKey)> {
    let grant_claims = GrantClaims::decode(&saved.grant_jws).map_err(|err| {
        AuthError::Validation(format!(
            "invalid delegated grant credential grant JWS: {err}"
        ))
    })?;
    if grant_claims.exp <= now_unix() {
        return Err(AuthError::Validation("delegated grant credential has expired".into()).into());
    }

    if saved.client_pk != grant_claims.cnf {
        return Err(AuthError::Validation(
            "delegated grant credential client key does not match the grant cnf".into(),
        )
        .into());
    }

    Ok((
        saved.grant_jws,
        grant_claims,
        GrantPopSigner::delegated(saved.key_id, saved.client_pk, sign),
        saved.homeserver_pk,
    ))
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
    client_signer.sign_jws(POP_JWS_TYP, &claims).await
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use pkarr::{Cache, InMemoryCache};
    use pubky_common::{
        auth::jws::{ClientId, GRANT_JWS_TYP, GrantId},
        capabilities::Capability,
    };

    use super::*;

    #[test]
    fn stored_grant_credential_encode_decode_round_trips() {
        let (stored, _claims) = stored_credential(now_unix() + 3600);

        let encoded = stored.encode();
        let decoded = StoredGrantCredential::decode(&encoded).unwrap();

        assert_eq!(decoded, stored);
    }

    #[test]
    fn restore_material_rejects_mismatched_client_key() {
        let (mut stored, _claims) = stored_credential(now_unix() + 3600);
        stored.client_key_secret = Keypair::random().secret();

        let error = restore_material(stored).unwrap_err().to_string();

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

        let error = restore_delegated_material(saved, test_delegated_signer())
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

        let error = restore_delegated_material(saved, test_delegated_signer())
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

        let error = restore_material(stored).unwrap_err().to_string();

        assert!(error.contains("has expired"));
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
            .pkarr(|b| b.cache(cache.clone()));
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
