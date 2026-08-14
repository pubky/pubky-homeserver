//! Auth service facade — orchestrates the full grant-based auth flow.
//!
//! Route handlers call `AuthService` methods instead of orchestrating
//! verification, persistence, and minting steps directly.

use crate::persistence::sql::{signup_code::SignupCode, uexecutor, SqlDb, UnifiedExecutor};
use crate::services::user_service::{UserEntity, UserService};
use chrono::Utc;
use pubky_common::{
    auth::grant::GrantClaims,
    auth::grant_session_responses::{GrantSessionInfo, GrantSessionResponse},
    auth::jws::GrantId,
    crypto::PublicKey,
};

use super::crypto::{
    grant_verifier::verify_grant,
    jws_crypto::JwsCompact,
    pop_verifier::{
        PopProof, PopVerificationContext, POP_MAX_AGE_SECS, POP_NONCE_GC_THRESHOLD_SECS,
    },
    session_token::SessionBearer,
};
use super::persistence::{
    grant::{GrantEntity, GrantRepository, NewGrant},
    grant_session::{GrantSessionEntity, GrantSessionRepository, NewGrantSession},
    pop_nonce::{PopNonceError, PopNonceRepository},
};
use super::service_error::AuthServiceError;
use super::session::GrantSession;
use crate::client_server::auth::{AuthRevocation, AuthSession, SignupService};

/// Default session bearer lifetime: 1 hour.
const DEFAULT_SESSION_TOKEN_LIFETIME_SECS: u64 = 3600;

/// Reserved client id for one-shot sessionless signup grants.
const SIGNUP_CLIENT_ID: &str = "pubky.signup";

/// Signup grants are single-use account creation proofs, not refresh grants.
const MAX_SIGNUP_GRANT_LIFETIME_SECS: u64 = 5 * 60;

/// Facade for all grant-based auth operations.
///
/// Constructed once and stored in `AppState`. Encapsulates the verify → persist
/// → mint pipeline so route handlers stay thin.
#[derive(Clone, Debug)]
pub struct GrantAuthService {
    sql_db: SqlDb,
    homeserver_public_key: PublicKey,
    signup_service: SignupService,
    user_service: UserService,
}

impl GrantAuthService {
    /// Creates the service from the application context.
    pub fn from_context(context: &crate::AppContext) -> Self {
        Self {
            sql_db: context.sql_db.clone(),
            homeserver_public_key: context.keypair.public_key(),
            signup_service: SignupService::from_context(context),
            user_service: context.user_service.clone(),
        }
    }

    /// Creates the service with explicit dependencies (test-only).
    #[cfg(test)]
    pub fn new(
        sql_db: SqlDb,
        homeserver_public_key: PublicKey,
        signup_service: SignupService,
        user_service: UserService,
    ) -> Self {
        Self {
            sql_db,
            homeserver_public_key,
            signup_service,
            user_service,
        }
    }

    /// The homeserver's public key (used by tests as the PoP audience).
    #[cfg(test)]
    pub fn homeserver_public_key(&self) -> pubky_common::crypto::PublicKey {
        self.homeserver_public_key.clone()
    }

    /// Full grant-based session creation: verify → find user → store → mint.
    pub async fn create_grant_session(
        &self,
        grant_jws: &JwsCompact,
        pop_jws: &JwsCompact,
    ) -> Result<GrantSessionResponse, AuthServiceError> {
        let grant = self.verify_grant_and_pop(grant_jws, pop_jws).await?;
        let user = self.find_user(&grant).await?;
        self.store_and_mint(&grant, &user).await
    }

    /// Grant-based signup: verify → create user (all-or-nothing).
    pub async fn signup_grant_account(
        &self,
        grant_jws: &JwsCompact,
        pop_jws: &JwsCompact,
        signup_token: Option<&SignupCode>,
    ) -> Result<(), AuthServiceError> {
        let grant = self.verify_signup_grant_and_pop(grant_jws, pop_jws).await?;
        let mut tx = self.sql_db.pool().begin().await?;
        let user = self
            .signup_service
            .create_user_in_tx(&grant.iss, signup_token, &mut tx)
            .await?;
        tx.commit().await?;
        self.signup_service.cache_user_quota(&user);
        Ok(())
    }

    /// Revoke a grant after verifying it belongs to the authenticated user.
    pub async fn revoke_user_grant(
        &self,
        grant_id: &GrantId,
        auth: &AuthSession,
    ) -> Result<(), AuthServiceError> {
        let user_id = self.resolve_user_id(auth).await?;
        let grant = self.get_grant(grant_id).await?;
        if grant.user_id != user_id {
            return Err(AuthServiceError::GrantOwnershipMismatch);
        }
        self.revoke_grant(grant_id).await
    }

    /// Revoke a grant and delete all its sessions atomically.
    async fn revoke_grant(&self, grant_id: &GrantId) -> Result<(), AuthServiceError> {
        let mut tx = self.sql_db.pool().begin().await?;
        GrantRepository::revoke(grant_id, uexecutor!(tx)).await?;
        GrantSessionRepository::delete_all_for_grant(grant_id, uexecutor!(tx)).await?;
        AuthRevocation::notify_grant_in_transaction(grant_id, uexecutor!(tx)).await?;
        tx.commit().await?;
        Ok(())
    }

    /// List all active (non-revoked, non-expired) grants for a user.
    pub async fn list_active_grants(
        &self,
        user_id: i32,
    ) -> Result<Vec<GrantEntity>, AuthServiceError> {
        Ok(GrantRepository::list_active_for_user(user_id, &mut self.sql_db.pool().into()).await?)
    }

    /// Return session info for a grant session.
    pub async fn get_grant_session_info(
        &self,
        session: &GrantSession,
    ) -> Result<GrantSessionInfo, AuthServiceError> {
        let grant = self.get_grant(&session.grant_id).await?;

        Ok(GrantSessionInfo {
            homeserver: self.homeserver_public_key.clone(),
            pubky: session.user_key.clone(),
            client_id: grant.client_id.clone(),
            capabilities: session.capabilities.to_vec(),
            grant_id: session.grant_id.clone(),
            token_expires_at: session.token_expires_at,
            grant_expires_at: grant.expires_at as u64,
            created_at: grant.created_at.and_utc().timestamp() as u64,
        })
    }

    /// Sign out: Revoke its grant and delete all sessions.
    pub async fn signout_grant_session(
        &self,
        session: &GrantSession,
    ) -> Result<(), AuthServiceError> {
        self.revoke_grant(&session.grant_id).await
    }

    /// Resolve an opaque bearer into a `GrantSession`.
    ///
    /// Hashes the bearer, looks up the matching session row, loads the
    /// backing grant (with JOINed user pubkey), and asserts the grant is
    /// still active.
    pub async fn resolve_grant_session_by_bearer(
        &self,
        bearer: &SessionBearer,
    ) -> Result<GrantSession, AuthServiceError> {
        let hash = bearer.hash();
        let session = map_not_found(
            GrantSessionRepository::get_by_token_hash(&hash, &mut self.sql_db.pool().into()).await,
            AuthServiceError::SessionNotFound,
        )?;

        let grant = self.validate_active_grant_session_entity(&session).await?;

        Ok(GrantSession {
            user_key: grant.user_pubkey.clone(),
            capabilities: grant.capabilities,
            grant_id: session.grant_id,
            token_expires_at: session.expires_at as u64,
            token_hash: session.token_hash,
        })
    }

    /// Resolve the database user ID from an auth session.
    pub async fn resolve_user_id(&self, auth: &AuthSession) -> Result<i32, AuthServiceError> {
        match auth {
            AuthSession::Grant(b) => {
                let grant = self.get_grant(&b.grant_id).await?;
                Ok(grant.user_id)
            }
            AuthSession::Cookie(c) => Ok(c.user_id),
        }
    }

    /// Check that the session has root capability.
    pub fn require_root_capability(auth: &AuthSession) -> Result<(), AuthServiceError> {
        if auth.capabilities().iter().any(|cap| cap.is_root()) {
            Ok(())
        } else {
            Err(AuthServiceError::RootCapabilityRequired)
        }
    }

    // ── Private helpers ─────────────────────────────────────────────────

    /// Recheck that this exact bearer session row still exists before opening
    /// a private long-lived stream.
    pub(crate) async fn validate_active_grant_session(
        &self,
        session: &GrantSession,
    ) -> Result<GrantEntity, AuthServiceError> {
        let persisted = map_not_found(
            GrantSessionRepository::get_by_token_hash(
                &session.token_hash,
                &mut self.sql_db.pool().into(),
            )
            .await,
            AuthServiceError::SessionNotFound,
        )?;

        if persisted.grant_id != session.grant_id {
            return Err(AuthServiceError::SessionNotFound);
        }

        self.validate_active_grant_session_entity(&persisted).await
    }

    async fn validate_active_grant_session_entity(
        &self,
        session: &GrantSessionEntity,
    ) -> Result<GrantEntity, AuthServiceError> {
        let now = Utc::now().timestamp();
        if session.expires_at <= now {
            return Err(AuthServiceError::SessionExpired);
        }

        let grant = self.get_grant(&session.grant_id).await?;
        grant.require_active(now)?;
        Ok(grant)
    }

    /// Shared verification pipeline: verify grant → check revocation → verify PoP → check nonce.
    async fn verify_grant_and_pop(
        &self,
        grant_jws: &JwsCompact,
        pop_jws: &JwsCompact,
    ) -> Result<GrantClaims, AuthServiceError> {
        let grant = self.verify_grant(grant_jws)?;
        self.check_grant_not_revoked(&grant).await?;
        let pop = self.verify_pop_proof(pop_jws, &grant)?;
        self.check_nonce_replay(&pop).await?;
        Ok(grant)
    }

    /// Signup grants use the grant + PoP wire shape but are never persisted.
    async fn verify_signup_grant_and_pop(
        &self,
        grant_jws: &JwsCompact,
        pop_jws: &JwsCompact,
    ) -> Result<GrantClaims, AuthServiceError> {
        let grant = self.verify_grant(grant_jws)?;
        Self::require_signup_client_id(&grant)?;
        Self::require_root_capability_claim(&grant)?;
        Self::require_short_signup_lifetime(&grant)?;
        let pop = self.verify_pop_proof(pop_jws, &grant)?;
        self.check_nonce_replay(&pop).await?;
        Ok(grant)
    }

    fn require_signup_client_id(grant: &GrantClaims) -> Result<(), AuthServiceError> {
        if grant.client_id.as_str() == SIGNUP_CLIENT_ID {
            return Ok(());
        }
        Err(AuthServiceError::InvalidSignupGrant(
            "signup grants must use client_id pubky.signup".into(),
        ))
    }

    fn require_root_capability_claim(grant: &GrantClaims) -> Result<(), AuthServiceError> {
        if grant.caps.iter().any(|cap| cap.is_root()) {
            return Ok(());
        }
        Err(AuthServiceError::RootCapabilityRequired)
    }

    fn require_short_signup_lifetime(grant: &GrantClaims) -> Result<(), AuthServiceError> {
        let now = Utc::now().timestamp() as u64;
        if grant.iat > now + POP_MAX_AGE_SECS {
            return Err(AuthServiceError::InvalidSignupGrant(
                "signup grant iat is too far in the future".into(),
            ));
        }
        if grant.exp.saturating_sub(grant.iat) > MAX_SIGNUP_GRANT_LIFETIME_SECS {
            return Err(AuthServiceError::InvalidSignupGrant(
                "signup grant lifetime exceeds 5 minutes".into(),
            ));
        }
        Ok(())
    }

    /// Shared tail: persist grant → mint grant session.
    /// No tx needed because store_grant is idempotent and mint_session only creates a session row.
    async fn store_and_mint(
        &self,
        grant: &GrantClaims,
        user: &UserEntity,
    ) -> Result<GrantSessionResponse, AuthServiceError> {
        Self::store_grant(grant, user, &mut self.sql_db.pool().into()).await?;
        self.mint_session(grant, &mut self.sql_db.pool().into())
            .await
    }

    /// Look up a grant by ID. Returns `GrantNotFound` if missing.
    async fn get_grant(&self, grant_id: &GrantId) -> Result<GrantEntity, AuthServiceError> {
        map_not_found(
            GrantRepository::get_by_id(grant_id, &mut self.sql_db.pool().into()).await,
            AuthServiceError::GrantNotFound,
        )
    }

    /// Verify the grant JWS signature, type header, and expiry.
    fn verify_grant(&self, compact: &JwsCompact) -> Result<GrantClaims, AuthServiceError> {
        Ok(verify_grant(compact)?)
    }

    /// Look up the user identified by the grant's `iss` claim. Returns error if not found.
    async fn find_user(&self, grant: &GrantClaims) -> Result<UserEntity, AuthServiceError> {
        map_not_found(
            self.user_service.get(&grant.iss).await,
            AuthServiceError::UserNotFound,
        )
    }

    /// Verify the PoP proof signature, audience, grant binding, and timestamp window.
    fn verify_pop_proof(
        &self,
        compact: &JwsCompact,
        grant: &GrantClaims,
    ) -> Result<PopProof, AuthServiceError> {
        let hs_pubkey_z32 = self.homeserver_public_key.z32();
        let context = PopVerificationContext {
            cnf_key: &grant.cnf,
            expected_audience: &hs_pubkey_z32,
            expected_grant_id: &grant.jti,
        };
        Ok(PopProof::verify(compact, &context)?)
    }

    /// Reject replayed PoP nonces. Garbage-collects expired nonces first.
    async fn check_nonce_replay(&self, pop: &PopProof) -> Result<(), AuthServiceError> {
        if let Err(e) = PopNonceRepository::garbage_collect(
            POP_NONCE_GC_THRESHOLD_SECS,
            &mut self.sql_db.pool().into(),
        )
        .await
        {
            tracing::warn!("PoP nonce garbage collection failed: {e}");
        }

        PopNonceRepository::check_and_track(&pop.nonce, &mut self.sql_db.pool().into())
            .await
            .map_err(|e| match e {
                PopNonceError::AlreadyUsed => AuthServiceError::NonceReplay,
                PopNonceError::Internal(e) => AuthServiceError::Internal(e),
            })
    }

    /// Verify the grant has not been revoked. A not-yet-stored grant passes (first use).
    async fn check_grant_not_revoked(&self, grant: &GrantClaims) -> Result<(), AuthServiceError> {
        let is_revoked = GrantRepository::is_revoked(&grant.jti, &mut self.sql_db.pool().into())
            .await
            .or_else(|e| match e {
                sqlx::Error::RowNotFound => Ok(false),
                other => Err(AuthServiceError::Internal(other)),
            })?;
        if is_revoked {
            return Err(AuthServiceError::GrantRevoked);
        }
        Ok(())
    }

    /// Persist the grant idempotently (ON CONFLICT DO NOTHING).
    async fn store_grant<'a>(
        grant: &GrantClaims,
        user: &UserEntity,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), AuthServiceError> {
        let new_grant = NewGrant {
            id: grant.jti.clone(),
            user_id: user.id,
            client_id: grant.client_id.clone(),
            client_cnf_key: grant.cnf.z32(),
            capabilities: grant.caps.clone().into(),
            issued_at: grant.iat,
            expires_at: grant.exp,
        };
        GrantRepository::create(&new_grant, executor).await?;
        Ok(())
    }

    /// Generate a fresh opaque bearer, persist its hash, and return the wire response.
    async fn mint_session<'a>(
        &self,
        grant: &GrantClaims,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<GrantSessionResponse, AuthServiceError> {
        let now = Utc::now().timestamp() as u64;
        let expires_at = now + DEFAULT_SESSION_TOKEN_LIFETIME_SECS;
        let bearer = SessionBearer::generate();
        let token_hash = bearer.hash();

        let new_session = NewGrantSession {
            token_hash,
            grant_id: grant.jti.clone(),
            expires_at,
        };
        // Enforces MAX_SESSIONS_PER_GRANT: atomically replaces any prior session row for this grant.
        GrantSessionRepository::replace_for_grant(&new_session, executor).await?;

        Ok(build_session_response(
            bearer.into_string(),
            grant,
            self.homeserver_public_key.clone(),
            expires_at,
            now,
        ))
    }
}

/// Map a `sqlx::Error::RowNotFound` to a specific domain error.
fn map_not_found<T>(
    result: Result<T, sqlx::Error>,
    not_found_err: AuthServiceError,
) -> Result<T, AuthServiceError> {
    result.map_err(|e| match e {
        sqlx::Error::RowNotFound => not_found_err,
        other => AuthServiceError::Internal(other),
    })
}

fn build_session_response(
    token: String,
    grant: &GrantClaims,
    homeserver: PublicKey,
    token_expires_at: u64,
    now: u64,
) -> GrantSessionResponse {
    GrantSessionResponse {
        token,
        session: GrantSessionInfo {
            homeserver,
            pubky: grant.iss.clone(),
            client_id: grant.client_id.clone(),
            capabilities: grant.caps.clone(),
            grant_id: grant.jti.clone(),
            token_expires_at,
            grant_expires_at: grant.exp,
            created_at: now,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::super::crypto::jws_crypto;
    use super::*;
    use crate::persistence::sql::{
        signup_code::{SignupCode, SignupCodeRepository},
        SqlDb,
    };
    use crate::shared::user_quota::UserQuota;
    use crate::SignupMode;
    use pubky_common::{
        auth::{
            jws::{ClientId, GrantId, PopNonce, GRANT_JWS_TYP, POP_JWS_TYP},
            pop::PopProofClaims,
        },
        capabilities::{Capabilities, Capability},
        crypto::{Keypair, PublicKey},
    };

    // ── Helpers ─────────────────────────────────────────────────────

    async fn test_service() -> GrantAuthService {
        test_service_with_signup_mode(SignupMode::Open).await
    }

    async fn test_service_with_signup_mode(signup_mode: SignupMode) -> GrantAuthService {
        let db = SqlDb::test().await;
        let hs_kp = Keypair::random();
        let user_service = crate::services::user_service::UserService::new(db.clone());
        let signup_service = SignupService::new(db.clone(), signup_mode, user_service.clone());
        GrantAuthService::new(db, hs_kp.public_key(), signup_service, user_service)
    }

    async fn create_test_user(service: &GrantAuthService) -> (Keypair, i32) {
        let kp = Keypair::random();
        let user = service.user_service.create(&kp.public_key()).await.unwrap();
        (kp, user.id)
    }

    fn sign_grant(
        user_kp: &Keypair,
        client_kp: &Keypair,
        hs_pubkey: &PublicKey,
    ) -> (JwsCompact, JwsCompact, GrantClaims) {
        sign_grant_with_client_id(user_kp, client_kp, hs_pubkey, "test.app", 3600)
    }

    fn sign_signup_grant(
        user_kp: &Keypair,
        client_kp: &Keypair,
        hs_pubkey: &PublicKey,
    ) -> (JwsCompact, JwsCompact, GrantClaims) {
        sign_grant_with_client_id(
            user_kp,
            client_kp,
            hs_pubkey,
            SIGNUP_CLIENT_ID,
            MAX_SIGNUP_GRANT_LIFETIME_SECS,
        )
    }

    fn sign_grant_with_client_id(
        user_kp: &Keypair,
        client_kp: &Keypair,
        hs_pubkey: &PublicKey,
        client_id: &str,
        lifetime_secs: u64,
    ) -> (JwsCompact, JwsCompact, GrantClaims) {
        let now = Utc::now().timestamp() as u64;
        let raw_grant = GrantClaims {
            iss: user_kp.public_key(),
            client_id: ClientId::new(client_id).unwrap(),
            caps: vec![Capability::root()],
            cnf: client_kp.public_key(),
            jti: GrantId::generate(),
            iat: now,
            exp: now + lifetime_secs,
        };
        let grant_jws = sign_jws(user_kp, GRANT_JWS_TYP, &raw_grant);

        let pop_claims = PopProofClaims {
            aud: hs_pubkey.clone(),
            gid: raw_grant.jti.clone(),
            nonce: PopNonce::generate(),
            iat: now,
        };
        let pop_jws = sign_jws(client_kp, POP_JWS_TYP, &pop_claims);

        (grant_jws, pop_jws, raw_grant)
    }

    fn sign_jws<T: serde::Serialize>(kp: &Keypair, typ: &str, claims: &T) -> JwsCompact {
        let header = jws_crypto::eddsa_header(typ);
        let enc = jws_crypto::encoding_key(kp);
        let token = jsonwebtoken::encode(&header, claims, &enc).unwrap();
        JwsCompact::parse(&token).unwrap()
    }

    // ── create_grant_session ────────────────────────────────────────

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn create_grant_session_happy_path() {
        let service = test_service().await;
        let (user_kp, _user_id) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let response = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();
        assert!(!response.token.is_empty());
        assert_eq!(response.session.pubky, user_kp.public_key());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn create_grant_session_user_not_found() {
        let service = test_service().await;
        let user_kp = Keypair::random(); // user not created
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let err = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::UserNotFound));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn create_grant_session_invalid_grant_signature() {
        let service = test_service().await;
        let (user_kp, _) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let wrong_signer = Keypair::random();

        // Sign grant with wrong key
        let (_, pop_jws, _) = sign_grant(&user_kp, &client_kp, &service.homeserver_public_key());
        let now = Utc::now().timestamp() as u64;
        let raw_grant = GrantClaims {
            iss: user_kp.public_key(),
            client_id: ClientId::new("test.app").unwrap(),
            caps: vec![Capability::root()],
            cnf: client_kp.public_key(),
            jti: GrantId::generate(),
            iat: now,
            exp: now + 3600,
        };
        let bad_grant_jws = sign_jws(&wrong_signer, GRANT_JWS_TYP, &raw_grant);

        let err = service
            .create_grant_session(&bad_grant_jws, &pop_jws)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::InvalidGrant(_)));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn create_grant_session_nonce_replay() {
        let service = test_service().await;
        let (user_kp, _) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let hs_pubkey = service.homeserver_public_key();

        // Create a shared PoP nonce for replay
        let now = Utc::now().timestamp() as u64;
        let grant_id = GrantId::generate();
        let shared_nonce = PopNonce::generate();

        let raw_grant = GrantClaims {
            iss: user_kp.public_key(),
            client_id: ClientId::new("test.app").unwrap(),
            caps: vec![Capability::root()],
            cnf: client_kp.public_key(),
            jti: grant_id.clone(),
            iat: now,
            exp: now + 3600,
        };
        let grant_jws = sign_jws(&user_kp, GRANT_JWS_TYP, &raw_grant);

        let pop_claims = PopProofClaims {
            aud: hs_pubkey.clone(),
            gid: grant_id.clone(),
            nonce: shared_nonce.clone(),
            iat: now,
        };
        let pop_jws = sign_jws(&client_kp, POP_JWS_TYP, &pop_claims);

        // First call succeeds
        service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();

        // Second call with same nonce fails
        let err = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::NonceReplay));
    }

    // ── signup_grant_account ────────────────────────────────────────

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn signup_grant_account_open_mode() {
        let service = test_service().await;
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_signup_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        service
            .signup_grant_account(&grant_jws, &pop_jws, None)
            .await
            .unwrap();
        let user = service
            .user_service
            .get(&user_kp.public_key())
            .await
            .unwrap();
        assert_eq!(user.public_key, user_kp.public_key());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn signup_grant_account_user_already_exists() {
        let service = test_service().await;
        let (user_kp, _) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_signup_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let err = service
            .signup_grant_account(&grant_jws, &pop_jws, None)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::UserAlreadyExists));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn signup_grant_account_token_required_happy_path() {
        let service = test_service_with_signup_mode(SignupMode::TokenRequired).await;
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_signup_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let code_id = SignupCode::random();
        SignupCodeRepository::create(
            &code_id,
            &UserQuota::default(),
            &mut service.sql_db.pool().into(),
        )
        .await
        .unwrap();

        service
            .signup_grant_account(&grant_jws, &pop_jws, Some(&code_id))
            .await
            .unwrap();

        let consumed = SignupCodeRepository::get(&code_id, &mut service.sql_db.pool().into())
            .await
            .unwrap();
        assert_eq!(consumed.used_by, Some(user_kp.public_key()));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn signup_grant_account_token_required_missing_token() {
        let service = test_service_with_signup_mode(SignupMode::TokenRequired).await;
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_signup_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let err = service
            .signup_grant_account(&grant_jws, &pop_jws, None)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::SignupTokenRequired));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn signup_grant_account_token_required_unknown_token() {
        let service = test_service_with_signup_mode(SignupMode::TokenRequired).await;
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_signup_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        // Well-formed but never inserted into the DB.
        let unknown = SignupCode::random();

        let err = service
            .signup_grant_account(&grant_jws, &pop_jws, Some(&unknown))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::InvalidSignupToken));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn signup_grant_account_token_required_already_used() {
        let service = test_service_with_signup_mode(SignupMode::TokenRequired).await;
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_signup_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let code_id = SignupCode::random();
        SignupCodeRepository::create(
            &code_id,
            &UserQuota::default(),
            &mut service.sql_db.pool().into(),
        )
        .await
        .unwrap();
        let prior_user = Keypair::random().public_key();
        SignupCodeRepository::mark_as_used(
            &code_id,
            &prior_user,
            &mut service.sql_db.pool().into(),
        )
        .await
        .unwrap();

        let err = service
            .signup_grant_account(&grant_jws, &pop_jws, Some(&code_id))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::SignupTokenAlreadyUsed));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn signup_grant_account_rejects_wrong_client_id() {
        let service = test_service().await;
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) = sign_grant_with_client_id(
            &user_kp,
            &client_kp,
            &service.homeserver_public_key(),
            "test.app",
            MAX_SIGNUP_GRANT_LIFETIME_SECS,
        );

        let err = service
            .signup_grant_account(&grant_jws, &pop_jws, None)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::InvalidSignupGrant(_)));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn signup_grant_account_rejects_long_lifetime() {
        let service = test_service().await;
        let user_kp = Keypair::random();
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) = sign_grant_with_client_id(
            &user_kp,
            &client_kp,
            &service.homeserver_public_key(),
            SIGNUP_CLIENT_ID,
            MAX_SIGNUP_GRANT_LIFETIME_SECS + 1,
        );

        let err = service
            .signup_grant_account(&grant_jws, &pop_jws, None)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::InvalidSignupGrant(_)));
    }

    // ── revoke_grant + resolve_grant_session_by_bearer ───────────────

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn resolve_grant_session_happy_path() {
        let service = test_service().await;
        let (user_kp, _) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, raw_grant) =
            sign_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let response = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();

        let session = service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&response.token).unwrap())
            .await
            .unwrap();

        assert_eq!(session.user_key, user_kp.public_key());
        assert_eq!(session.grant_id, raw_grant.jti);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn validate_active_grant_session_rejects_rotated_bearer() {
        let service = test_service().await;
        let (user_kp, _) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, raw_grant) =
            sign_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let response = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();
        let session = service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&response.token).unwrap())
            .await
            .unwrap();

        service
            .validate_active_grant_session(&session)
            .await
            .unwrap();

        service
            .mint_session(&raw_grant, &mut service.sql_db.pool().into())
            .await
            .unwrap();

        let err = service
            .validate_active_grant_session(&session)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::SessionNotFound));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn resolve_grant_session_after_revoke() {
        let service = test_service().await;
        let (user_kp, _) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, raw_grant) =
            sign_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let response = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();
        service.revoke_grant(&raw_grant.jti).await.unwrap();

        let err = service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&response.token).unwrap())
            .await
            .unwrap_err();
        // Session was deleted by revoke_grant, so SessionNotFound (or GrantRevoked depending on timing)
        assert!(matches!(
            err,
            AuthServiceError::SessionNotFound | AuthServiceError::GrantRevoked
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn resolve_grant_session_missing_session() {
        let service = test_service().await;

        // A well-formed but unrecognized bearer must resolve to SessionNotFound.
        let unknown = SessionBearer::parse("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG").unwrap();
        let err = service
            .resolve_grant_session_by_bearer(&unknown)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::SessionNotFound));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn resolve_grant_session_expired_session() {
        let service = test_service().await;
        let (user_kp, _) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let response = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();
        let bearer = SessionBearer::parse(&response.token).unwrap();
        let expired_at = Utc::now().timestamp().saturating_sub(1);
        sqlx::query("UPDATE grant_sessions SET expires_at = $1 WHERE token_hash = $2")
            .bind(expired_at)
            .bind(bearer.hash().as_ref().to_vec())
            .execute(service.sql_db.pool())
            .await
            .unwrap();

        let err = service
            .resolve_grant_session_by_bearer(&bearer)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::SessionExpired));
    }

    // ── get_grant_session_info ─────────────────────────────────────

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn get_grant_session_info_happy_path() {
        let service = test_service().await;
        let (user_kp, _) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let response = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();
        let session = service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&response.token).unwrap())
            .await
            .unwrap();

        let info = service.get_grant_session_info(&session).await.unwrap();
        assert_eq!(info.pubky, user_kp.public_key());
        assert_eq!(info.homeserver, service.homeserver_public_key());
    }

    // ── revoke_user_grant ─────────────────────────────────────────

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn revoke_user_grant_ownership_mismatch() {
        let service = test_service().await;
        let (user_a_kp, _) = create_test_user(&service).await;
        let (user_b_kp, _) = create_test_user(&service).await;
        let client_kp = Keypair::random();

        // User A creates a grant session
        let (grant_jws, pop_jws, raw_grant) =
            sign_grant(&user_a_kp, &client_kp, &service.homeserver_public_key());
        service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();

        // User B tries to revoke User A's grant
        let client_b_kp = Keypair::random();
        let (grant_b_jws, pop_b_jws, _) =
            sign_grant(&user_b_kp, &client_b_kp, &service.homeserver_public_key());
        let response_b = service
            .create_grant_session(&grant_b_jws, &pop_b_jws)
            .await
            .unwrap();
        let session_b = service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&response_b.token).unwrap())
            .await
            .unwrap();
        let auth_b = AuthSession::Grant(session_b);

        let err = service
            .revoke_user_grant(&raw_grant.jti, &auth_b)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::GrantOwnershipMismatch));
    }

    // ── list_active_grants ──────────────────────────────────────────

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn list_active_grants_happy_path() {
        let service = test_service().await;
        let (user_kp, user_id) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();

        let grants = service.list_active_grants(user_id).await.unwrap();
        assert_eq!(grants.len(), 1);
    }

    // ── signout_grant_session ──────────────────────────────────────────────

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn signout_grant_session_revokes_grant() {
        let service = test_service().await;
        let (user_kp, _) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let response = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();
        let session = service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&response.token).unwrap())
            .await
            .unwrap();

        service.signout_grant_session(&session).await.unwrap();

        // Session should be gone
        let err = service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&response.token).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AuthServiceError::SessionNotFound | AuthServiceError::GrantRevoked
        ));
    }

    // ── resolve_user_id ─────────────────────────────────────────────

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn resolve_user_id_grant_session() {
        let service = test_service().await;
        let (user_kp, user_id) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let (grant_jws, pop_jws, _) =
            sign_grant(&user_kp, &client_kp, &service.homeserver_public_key());

        let response = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();
        let session = service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&response.token).unwrap())
            .await
            .unwrap();

        let resolved = service
            .resolve_user_id(&AuthSession::Grant(session))
            .await
            .unwrap();
        assert_eq!(resolved, user_id);
    }

    // ── require_root_capability ─────────────────────────────────────

    #[test]
    fn require_root_capability_passes_with_root() {
        let session = GrantSession::test(
            Keypair::random().public_key(),
            Capabilities::builder().cap(Capability::root()).finish(),
            GrantId::generate(),
            0,
        );
        assert!(GrantAuthService::require_root_capability(&AuthSession::Grant(session)).is_ok());
    }

    #[test]
    fn require_root_capability_fails_without_root() {
        let session = GrantSession::test(
            Keypair::random().public_key(),
            Capabilities::builder()
                .cap(Capability::read("/").unwrap())
                .finish(),
            GrantId::generate(),
            0,
        );
        let err =
            GrantAuthService::require_root_capability(&AuthSession::Grant(session)).unwrap_err();
        assert!(matches!(err, AuthServiceError::RootCapabilityRequired));
    }
}
