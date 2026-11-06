//! Auth service facade — orchestrates the full grant-based auth flow.
//!
//! Route handlers call `AuthService` methods instead of orchestrating
//! verification, persistence, and minting steps directly.

use std::collections::HashSet;

use crate::persistence::sql::{signup_code::SignupCode, uexecutor, SqlDb, UnifiedExecutor};
use crate::services::user_service::{UserEntity, UserService};
use chrono::Utc;
use pubky_common::{
    auth::grant::GrantClaims,
    auth::grant_session_responses::{GrantKind, GrantSessionInfo, GrantSessionResponse},
    auth::jws::GrantId,
    crypto::PublicKey,
};
use sqlx::{Postgres, Transaction};

use super::crypto::{
    grant_verifier::{
        is_parent_grant, verify_chain, verify_chain_for_revocation, verify_grant,
        verify_grant_for_revocation, verify_parent, verify_parent_for_revocation, GrantChain,
    },
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

    /// Verify the grant and proof, then replace its current bearer.
    pub async fn create_grant_session(
        &self,
        grant_jws: &JwsCompact,
        pop_jws: &JwsCompact,
    ) -> Result<GrantSessionResponse, AuthServiceError> {
        let grant = self.verify_grant_and_pop(grant_jws, pop_jws).await?;
        let user = self.find_user(&grant).await?;
        let new_grant = NewGrant::from_claims(&grant, user.id, GrantKind::Direct, None);
        Self::store_grant(&new_grant, &mut self.sql_db.pool().into()).await?;
        self.mint_session(&grant).await
    }

    /// Verify a parent, child and proof, then replace the child's current bearer.
    ///
    /// The first exchange of a child records it and replaces the app's previous
    /// child under this parent. Repeating an exchange only rotates the bearer.
    /// Everything after the proof checks runs in one transaction, holding the
    /// parent's lock, so concurrent lifecycle changes under the parent apply one
    /// at a time and can't leave a second active child.
    pub async fn create_child_grant_session(
        &self,
        parent_jws: &JwsCompact,
        child_jws: &JwsCompact,
        pop_jws: &JwsCompact,
    ) -> Result<GrantSessionResponse, AuthServiceError> {
        let GrantChain { parent, child } = verify_chain(parent_jws, child_jws)?;
        self.verify_and_track_pop(pop_jws, &child.grant).await?;
        let user = self.find_user(&parent).await?;
        let new_parent = NewGrant::from_claims(&parent, user.id, GrantKind::Parent, None);
        let new_child = NewGrant::from_claims(
            &child.grant,
            user.id,
            GrantKind::Child,
            Some(parent.jti.clone()),
        );
        let client_id = &child.grant.client_id;
        let now = Utc::now().timestamp();

        let mut tx = self.sql_db.pool().begin().await?;
        Self::store_grant(&new_parent, uexecutor!(tx))
            .await?
            .require_active(now)?;
        if GrantRepository::is_app_blocked(user.id, &parent.jti, client_id, uexecutor!(tx)).await? {
            return Err(AuthServiceError::AppBlocked);
        }
        let stored_child = GrantRepository::get_by_id(&child.grant.jti, uexecutor!(tx)).await;
        match stored_child {
            Ok(_) => {}
            Err(sqlx::Error::RowNotFound) => {
                let replaced =
                    GrantRepository::revoke_children(&parent.jti, Some(client_id), uexecutor!(tx))
                        .await?;
                Self::end_sessions(&replaced, &mut tx).await?;
            }
            Err(e) => return Err(e.into()),
        }
        Self::store_grant(&new_child, uexecutor!(tx))
            .await?
            .require_active(now)?;
        let (session, response) = self.prepare_session(&child.grant);
        GrantSessionRepository::replace_in_tx(&session, &mut tx).await?;
        tx.commit().await?;
        Ok(response)
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

    /// Revoke with grant + PoP, even after bearer or grant expiry.
    /// Fresh proofs allow retries after revocation.
    ///
    /// A parent grant in place of the grant signs out the parent and all
    /// its children.
    pub async fn signout_with_proof(
        &self,
        grant_jws: &JwsCompact,
        pop_jws: &JwsCompact,
    ) -> Result<(), AuthServiceError> {
        if is_parent_grant(grant_jws) {
            return self.signout_parent_with_proof(grant_jws, pop_jws).await;
        }
        let grant = verify_grant_for_revocation(grant_jws)?;
        self.verify_and_track_pop(pop_jws, &grant).await?;
        let stored = self.get_grant(&grant.jti).await?;
        if stored.user_pubkey != grant.iss || stored.client_cnf_key != grant.cnf.z32() {
            return Err(AuthServiceError::GrantOwnershipMismatch);
        }
        self.revoke_grant(&grant.jti).await
    }

    /// Revoke a parent and its children with the parent's key.
    ///
    /// An unseen parent is recorded as revoked, so children issued from it can't
    /// be exchanged later.
    async fn signout_parent_with_proof(
        &self,
        parent_jws: &JwsCompact,
        pop_jws: &JwsCompact,
    ) -> Result<(), AuthServiceError> {
        let parent = verify_parent_for_revocation(parent_jws)?;
        self.verify_and_track_pop(pop_jws, &parent).await?;
        let user = self.find_user(&parent).await?;
        let new_parent = NewGrant::from_claims(&parent, user.id, GrantKind::Parent, None);

        let mut tx = self.sql_db.pool().begin().await?;
        let stored = Self::store_grant(&new_parent, uexecutor!(tx)).await?;
        Self::revoke_in_tx(&stored, false, &mut tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Sign an app out with its child chain and the child's key.
    ///
    /// Leaves the parent and sibling apps usable, and doesn't block the app from
    /// signing in again with a new child. An unseen child is recorded as revoked
    /// without displacing the app's current child.
    pub async fn signout_child_with_proof(
        &self,
        parent_jws: &JwsCompact,
        child_jws: &JwsCompact,
        pop_jws: &JwsCompact,
    ) -> Result<(), AuthServiceError> {
        let GrantChain { parent, child } = verify_chain_for_revocation(parent_jws, child_jws)?;
        self.verify_and_track_pop(pop_jws, &child.grant).await?;
        let user = self.find_user(&parent).await?;
        let new_parent = NewGrant::from_claims(&parent, user.id, GrantKind::Parent, None);
        let mut new_child = NewGrant::from_claims(
            &child.grant,
            user.id,
            GrantKind::Child,
            Some(parent.jti.clone()),
        );
        new_child.revoked_at = Some(Utc::now().timestamp());

        let mut tx = self.sql_db.pool().begin().await?;
        Self::store_grant(&new_parent, uexecutor!(tx)).await?;
        let stored = Self::store_grant(&new_child, uexecutor!(tx)).await?;
        Self::revoke_in_tx(&stored, false, &mut tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Clear an app's reconnection block under a parent.
    ///
    /// Requires a `pubky-reconnect` proof from the parent's key. The app then
    /// needs a new child: a revoked child never becomes active again.
    pub async fn reconnect_app(
        &self,
        parent_jws: &JwsCompact,
        proof_jws: &JwsCompact,
    ) -> Result<(), AuthServiceError> {
        let parent = verify_parent(parent_jws)?;
        let hs_pubkey_z32 = self.homeserver_public_key.z32();
        let context = PopVerificationContext {
            cnf_key: &parent.cnf,
            expected_audience: &hs_pubkey_z32,
            expected_grant_id: &parent.jti,
        };
        let (pop, client_id) = PopProof::verify_reconnect(proof_jws, &context)?;
        self.check_nonce_replay(&pop).await?;
        let user = self.find_user(&parent).await?;
        let new_parent = NewGrant::from_claims(&parent, user.id, GrantKind::Parent, None);

        let mut tx = self.sql_db.pool().begin().await?;
        Self::store_grant(&new_parent, uexecutor!(tx))
            .await?
            .require_active(Utc::now().timestamp())?;
        GrantRepository::unblock_app(user.id, &parent.jti, &client_id, uexecutor!(tx)).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Revoke a grant after verifying it belongs to the authenticated user.
    ///
    /// Revoking a child this way is the user's decision to remove the app, so it
    /// also blocks the app under that parent until it is reconnected.
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
        let mut tx = self.sql_db.pool().begin().await?;
        Self::revoke_in_tx(&grant, true, &mut tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Revoke a grant and delete all its sessions atomically.
    async fn revoke_grant(&self, grant_id: &GrantId) -> Result<(), AuthServiceError> {
        let mut tx = self.sql_db.pool().begin().await?;
        let grant = map_not_found(
            GrantRepository::get_by_id(grant_id, uexecutor!(tx)).await,
            AuthServiceError::GrantNotFound,
        )?;
        Self::revoke_in_tx(&grant, false, &mut tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Revoke a grant according to its stored kind and end the affected sessions.
    ///
    /// A parent takes all its children with it. `block_app` applies to a child:
    /// it blocks the app under the parent and revokes the app's current child,
    /// which may have replaced `grant`.
    async fn revoke_in_tx(
        grant: &GrantEntity,
        block_app: bool,
        tx: &mut Transaction<'static, Postgres>,
    ) -> Result<(), AuthServiceError> {
        let mut revoked = vec![grant.id.clone()];
        if let Some(parent_id) = &grant.parent_id {
            GrantRepository::get_for_update(parent_id, uexecutor!(*tx)).await?;
            if block_app {
                GrantRepository::block_app(
                    grant.user_id,
                    parent_id,
                    &grant.client_id,
                    uexecutor!(*tx),
                )
                .await?;
                let current = GrantRepository::revoke_children(
                    parent_id,
                    Some(&grant.client_id),
                    uexecutor!(*tx),
                )
                .await?;
                // `grant` is listed again when it was still the app's current child.
                revoked.extend(current.into_iter().filter(|id| id != &grant.id));
            }
        } else if grant.kind == GrantKind::Parent {
            GrantRepository::get_for_update(&grant.id, uexecutor!(*tx)).await?;
            revoked
                .extend(GrantRepository::revoke_children(&grant.id, None, uexecutor!(*tx)).await?);
        }
        GrantRepository::revoke(&grant.id, uexecutor!(*tx)).await?;
        Self::end_sessions(&revoked, tx).await
    }

    /// Delete revoked grants' sessions and queue their stream shutdown signals.
    async fn end_sessions(
        grant_ids: &[GrantId],
        tx: &mut Transaction<'static, Postgres>,
    ) -> Result<(), AuthServiceError> {
        for grant_id in grant_ids {
            GrantSessionRepository::delete_all_for_grant(grant_id, uexecutor!(*tx)).await?;
            AuthRevocation::notify_grant_in_transaction(grant_id, uexecutor!(*tx)).await?;
        }
        Ok(())
    }

    /// List all active (non-revoked, non-expired) grants for a user.
    ///
    /// A child appears only while its parent is active too.
    pub async fn list_active_grants(
        &self,
        user_id: i32,
    ) -> Result<Vec<GrantEntity>, AuthServiceError> {
        let mut grants =
            GrantRepository::list_active_for_user(user_id, &mut self.sql_db.pool().into()).await?;
        let active: HashSet<GrantId> = grants.iter().map(|grant| grant.id.clone()).collect();
        grants.retain(|grant| {
            grant
                .parent_id
                .as_ref()
                .is_none_or(|parent_id| active.contains(parent_id))
        });
        Ok(grants)
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
        if let Some(parent_id) = &grant.parent_id {
            let parent = map_not_found(
                GrantRepository::get_parent_state(
                    grant.user_id,
                    parent_id,
                    &grant.client_id,
                    &mut self.sql_db.pool().into(),
                )
                .await,
                AuthServiceError::GrantNotFound,
            )?;
            parent.require_active(now)?;
            if parent.app_blocked {
                return Err(AuthServiceError::AppBlocked);
            }
        }
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
        self.verify_and_track_pop(pop_jws, &grant).await?;
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
        self.verify_and_track_pop(pop_jws, &grant).await?;
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

    /// Verify the PoP proof signature, audience, grant binding, and timestamp window,
    /// then record its nonce so the proof can't be replayed.
    async fn verify_and_track_pop(
        &self,
        compact: &JwsCompact,
        grant: &GrantClaims,
    ) -> Result<(), AuthServiceError> {
        let hs_pubkey_z32 = self.homeserver_public_key.z32();
        let context = PopVerificationContext {
            cnf_key: &grant.cnf,
            expected_audience: &hs_pubkey_z32,
            expected_grant_id: &grant.jti,
        };
        let pop = PopProof::verify(compact, &context)?;
        self.check_nonce_replay(&pop).await
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

    /// Record a grant on first use, lock it, and return its current state.
    ///
    /// Sessions take their user and capabilities from the stored row, and an
    /// existing row for the same client-chosen ID is kept. Refuse a grant that
    /// row doesn't describe, so a grant ID can't be reused by another user or
    /// re-signed with other claims. The capability list is compared as signed:
    /// parsing canonicalizes each entry's actions, so the stored list round-trips
    /// unchanged.
    async fn store_grant<'a>(
        new_grant: &NewGrant,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<GrantEntity, AuthServiceError> {
        GrantRepository::create(new_grant, executor).await?;
        let stored = GrantRepository::get_for_update(&new_grant.id, executor).await?;
        if !stored.has_same_claims(new_grant) {
            return Err(AuthServiceError::GrantClaimsMismatch);
        }
        Ok(stored)
    }

    /// Generate a fresh opaque bearer, persist its hash, and return the wire response.
    async fn mint_session(
        &self,
        grant: &GrantClaims,
    ) -> Result<GrantSessionResponse, AuthServiceError> {
        let (new_session, response) = self.prepare_session(grant);
        GrantSessionRepository::replace_for_grant(&new_session, &self.sql_db).await?;
        Ok(response)
    }

    /// Generate a bearer and build its session record and wire response.
    ///
    /// The bearer can't outlive `grant`. A child never outlives its parent, so
    /// this also caps a child's bearer at the parent's expiry.
    fn prepare_session(&self, grant: &GrantClaims) -> (NewGrantSession, GrantSessionResponse) {
        let now = Utc::now().timestamp() as u64;
        let expires_at = (now + DEFAULT_SESSION_TOKEN_LIFETIME_SECS).min(grant.exp);
        let bearer = SessionBearer::generate();
        let token_hash = bearer.hash();

        let new_session = NewGrantSession {
            token_hash,
            grant_id: grant.jti.clone(),
            expires_at,
        };
        let response = GrantSessionResponse {
            token: bearer.into_string(),
            session: GrantSessionInfo {
                homeserver: self.homeserver_public_key.clone(),
                pubky: grant.iss.clone(),
                client_id: grant.client_id.clone(),
                capabilities: grant.caps.clone(),
                grant_id: grant.jti.clone(),
                token_expires_at: expires_at,
                grant_expires_at: grant.exp,
                created_at: now,
            },
        };
        (new_session, response)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::{
        signup_code::{SignupCode, SignupCodeRepository},
        SqlDb,
    };
    use crate::shared::quota::UserQuota;
    use crate::SignupMode;
    use pubky_common::{
        auth::{
            grant::ChildGrantClaims,
            jws::{
                ClientId, GrantId, PopNonce, CHILD_GRANT_JWS_TYP, GRANT_JWS_TYP,
                PARENT_GRANT_JWS_TYP, POP_JWS_TYP, RECONNECT_JWS_TYP,
            },
            pop::{PopProofClaims, ReconnectProofClaims},
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

    /// A grant session for a fresh user holding `caps`.
    fn session_with(caps: Capabilities) -> AuthSession {
        AuthSession::Grant(GrantSession::test(
            Keypair::random().public_key(),
            caps,
            GrantId::generate(),
            0,
        ))
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
        let (grant_jws, pop_jws) = sign_grant_claims(user_kp, client_kp, hs_pubkey, &raw_grant);
        (grant_jws, pop_jws, raw_grant)
    }

    /// Sign `raw_grant` as the user and a fresh PoP proof for it as the client.
    fn sign_grant_claims(
        user_kp: &Keypair,
        client_kp: &Keypair,
        hs_pubkey: &PublicKey,
        raw_grant: &GrantClaims,
    ) -> (JwsCompact, JwsCompact) {
        let grant_jws = sign_jws(user_kp, GRANT_JWS_TYP, raw_grant);

        let pop_claims = PopProofClaims {
            aud: hs_pubkey.clone(),
            gid: raw_grant.jti.clone(),
            nonce: PopNonce::generate(),
            iat: Utc::now().timestamp() as u64,
        };
        let pop_jws = sign_jws(client_kp, POP_JWS_TYP, &pop_claims);

        (grant_jws, pop_jws)
    }

    fn sign_jws<T: serde::Serialize>(kp: &Keypair, typ: &str, claims: &T) -> JwsCompact {
        let token = pubky_common::auth::jws::sign_jws(kp, typ, claims);
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

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn create_grant_session_rejects_grant_id_owned_by_another_user() {
        let service = test_service().await;
        let (owner_kp, owner_id) = create_test_user(&service).await;
        let (attacker_kp, _) = create_test_user(&service).await;
        let hs_pubkey = service.homeserver_public_key();

        let (grant_jws, pop_jws, owner_grant) =
            sign_grant(&owner_kp, &Keypair::random(), &hs_pubkey);
        let owner_session = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();

        // The attacker signs their own grant and PoP, reusing only the owner's grant ID.
        let attacker_client_kp = Keypair::random();
        let attacker_grant = GrantClaims {
            iss: attacker_kp.public_key(),
            cnf: attacker_client_kp.public_key(),
            ..owner_grant.clone()
        };
        let (grant_jws, pop_jws) = sign_grant_claims(
            &attacker_kp,
            &attacker_client_kp,
            &hs_pubkey,
            &attacker_grant,
        );
        let err = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthServiceError::GrantClaimsMismatch));

        // The owner's bearer and stored grant are untouched.
        let session = service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&owner_session.token).unwrap())
            .await
            .unwrap();
        assert_eq!(session.user_key, owner_kp.public_key());
        let stored = service.get_grant(&owner_grant.jti).await.unwrap();
        assert_eq!(stored.user_id, owner_id);
        assert_eq!(stored.client_cnf_key, owner_grant.cnf.z32());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn create_grant_session_rejects_changed_claims_from_same_user() {
        let service = test_service().await;
        let (user_kp, _) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let hs_pubkey = service.homeserver_public_key();

        let (grant_jws, pop_jws, original) = sign_grant(&user_kp, &client_kp, &hs_pubkey);
        service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();

        let narrower_caps = GrantClaims {
            caps: vec![Capability::read("/pub/").unwrap()],
            ..original.clone()
        };
        let other_client_id = GrantClaims {
            client_id: ClientId::new("other.app").unwrap(),
            ..original.clone()
        };
        let issued_earlier = GrantClaims {
            iat: original.iat - 1,
            ..original.clone()
        };
        let longer_lived = GrantClaims {
            exp: original.exp + 1,
            ..original.clone()
        };
        let new_client_kp = Keypair::random();
        let rebound = GrantClaims {
            cnf: new_client_kp.public_key(),
            ..original.clone()
        };
        for (changed, pop_signer) in [
            (narrower_caps, &client_kp),
            (other_client_id, &client_kp),
            (issued_earlier, &client_kp),
            (longer_lived, &client_kp),
            (rebound, &new_client_kp),
        ] {
            let (grant_jws, pop_jws) =
                sign_grant_claims(&user_kp, pop_signer, &hs_pubkey, &changed);
            let err = service
                .create_grant_session(&grant_jws, &pop_jws)
                .await
                .unwrap_err();
            assert!(matches!(err, AuthServiceError::GrantClaimsMismatch));
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn create_grant_session_allows_re_exchanging_the_same_grant() {
        let service = test_service().await;
        let (user_kp, _) = create_test_user(&service).await;
        let client_kp = Keypair::random();
        let hs_pubkey = service.homeserver_public_key();

        // Unsorted and duplicated capabilities must still match their stored form.
        let now = Utc::now().timestamp() as u64;
        let raw_grant = GrantClaims {
            iss: user_kp.public_key(),
            client_id: ClientId::new("test.app").unwrap(),
            caps: vec![
                Capability::write("/pub/b/").unwrap(),
                Capability::read("/pub/a/").unwrap(),
                Capability::write("/pub/a/").unwrap(),
                Capability::read("/pub/a/").unwrap(),
            ],
            cnf: client_kp.public_key(),
            jti: GrantId::generate(),
            iat: now,
            exp: now + 3600,
        };
        let (grant_jws, pop_jws) = sign_grant_claims(&user_kp, &client_kp, &hs_pubkey, &raw_grant);
        let first = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();

        let (grant_jws, pop_jws) = sign_grant_claims(&user_kp, &client_kp, &hs_pubkey, &raw_grant);
        let second = service
            .create_grant_session(&grant_jws, &pop_jws)
            .await
            .unwrap();
        assert_ne!(first.token, second.token);

        let session = service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&second.token).unwrap())
            .await
            .unwrap();
        assert_eq!(session.user_key, user_kp.public_key());
        assert_eq!(session.capabilities, Capabilities::from(raw_grant.caps));
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

        service.mint_session(&raw_grant).await.unwrap();

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
        let auth = session_with(Capabilities::builder().cap(Capability::root()).finish());
        assert!(GrantAuthService::require_root_capability(&auth).is_ok());
    }

    #[test]
    fn require_root_capability_fails_without_root() {
        let auth = session_with(
            Capabilities::builder()
                .cap(Capability::read("/").unwrap())
                .finish(),
        );
        let err = GrantAuthService::require_root_capability(&auth).unwrap_err();
        assert!(matches!(err, AuthServiceError::RootCapabilityRequired));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn proof_logout_works_after_bearer_expiry_and_rotation() {
        let service = test_service().await;
        let (user, _) = create_test_user(&service).await;
        let client = Keypair::random();
        let (grant_jws, pop, grant) = sign_grant(&user, &client, &service.homeserver_public_key());
        let a = service
            .create_grant_session(&grant_jws, &pop)
            .await
            .unwrap();
        sqlx::query("UPDATE grant_sessions SET expires_at = 0 WHERE grant_id = $1")
            .bind(grant.jti.to_string())
            .execute(service.sql_db.pool())
            .await
            .unwrap();
        let b = service.mint_session(&grant).await.unwrap();
        assert!(service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&a.token).unwrap())
            .await
            .is_err());
        for _ in 0..2 {
            let proof = sign_jws(
                &client,
                POP_JWS_TYP,
                &PopProofClaims {
                    aud: service.homeserver_public_key(),
                    gid: grant.jti.clone(),
                    nonce: PopNonce::generate(),
                    iat: Utc::now().timestamp() as u64,
                },
            );
            service
                .signout_with_proof(&grant_jws, &proof)
                .await
                .unwrap();
        }
        assert!(service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&b.token).unwrap())
            .await
            .is_err());
        assert!(matches!(
            service.mint_session(&grant).await,
            Err(AuthServiceError::GrantRevoked)
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn proof_logout_accepts_expired_grants_but_session_issuance_does_not() {
        let service = test_service().await;
        let (user, _) = create_test_user(&service).await;
        let client = Keypair::random();
        let (grant_jws, _, grant) = sign_grant_with_client_id(
            &user,
            &client,
            &service.homeserver_public_key(),
            "test.app",
            0,
        );
        let stored_user = service.find_user(&grant).await.unwrap();
        let new_grant = NewGrant::from_claims(&grant, stored_user.id, GrantKind::Direct, None);
        GrantAuthService::store_grant(&new_grant, &mut service.sql_db.pool().into())
            .await
            .unwrap();

        for _ in 0..2 {
            let proof = sign_jws(
                &client,
                POP_JWS_TYP,
                &PopProofClaims {
                    aud: service.homeserver_public_key(),
                    gid: grant.jti.clone(),
                    nonce: PopNonce::generate(),
                    iat: Utc::now().timestamp() as u64,
                },
            );
            assert!(matches!(
                service.create_grant_session(&grant_jws, &proof).await,
                Err(AuthServiceError::InvalidGrant(
                    super::super::crypto::grant_verifier::Error::Expired
                ))
            ));
            service
                .signout_with_proof(&grant_jws, &proof)
                .await
                .unwrap();
            assert!(service
                .get_grant(&grant.jti)
                .await
                .unwrap()
                .revoked_at
                .is_some());
            assert!(matches!(
                service.signout_with_proof(&grant_jws, &proof).await,
                Err(AuthServiceError::NonceReplay)
            ));
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn proof_logout_requires_the_grants_client_key() {
        let service = test_service().await;
        let (user, _) = create_test_user(&service).await;
        let client = Keypair::random();
        let (grant_jws, pop, grant) = sign_grant(&user, &client, &service.homeserver_public_key());
        let a = service
            .create_grant_session(&grant_jws, &pop)
            .await
            .unwrap();
        let proof = sign_jws(
            &Keypair::random(),
            POP_JWS_TYP,
            &PopProofClaims {
                aud: service.homeserver_public_key(),
                gid: grant.jti,
                nonce: PopNonce::generate(),
                iat: Utc::now().timestamp() as u64,
            },
        );
        assert!(matches!(
            service.signout_with_proof(&grant_jws, &proof).await,
            Err(AuthServiceError::InvalidPopProof(_))
        ));
        service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&a.token).unwrap())
            .await
            .unwrap();
    }

    // ── Repeated grant IDs ──────────────────────────────────────────

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn repeated_grant_id_with_changed_claims_is_rejected() {
        let service = test_service().await;
        let (user, _) = create_test_user(&service).await;
        let (other_user, _) = create_test_user(&service).await;
        let client = Keypair::random();
        let hs = service.homeserver_public_key();
        let (grant_jws, pop, grant) = sign_grant(&user, &client, &hs);
        let response = service
            .create_grant_session(&grant_jws, &pop)
            .await
            .unwrap();

        // The same grant keeps working.
        let same = pop_for(&service, &client, &grant.jti);
        service
            .create_grant_session(&grant_jws, &same)
            .await
            .unwrap();
        let bearer = SessionBearer::parse(&response.token).unwrap();
        assert!(service
            .resolve_grant_session_by_bearer(&bearer)
            .await
            .is_err());

        let with_caps = GrantClaims {
            caps: vec!["/pub/:r".parse().unwrap()],
            ..grant.clone()
        };
        let with_expiry = GrantClaims {
            exp: grant.exp + 60,
            ..grant.clone()
        };
        let with_client = GrantClaims {
            client_id: ClientId::new("other.app").unwrap(),
            ..grant.clone()
        };
        let with_user = GrantClaims {
            iss: other_user.public_key(),
            ..grant.clone()
        };
        for (signer, claims) in [
            (&user, &with_caps),
            (&user, &with_expiry),
            (&user, &with_client),
            (&other_user, &with_user),
        ] {
            let jws = sign_jws(signer, GRANT_JWS_TYP, claims);
            let proof = pop_for(&service, &client, &grant.jti);
            assert!(matches!(
                service.create_grant_session(&jws, &proof).await,
                Err(AuthServiceError::GrantClaimsMismatch)
            ));
        }

        // The original grant still resolves to its own user and capabilities.
        let proof = pop_for(&service, &client, &grant.jti);
        let response = service
            .create_grant_session(&grant_jws, &proof)
            .await
            .unwrap();
        let session = service
            .resolve_grant_session_by_bearer(&SessionBearer::parse(&response.token).unwrap())
            .await
            .unwrap();
        assert_eq!(session.user_key, user.public_key());
    }

    // ── Child grants ────────────────────────────────────────────────

    const CHAT: &str = "https://chat.example/auth/callback";
    const SHOP: &str = "https://shop.example/auth/callback";

    /// A user with a parent grant held by an Accounts key.
    struct ParentGrant {
        service: GrantAuthService,
        user: Keypair,
        user_id: i32,
        accounts: Keypair,
        parent: GrantClaims,
    }

    /// A child grant with the app key that holds it.
    #[derive(Clone)]
    struct App {
        key: Keypair,
        child: ChildGrantClaims,
    }

    impl ParentGrant {
        async fn new() -> Self {
            let service = test_service().await;
            let (user, user_id) = create_test_user(&service).await;
            Self::for_user(service, user, user_id)
        }

        fn for_user(service: GrantAuthService, user: Keypair, user_id: i32) -> Self {
            let accounts = Keypair::random();
            let now = Utc::now().timestamp() as u64;
            let parent = GrantClaims {
                iss: user.public_key(),
                client_id: ClientId::new("https://accounts.example/auth/callback").unwrap(),
                caps: vec!["/pub/:rwe".parse().unwrap(), "/priv/:rwe".parse().unwrap()],
                cnf: accounts.public_key(),
                jti: GrantId::generate(),
                iat: now,
                exp: now + 7200,
            };
            Self {
                service,
                user,
                user_id,
                accounts,
                parent,
            }
        }

        fn sibling(&self) -> Self {
            Self::for_user(self.service.clone(), self.user.clone(), self.user_id)
        }

        fn parent_jws(&self) -> JwsCompact {
            sign_jws(&self.user, PARENT_GRANT_JWS_TYP, &self.parent)
        }

        fn app(&self, callback: &str) -> App {
            let key = Keypair::random();
            let child = ChildGrantClaims {
                grant: GrantClaims {
                    iss: self.user.public_key(),
                    client_id: ClientId::new(callback).unwrap(),
                    caps: vec!["/priv/chat/:rw".parse().unwrap()],
                    cnf: key.public_key(),
                    jti: GrantId::generate(),
                    iat: self.parent.iat,
                    exp: self.parent.exp,
                },
                parent_jti: self.parent.jti.clone(),
            };
            App { key, child }
        }

        fn child_jws(&self, app: &App) -> JwsCompact {
            sign_jws(&self.accounts, CHILD_GRANT_JWS_TYP, &app.child)
        }

        async fn exchange(&self, app: &App) -> Result<GrantSessionResponse, AuthServiceError> {
            let pop = pop_for(&self.service, &app.key, &app.child.grant.jti);
            self.service
                .create_child_grant_session(&self.parent_jws(), &self.child_jws(app), &pop)
                .await
        }

        async fn app_signout(&self, app: &App) -> Result<(), AuthServiceError> {
            let pop = pop_for(&self.service, &app.key, &app.child.grant.jti);
            self.service
                .signout_child_with_proof(&self.parent_jws(), &self.child_jws(app), &pop)
                .await
        }

        async fn parent_signout(&self) -> Result<(), AuthServiceError> {
            let pop = pop_for(&self.service, &self.accounts, &self.parent.jti);
            self.service
                .signout_with_proof(&self.parent_jws(), &pop)
                .await
        }

        fn reconnect_proof(&self, signer: &Keypair, typ: &str, callback: &str) -> JwsCompact {
            sign_jws(
                signer,
                typ,
                &ReconnectProofClaims {
                    pop: PopProofClaims {
                        aud: self.service.homeserver_public_key(),
                        gid: self.parent.jti.clone(),
                        nonce: PopNonce::generate(),
                        iat: Utc::now().timestamp() as u64,
                    },
                    client_id: ClientId::new(callback).unwrap(),
                },
            )
        }

        async fn reconnect(&self, callback: &str) -> Result<(), AuthServiceError> {
            let proof = self.reconnect_proof(&self.accounts, RECONNECT_JWS_TYP, callback);
            self.service.reconnect_app(&self.parent_jws(), &proof).await
        }

        /// A stored root session for the user, the authority behind deliberate revocation.
        async fn stored_root(&self) -> AuthSession {
            let client = Keypair::random();
            let (grant_jws, pop, _) =
                sign_grant(&self.user, &client, &self.service.homeserver_public_key());
            let response = self
                .service
                .create_grant_session(&grant_jws, &pop)
                .await
                .unwrap();
            AuthSession::Grant(self.resolve(&response).await.unwrap())
        }

        async fn resolve(
            &self,
            response: &GrantSessionResponse,
        ) -> Result<GrantSession, AuthServiceError> {
            self.service
                .resolve_grant_session_by_bearer(&SessionBearer::parse(&response.token).unwrap())
                .await
        }

        /// The IDs of this parent's children that are not revoked.
        async fn active_children(&self) -> Vec<String> {
            sqlx::query_scalar("SELECT id FROM grants WHERE parent_id = $1 AND revoked_at IS NULL")
                .bind(self.parent.jti.as_str())
                .fetch_all(self.service.sql_db.pool())
                .await
                .unwrap()
        }

        async fn session_count(&self, grant_id: &GrantId) -> i64 {
            sqlx::query_scalar("SELECT count(*) FROM grant_sessions WHERE grant_id = $1")
                .bind(grant_id.as_str())
                .fetch_one(self.service.sql_db.pool())
                .await
                .unwrap()
        }
    }

    fn pop_for(service: &GrantAuthService, key: &Keypair, grant_id: &GrantId) -> JwsCompact {
        sign_jws(
            key,
            POP_JWS_TYP,
            &PopProofClaims {
                aud: service.homeserver_public_key(),
                gid: grant_id.clone(),
                nonce: PopNonce::generate(),
                iat: Utc::now().timestamp() as u64,
            },
        )
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn child_exchange_issues_a_session_with_the_childs_identity_and_rights() {
        let d = ParentGrant::new().await;
        let app = d.app(CHAT);

        let response = d.exchange(&app).await.unwrap();

        let info = &response.session;
        assert_eq!(info.pubky, d.user.public_key());
        assert_eq!(info.client_id.as_str(), CHAT);
        assert_eq!(info.grant_id, app.child.grant.jti);
        assert_eq!(info.grant_expires_at, app.child.grant.exp);
        assert_eq!(info.capabilities, app.child.grant.caps);
        assert!(info.token_expires_at <= info.created_at + DEFAULT_SESSION_TOKEN_LIFETIME_SECS);

        let session = d.resolve(&response).await.unwrap();
        assert_eq!(session.user_key, d.user.public_key());
        assert_eq!(session.capabilities.to_string(), "/priv/chat/:rw");

        let parent = d.service.get_grant(&d.parent.jti).await.unwrap();
        assert_eq!(parent.kind, GrantKind::Parent);
        assert_eq!(parent.parent_id, None);
        let child = d.service.get_grant(&app.child.grant.jti).await.unwrap();
        assert_eq!(child.kind, GrantKind::Child);
        assert_eq!(child.parent_id, Some(d.parent.jti.clone()));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn child_bearer_expires_with_a_short_lived_child() {
        let d = ParentGrant::new().await;
        let mut app = d.app(CHAT);
        app.child.grant.exp = Utc::now().timestamp() as u64 + 60;

        let response = d.exchange(&app).await.unwrap();

        assert_eq!(response.session.token_expires_at, app.child.grant.exp);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn child_exchange_requires_the_childs_key_and_a_fresh_nonce() {
        let d = ParentGrant::new().await;
        let app = d.app(CHAT);
        let (parent, child) = (d.parent_jws(), d.child_jws(&app));

        for wrong_key in [&d.accounts, &d.user] {
            let pop = pop_for(&d.service, wrong_key, &app.child.grant.jti);
            assert!(matches!(
                d.service
                    .create_child_grant_session(&parent, &child, &pop)
                    .await,
                Err(AuthServiceError::InvalidPopProof(_))
            ));
        }

        let parent_bound = pop_for(&d.service, &app.key, &d.parent.jti);
        assert!(matches!(
            d.service
                .create_child_grant_session(&parent, &child, &parent_bound)
                .await,
            Err(AuthServiceError::InvalidPopProof(_))
        ));

        let pop = pop_for(&d.service, &app.key, &app.child.grant.jti);
        d.service
            .create_child_grant_session(&parent, &child, &pop)
            .await
            .unwrap();
        assert!(matches!(
            d.service
                .create_child_grant_session(&parent, &child, &pop)
                .await,
            Err(AuthServiceError::NonceReplay)
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn delegated_grants_are_never_accepted_as_direct_grants() {
        let d = ParentGrant::new().await;
        let app = d.app(CHAT);
        let parent_pop = pop_for(&d.service, &d.accounts, &d.parent.jti);
        let child_pop = pop_for(&d.service, &app.key, &app.child.grant.jti);

        for (grant, pop) in [
            (d.parent_jws(), &parent_pop),
            (d.child_jws(&app), &child_pop),
        ] {
            assert!(matches!(
                d.service.create_grant_session(&grant, pop).await,
                Err(AuthServiceError::InvalidGrant(_))
            ));
            assert!(matches!(
                d.service.signup_grant_account(&grant, pop, None).await,
                Err(AuthServiceError::InvalidGrant(_))
            ));
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn repeated_exchange_rotates_the_bearer_without_replacing_the_child() {
        let d = ParentGrant::new().await;
        let app = d.app(CHAT);

        let first = d.exchange(&app).await.unwrap();
        let second = d.exchange(&app).await.unwrap();

        assert!(matches!(
            d.resolve(&first).await,
            Err(AuthServiceError::SessionNotFound)
        ));
        d.resolve(&second).await.unwrap();
        assert_eq!(
            d.active_children().await,
            vec![app.child.grant.jti.to_string()]
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn changed_chain_claims_under_recorded_ids_are_rejected() {
        let d = ParentGrant::new().await;
        let app = d.app(CHAT);
        d.exchange(&app).await.unwrap();

        let mut changed_child = app.clone();
        changed_child.child.grant.caps = vec!["/pub/:r".parse().unwrap()];
        assert!(matches!(
            d.exchange(&changed_child).await,
            Err(AuthServiceError::GrantClaimsMismatch)
        ));

        // A new parent can't claim the child's ID either.
        let other_parent = d.sibling();
        let mut moved = other_parent.app(CHAT);
        moved.child.grant.jti = app.child.grant.jti.clone();
        assert!(matches!(
            other_parent.exchange(&moved).await,
            Err(AuthServiceError::GrantClaimsMismatch)
        ));

        let mut changed_parent = d.sibling();
        changed_parent.parent.jti = d.parent.jti.clone();
        changed_parent.parent.exp -= 1;
        let mut new_app = changed_parent.app(SHOP);
        new_app.child.grant.exp = changed_parent.parent.exp;
        assert!(matches!(
            changed_parent.exchange(&new_app).await,
            Err(AuthServiceError::GrantClaimsMismatch)
        ));

        // A child can't reuse its parent's ID, and a direct grant can't reuse either.
        let mut parent_id_child = d.app(SHOP);
        parent_id_child.child.grant.jti = d.parent.jti.clone();
        assert!(matches!(
            d.exchange(&parent_id_child).await,
            Err(AuthServiceError::GrantClaimsMismatch)
        ));
        let client = Keypair::random();
        let (_, _, mut direct) = sign_grant(&d.user, &client, &d.service.homeserver_public_key());
        direct.jti = app.child.grant.jti.clone();
        let jws = sign_jws(&d.user, GRANT_JWS_TYP, &direct);
        let pop = pop_for(&d.service, &client, &direct.jti);
        assert!(matches!(
            d.service.create_grant_session(&jws, &pop).await,
            Err(AuthServiceError::GrantClaimsMismatch)
        ));

        assert_eq!(
            d.active_children().await,
            vec![app.child.grant.jti.to_string()]
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn a_new_child_replaces_the_previous_child_for_that_app_and_parent() {
        let d = ParentGrant::new().await;
        let (old, new) = (d.app(CHAT), d.app(CHAT));
        let old_session = d.exchange(&old).await.unwrap();
        let new_session = d.exchange(&new).await.unwrap();

        assert!(d.resolve(&old_session).await.is_err());
        d.resolve(&new_session).await.unwrap();
        assert_eq!(d.session_count(&old.child.grant.jti).await, 0);
        assert_eq!(
            d.active_children().await,
            vec![new.child.grant.jti.to_string()]
        );

        // The replaced child can't come back, and its failed attempt changes nothing.
        assert!(matches!(
            d.exchange(&old).await,
            Err(AuthServiceError::GrantRevoked)
        ));
        d.resolve(&new_session).await.unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn replacement_is_scoped_to_one_app_and_one_parent() {
        let d = ParentGrant::new().await;
        let other_parent = d.sibling();
        let chat = d.exchange(&d.app(CHAT)).await.unwrap();
        let shop = d.exchange(&d.app(SHOP)).await.unwrap();
        let other_chat = other_parent
            .exchange(&other_parent.app(CHAT))
            .await
            .unwrap();

        for session in [&chat, &shop, &other_chat] {
            d.resolve(session).await.unwrap();
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn concurrent_exchanges_leave_one_active_child_with_one_bearer() {
        let d = std::sync::Arc::new(ParentGrant::new().await);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..10 {
            let d = d.clone();
            let app = d.app(CHAT);
            tasks.spawn(async move { d.exchange(&app).await });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }

        let active = d.active_children().await;
        assert_eq!(active.len(), 1);
        let sessions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM grant_sessions s JOIN grants g ON g.id = s.grant_id
             WHERE g.parent_id = $1",
        )
        .bind(d.parent.jti.as_str())
        .fetch_one(d.service.sql_db.pool())
        .await
        .unwrap();
        assert_eq!(sessions, 1);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn app_signout_is_independent_and_leaves_no_block() {
        let d = ParentGrant::new().await;
        let (chat, shop) = (d.app(CHAT), d.app(SHOP));
        let chat_session = d.exchange(&chat).await.unwrap();
        let shop_session = d.exchange(&shop).await.unwrap();

        // Bearer signout.
        d.service
            .signout_grant_session(&d.resolve(&chat_session).await.unwrap())
            .await
            .unwrap();
        assert!(d.resolve(&chat_session).await.is_err());
        d.resolve(&shop_session).await.unwrap();
        assert!(matches!(
            d.exchange(&chat).await,
            Err(AuthServiceError::GrantRevoked)
        ));

        // A new child signs the app in again without a reconnect.
        let new_chat = d.app(CHAT);
        let new_chat_session = d.exchange(&new_chat).await.unwrap();

        // Proof signout, repeatable with fresh nonces.
        for _ in 0..2 {
            d.app_signout(&new_chat).await.unwrap();
        }
        assert!(d.resolve(&new_chat_session).await.is_err());
        d.resolve(&shop_session).await.unwrap();
        d.exchange(&d.app(CHAT)).await.unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn app_signout_requires_the_childs_key() {
        let d = ParentGrant::new().await;
        let app = d.app(CHAT);
        let session = d.exchange(&app).await.unwrap();

        let pop = pop_for(&d.service, &d.accounts, &app.child.grant.jti);
        assert!(matches!(
            d.service
                .signout_child_with_proof(&d.parent_jws(), &d.child_jws(&app), &pop)
                .await,
            Err(AuthServiceError::InvalidPopProof(_))
        ));
        d.resolve(&session).await.unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn unseen_child_signout_records_it_revoked_without_displacing_the_current_child() {
        let d = ParentGrant::new().await;
        let current = d.app(CHAT);
        let session = d.exchange(&current).await.unwrap();
        let unseen = d.app(CHAT);

        d.app_signout(&unseen).await.unwrap();

        d.resolve(&session).await.unwrap();
        assert!(matches!(
            d.exchange(&unseen).await,
            Err(AuthServiceError::GrantRevoked)
        ));
        assert_eq!(
            d.active_children().await,
            vec![current.child.grant.jti.to_string()]
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn proof_signout_accepts_expired_chains() {
        let d = ParentGrant::new().await;
        let mut expired = d.sibling();
        expired.parent.iat = 1000;
        expired.parent.exp = 2000;
        let app = expired.app(CHAT);

        assert!(matches!(
            expired.exchange(&app).await,
            Err(AuthServiceError::InvalidGrant(_))
        ));
        expired.app_signout(&app).await.unwrap();
        expired.parent_signout().await.unwrap();
        assert!(expired
            .service
            .get_grant(&expired.parent.jti)
            .await
            .unwrap()
            .revoked_at
            .is_some());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn root_revocation_blocks_the_app_until_reconnect() {
        let d = ParentGrant::new().await;
        let root = d.stored_root().await;
        let (chat, shop) = (d.app(CHAT), d.app(SHOP));
        let chat_session = d.exchange(&chat).await.unwrap();
        let shop_session = d.exchange(&shop).await.unwrap();

        d.service
            .revoke_user_grant(&chat.child.grant.jti, &root)
            .await
            .unwrap();

        assert!(d.resolve(&chat_session).await.is_err());
        d.resolve(&shop_session).await.unwrap();
        d.exchange(&d.app(SHOP)).await.unwrap();

        let fresh = d.app(CHAT);
        assert!(matches!(
            d.exchange(&fresh).await,
            Err(AuthServiceError::AppBlocked)
        ));
        // The block belongs to this parent only.
        let other_parent = d.sibling();
        other_parent
            .exchange(&other_parent.app(CHAT))
            .await
            .unwrap();

        d.reconnect(CHAT).await.unwrap();

        assert!(matches!(
            d.exchange(&chat).await,
            Err(AuthServiceError::GrantRevoked)
        ));
        d.exchange(&fresh).await.unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn revoking_a_replaced_child_still_revokes_the_apps_current_child() {
        let d = ParentGrant::new().await;
        let root = d.stored_root().await;
        let (old, current) = (d.app(CHAT), d.app(CHAT));
        d.exchange(&old).await.unwrap();
        let session = d.exchange(&current).await.unwrap();

        d.service
            .revoke_user_grant(&old.child.grant.jti, &root)
            .await
            .unwrap();

        assert!(d.resolve(&session).await.is_err());
        assert!(d.active_children().await.is_empty());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn another_users_root_session_cannot_revoke_a_child() {
        let d = ParentGrant::new().await;
        let (other_user, other_user_id) = create_test_user(&d.service).await;
        let other = ParentGrant::for_user(d.service.clone(), other_user, other_user_id);
        let root = other.stored_root().await;
        let app = d.app(CHAT);
        let session = d.exchange(&app).await.unwrap();

        assert!(matches!(
            d.service
                .revoke_user_grant(&app.child.grant.jti, &root)
                .await,
            Err(AuthServiceError::GrantOwnershipMismatch)
        ));
        d.resolve(&session).await.unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn reconnect_requires_a_reconnect_proof_from_the_parents_key_for_that_app() {
        let d = ParentGrant::new().await;
        let root = d.stored_root().await;
        let app = d.app(CHAT);
        d.exchange(&app).await.unwrap();
        d.service
            .revoke_user_grant(&app.child.grant.jti, &root)
            .await
            .unwrap();
        let parent = d.parent_jws();

        // A child's key and an ordinary PoP from the parent's key are both refused.
        for (signer, typ) in [(&app.key, RECONNECT_JWS_TYP), (&d.accounts, POP_JWS_TYP)] {
            let proof = d.reconnect_proof(signer, typ, CHAT);
            assert!(matches!(
                d.service.reconnect_app(&parent, &proof).await,
                Err(AuthServiceError::InvalidPopProof(_))
            ));
        }

        // A proof for another callback doesn't clear this app's block.
        d.reconnect(SHOP).await.unwrap();
        assert!(matches!(
            d.exchange(&d.app(CHAT)).await,
            Err(AuthServiceError::AppBlocked)
        ));

        // A proof can't be replayed.
        let proof = d.reconnect_proof(&d.accounts, RECONNECT_JWS_TYP, CHAT);
        d.service.reconnect_app(&parent, &proof).await.unwrap();
        assert!(matches!(
            d.service.reconnect_app(&parent, &proof).await,
            Err(AuthServiceError::NonceReplay)
        ));

        d.exchange(&d.app(CHAT)).await.unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn reconnect_is_refused_after_the_parent_is_revoked() {
        let d = ParentGrant::new().await;
        d.exchange(&d.app(CHAT)).await.unwrap();
        d.parent_signout().await.unwrap();

        assert!(matches!(
            d.reconnect(CHAT).await,
            Err(AuthServiceError::GrantRevoked)
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn parent_revocation_ends_every_child_including_unexchanged_ones() {
        let d = ParentGrant::new().await;
        let other_parent = d.sibling();
        let (chat, shop) = (d.app(CHAT), d.app(SHOP));
        let chat_session = d.exchange(&chat).await.unwrap();
        let shop_session = d.exchange(&shop).await.unwrap();
        let other_session = other_parent
            .exchange(&other_parent.app(CHAT))
            .await
            .unwrap();
        let unexchanged = d.app("https://vibes.example/auth/callback");

        // Repeatable with fresh nonces, like other proof signouts.
        for _ in 0..2 {
            d.parent_signout().await.unwrap();
        }

        for session in [&chat_session, &shop_session] {
            assert!(d.resolve(session).await.is_err());
        }
        assert!(d.active_children().await.is_empty());
        for app in [&chat, &shop, &unexchanged] {
            assert!(matches!(
                d.exchange(app).await,
                Err(AuthServiceError::GrantRevoked)
            ));
        }
        other_parent.resolve(&other_session).await.unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn root_revocation_of_a_parent_cascades() {
        let d = ParentGrant::new().await;
        let root = d.stored_root().await;
        let app = d.app(CHAT);
        let session = d.exchange(&app).await.unwrap();

        d.service
            .revoke_user_grant(&d.parent.jti, &root)
            .await
            .unwrap();

        assert!(d.resolve(&session).await.is_err());
        assert!(matches!(
            d.exchange(&d.app(SHOP)).await,
            Err(AuthServiceError::GrantRevoked)
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn an_unseen_parent_can_be_recorded_as_revoked() {
        let d = ParentGrant::new().await;

        d.parent_signout().await.unwrap();

        let parent = d.service.get_grant(&d.parent.jti).await.unwrap();
        assert_eq!(parent.kind, GrantKind::Parent);
        assert!(parent.revoked_at.is_some());
        assert!(matches!(
            d.exchange(&d.app(CHAT)).await,
            Err(AuthServiceError::GrantRevoked)
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn parent_signout_requires_the_parents_key() {
        let d = ParentGrant::new().await;
        let app = d.app(CHAT);
        let session = d.exchange(&app).await.unwrap();

        for wrong_key in [&app.key, &d.user] {
            let pop = pop_for(&d.service, wrong_key, &d.parent.jti);
            assert!(matches!(
                d.service.signout_with_proof(&d.parent_jws(), &pop).await,
                Err(AuthServiceError::InvalidPopProof(_))
            ));
        }
        d.resolve(&session).await.unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn bearer_requires_an_active_parent_and_an_unblocked_app() {
        let d = ParentGrant::new().await;
        let app = d.app(CHAT);
        let response = d.exchange(&app).await.unwrap();
        let pool = d.service.sql_db.pool();

        // These records are normally changed with the child in one transaction.
        // Change them alone to prove the request-time check stands by itself.
        GrantRepository::block_app(
            d.user_id,
            &d.parent.jti,
            &app.child.grant.client_id,
            &mut pool.into(),
        )
        .await
        .unwrap();
        assert!(matches!(
            d.resolve(&response).await,
            Err(AuthServiceError::AppBlocked)
        ));
        GrantRepository::unblock_app(
            d.user_id,
            &d.parent.jti,
            &app.child.grant.client_id,
            &mut pool.into(),
        )
        .await
        .unwrap();
        d.resolve(&response).await.unwrap();

        GrantRepository::revoke(&d.parent.jti, &mut pool.into())
            .await
            .unwrap();
        assert!(matches!(
            d.resolve(&response).await,
            Err(AuthServiceError::GrantRevoked)
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn listing_shows_active_parents_and_children_with_their_relationship() {
        let d = ParentGrant::new().await;
        let client = Keypair::random();
        let (grant_jws, pop, direct) =
            sign_grant(&d.user, &client, &d.service.homeserver_public_key());
        d.service
            .create_grant_session(&grant_jws, &pop)
            .await
            .unwrap();
        let app = d.app(CHAT);
        d.exchange(&app).await.unwrap();

        let grants = d.service.list_active_grants(d.user_id).await.unwrap();
        assert_eq!(grants.len(), 3);
        let find = |id: &GrantId| grants.iter().find(|g| &g.id == id).unwrap();
        assert_eq!(find(&direct.jti).kind, GrantKind::Direct);
        assert_eq!(find(&d.parent.jti).kind, GrantKind::Parent);
        let child = find(&app.child.grant.jti);
        assert_eq!(child.kind, GrantKind::Child);
        assert_eq!(child.parent_id.as_ref(), Some(&d.parent.jti));

        // A child whose parent is no longer active is left out, even if its own
        // record is still active.
        GrantRepository::revoke(&d.parent.jti, &mut d.service.sql_db.pool().into())
            .await
            .unwrap();
        let grants = d.service.list_active_grants(d.user_id).await.unwrap();
        assert_eq!(
            grants.iter().map(|g| &g.id).collect::<Vec<_>>(),
            vec![&direct.jti]
        );
    }

    // ── Races ───────────────────────────────────────────────────────
    //
    // Each test holds an uncommitted lifecycle change, starts the competing
    // operation, and commits only once Postgres reports that operation waiting on
    // a lock. This fixes the order instead of relying on timing.

    async fn wait_for_lock_waiter(service: &GrantAuthService) {
        for _ in 0..500 {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname = current_database() AND wait_event_type = 'Lock'",
            )
            .fetch_one(service.sql_db.pool())
            .await
            .unwrap();
            if waiting > 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the competing operation never waited on a lock");
    }

    /// Begin a transaction holding the parent's lock, as lifecycle changes do.
    async fn lock_parent(d: &ParentGrant) -> (Transaction<'static, Postgres>, GrantEntity) {
        let mut tx = d.service.sql_db.pool().begin().await.unwrap();
        let parent = GrantRepository::get_for_update(&d.parent.jti, uexecutor!(tx))
            .await
            .unwrap();
        (tx, parent)
    }

    fn spawn_exchange(
        d: &std::sync::Arc<ParentGrant>,
        app: &App,
    ) -> tokio::task::JoinHandle<Result<GrantSessionResponse, AuthServiceError>> {
        let (d, app) = (d.clone(), app.clone());
        tokio::spawn(async move { d.exchange(&app).await })
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn new_child_waiting_on_parent_revocation_is_rejected() {
        let d = std::sync::Arc::new(ParentGrant::new().await);
        d.exchange(&d.app(SHOP)).await.unwrap();

        let (mut tx, parent) = lock_parent(&d).await;
        GrantAuthService::revoke_in_tx(&parent, false, &mut tx)
            .await
            .unwrap();
        let exchange = spawn_exchange(&d, &d.app(CHAT));
        wait_for_lock_waiter(&d.service).await;
        tx.commit().await.unwrap();

        assert!(matches!(
            exchange.await.unwrap(),
            Err(AuthServiceError::GrantRevoked)
        ));
        assert!(d.active_children().await.is_empty());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn refresh_waiting_on_child_revocation_cannot_restore_access() {
        let d = std::sync::Arc::new(ParentGrant::new().await);
        let app = d.app(CHAT);
        d.exchange(&app).await.unwrap();
        let child = d.service.get_grant(&app.child.grant.jti).await.unwrap();

        let (mut tx, _) = lock_parent(&d).await;
        GrantAuthService::revoke_in_tx(&child, false, &mut tx)
            .await
            .unwrap();
        let refresh = spawn_exchange(&d, &app);
        wait_for_lock_waiter(&d.service).await;
        tx.commit().await.unwrap();

        assert!(matches!(
            refresh.await.unwrap(),
            Err(AuthServiceError::GrantRevoked)
        ));
        assert_eq!(d.session_count(&app.child.grant.jti).await, 0);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn refresh_waiting_on_replacement_cannot_keep_the_old_child() {
        let d = std::sync::Arc::new(ParentGrant::new().await);
        let (old, new) = (d.app(CHAT), d.app(CHAT));
        d.exchange(&old).await.unwrap();

        let (mut tx, _) = lock_parent(&d).await;
        let replaced = GrantRepository::revoke_children(
            &d.parent.jti,
            Some(&old.child.grant.client_id),
            uexecutor!(tx),
        )
        .await
        .unwrap();
        GrantAuthService::end_sessions(&replaced, &mut tx)
            .await
            .unwrap();
        let refresh = spawn_exchange(&d, &old);
        wait_for_lock_waiter(&d.service).await;
        tx.commit().await.unwrap();

        assert!(matches!(
            refresh.await.unwrap(),
            Err(AuthServiceError::GrantRevoked)
        ));
        d.exchange(&new).await.unwrap();
        assert_eq!(
            d.active_children().await,
            vec![new.child.grant.jti.to_string()]
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn exchange_waiting_on_a_block_is_rejected() {
        let d = std::sync::Arc::new(ParentGrant::new().await);
        let app = d.app(CHAT);
        d.exchange(&app).await.unwrap();
        let child = d.service.get_grant(&app.child.grant.jti).await.unwrap();

        let (mut tx, _) = lock_parent(&d).await;
        GrantAuthService::revoke_in_tx(&child, true, &mut tx)
            .await
            .unwrap();
        let exchange = spawn_exchange(&d, &d.app(CHAT));
        wait_for_lock_waiter(&d.service).await;
        tx.commit().await.unwrap();

        assert!(matches!(
            exchange.await.unwrap(),
            Err(AuthServiceError::AppBlocked)
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn exchange_waiting_on_a_reconnect_sees_the_cleared_block() {
        let d = std::sync::Arc::new(ParentGrant::new().await);
        let app = d.app(CHAT);
        d.exchange(&app).await.unwrap();
        let root = d.stored_root().await;
        d.service
            .revoke_user_grant(&app.child.grant.jti, &root)
            .await
            .unwrap();

        let (mut tx, _) = lock_parent(&d).await;
        GrantRepository::unblock_app(
            d.user_id,
            &d.parent.jti,
            &app.child.grant.client_id,
            uexecutor!(tx),
        )
        .await
        .unwrap();
        let fresh = d.app(CHAT);
        let exchange = spawn_exchange(&d, &fresh);
        wait_for_lock_waiter(&d.service).await;
        tx.commit().await.unwrap();

        exchange.await.unwrap().unwrap();
        assert_eq!(
            d.active_children().await,
            vec![fresh.child.grant.jti.to_string()]
        );
    }
}
