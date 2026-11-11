//! Parent and child grant exchange, signout, and app reconnection.

use chrono::Utc;
use pubky_common::auth::grant_session_responses::GrantSessionResponse;

use super::GrantAuthService;
use crate::client_server::auth::grant::{
    crypto::{
        grant_verifier::{
            verify_chain, verify_chain_for_revocation, verify_parent, verify_parent_for_revocation,
            GrantChain,
        },
        jws_crypto::JwsCompact,
        pop_verifier::{PopProof, PopVerificationContext},
    },
    persistence::{
        grant::{GrantRepository, NewGrant},
        grant_session::GrantSessionRepository,
    },
    service_error::AuthServiceError,
};
use crate::persistence::sql::uexecutor;

impl GrantAuthService {
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
        let chain = verify_chain(parent_jws, child_jws)?;
        let GrantChain { parent, child } = &chain;
        self.verify_and_track_pop(pop_jws, &child.grant).await?;
        let user = self.find_user(parent).await?;
        let new_parent = NewGrant::parent(parent, user.id);
        let new_child = NewGrant::child(&chain, user.id);
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

    /// Revoke a parent and its children with the parent's key.
    ///
    /// An unseen parent is recorded as revoked, so children issued from it can't
    /// be exchanged later.
    pub(super) async fn signout_parent_with_proof(
        &self,
        parent_jws: &JwsCompact,
        pop_jws: &JwsCompact,
    ) -> Result<(), AuthServiceError> {
        let parent = verify_parent_for_revocation(parent_jws)?;
        self.verify_and_track_pop(pop_jws, &parent).await?;
        let user = self.find_user(&parent).await?;
        let new_parent = NewGrant::parent(&parent, user.id);

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
        let chain = verify_chain_for_revocation(parent_jws, child_jws)?;
        let GrantChain { parent, child } = &chain;
        self.verify_and_track_pop(pop_jws, &child.grant).await?;
        let user = self.find_user(parent).await?;
        let new_parent = NewGrant::parent(parent, user.id);
        let mut new_child = NewGrant::child(&chain, user.id);
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
        let new_parent = NewGrant::parent(&parent, user.id);

        let mut tx = self.sql_db.pool().begin().await?;
        Self::store_grant(&new_parent, uexecutor!(tx))
            .await?
            .require_active(Utc::now().timestamp())?;
        GrantRepository::unblock_app(user.id, &parent.jti, &client_id, uexecutor!(tx)).await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        tests::{create_test_user, pop_for, sign_grant, sign_jws, test_service},
        DEFAULT_SESSION_TOKEN_LIFETIME_SECS,
    };
    use super::*;
    use crate::client_server::auth::{
        grant::{
            crypto::session_token::SessionBearer, persistence::grant::GrantEntity,
            session::GrantSession,
        },
        AuthSession,
    };
    use pubky_common::{
        auth::{
            grant::{ChildGrantClaims, GrantClaims},
            grant_session_responses::GrantKind,
            jws::{
                ClientId, GrantId, PopNonce, CHILD_GRANT_JWS_TYP, GRANT_JWS_TYP,
                PARENT_GRANT_JWS_TYP, POP_JWS_TYP, RECONNECT_JWS_TYP,
            },
            pop::{PopProofClaims, ReconnectProofClaims},
        },
        crypto::Keypair,
    };
    use sqlx::{Postgres, Transaction};

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
        // Signing out an already blocked child must not clear the user's block.
        d.app_signout(&chat).await.unwrap();
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
    async fn parent_revocation_clears_only_its_app_blocks() {
        for with_root_session in [false, true] {
            let d = ParentGrant::new().await;
            let other_parent = d.sibling();
            let root = d.stored_root().await;
            let apps = [d.app(CHAT), d.app(SHOP)];
            let other_app = other_parent.app(CHAT);

            for (parent, app) in [(&d, &apps[0]), (&d, &apps[1]), (&other_parent, &other_app)] {
                parent.exchange(app).await.unwrap();
                parent
                    .service
                    .revoke_user_grant(&app.child.grant.jti, &root)
                    .await
                    .unwrap();
            }

            if with_root_session {
                d.service
                    .revoke_user_grant(&d.parent.jti, &root)
                    .await
                    .unwrap();
            } else {
                d.parent_signout().await.unwrap();
            }

            for app in &apps {
                assert!(!GrantRepository::is_app_blocked(
                    d.user_id,
                    &d.parent.jti,
                    &app.child.grant.client_id,
                    &mut d.service.sql_db.pool().into(),
                )
                .await
                .unwrap());
            }
            assert!(matches!(
                d.exchange(&d.app(CHAT)).await,
                Err(AuthServiceError::GrantRevoked)
            ));
            assert!(matches!(
                other_parent.exchange(&other_parent.app(CHAT)).await,
                Err(AuthServiceError::AppBlocked)
            ));
        }
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
