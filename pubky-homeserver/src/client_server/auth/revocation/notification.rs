//! The revocation payload and transactional notify helpers.

use pubky_common::auth::jws::GrantId;
use serde::{Deserialize, Serialize};

use crate::client_server::auth::AuthSession;
use crate::persistence::sql::UnifiedExecutor;

use super::PG_AUTH_REVOCATION_CHANNEL;

/// A committed authentication revocation forwarded to active private streams.
///
/// Cookie secrets and bearer tokens are deliberately not present in this
/// payload. Postgres channel consumers only need stable database identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub(crate) enum AuthRevocation {
    /// A deprecated cookie session row was deleted.
    CookieSession(i32),
    /// A grant and all of its bearer sessions were revoked.
    Grant(GrantId),
}

impl AuthRevocation {
    /// Return whether this signal invalidates `session`.
    pub(crate) fn matches(&self, session: &AuthSession) -> bool {
        match (self, session) {
            (Self::CookieSession(id), AuthSession::Cookie(cookie)) => id == &cookie.id,
            (Self::Grant(id), AuthSession::Grant(grant)) => id == &grant.grant_id,
            _ => false,
        }
    }

    /// Queue a cookie-session revocation in the caller's transaction.
    pub(crate) async fn notify_cookie_session_in_transaction<'a>(
        id: i32,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        Self::CookieSession(id)
            .notify_in_transaction(executor)
            .await
    }

    /// Queue a grant revocation in the caller's transaction.
    pub(crate) async fn notify_grant_in_transaction<'a>(
        id: &GrantId,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        Self::Grant(id.clone())
            .notify_in_transaction(executor)
            .await
    }

    /// Queue this notification in the caller's transaction.
    ///
    /// Postgres only delivers a `NOTIFY` at commit. Keeping this alongside the
    /// database mutation means a revocation cannot commit without its shutdown
    /// signal, and a rolled-back mutation never closes streams.
    async fn notify_in_transaction<'a>(
        &self,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let payload =
            serde_json::to_string(self).expect("auth revocation payload is always serializable");
        let con = executor.get_con().await?;
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(PG_AUTH_REVOCATION_CHANNEL)
            .bind(payload)
            .execute(con)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_server::auth::{
        cookie::persistence::{SessionEntity, SessionSecret},
        grant::session::GrantSession,
    };
    use pubky_common::{capabilities::Capabilities, crypto::Keypair};

    fn cookie_session(id: i32) -> AuthSession {
        AuthSession::Cookie(SessionEntity {
            id,
            secret: SessionSecret::random(),
            user_id: 1,
            user_pubkey: Keypair::random().public_key(),
            capabilities: Capabilities::default(),
            created_at: chrono::Utc::now().naive_utc(),
        })
    }

    fn grant_session(id: GrantId) -> AuthSession {
        AuthSession::Grant(GrantSession::test(
            Keypair::random().public_key(),
            Capabilities::default(),
            id,
            u64::MAX,
        ))
    }

    #[test]
    fn revocations_match_only_their_own_authentication_method() {
        let grant_id = GrantId::generate();
        assert!(AuthRevocation::CookieSession(7).matches(&cookie_session(7)));
        assert!(!AuthRevocation::CookieSession(8).matches(&cookie_session(7)));
        assert!(AuthRevocation::Grant(grant_id.clone()).matches(&grant_session(grant_id)));
        assert!(!AuthRevocation::CookieSession(7).matches(&grant_session(GrantId::generate())));
    }

    #[test]
    fn revocations_have_a_stable_wire_format() {
        let cases = [
            (
                AuthRevocation::CookieSession(7),
                serde_json::json!({"kind": "cookie_session", "id": 7}),
            ),
            (
                AuthRevocation::Grant(GrantId::parse("grant-id").unwrap()),
                serde_json::json!({"kind": "grant", "id": "grant-id"}),
            ),
        ];

        for (revocation, expected) in cases {
            let serialized = serde_json::to_value(&revocation).unwrap();
            assert_eq!(serialized, expected);
            assert_eq!(
                serde_json::from_value::<AuthRevocation>(serialized).unwrap(),
                revocation
            );
        }
    }
}
