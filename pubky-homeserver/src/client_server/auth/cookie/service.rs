//! Cookie auth service — orchestrates deprecated cookie auth use cases.

use pubky_common::{
    auth::AuthToken, capabilities::Capabilities, crypto::PublicKey, session::CookieSessionRecord,
};

use crate::persistence::sql::{signup_code::SignupCode, uexecutor, user::UserRepository, SqlDb};
use crate::shared::{HttpError, HttpResult};

use super::persistence::{SessionEntity, SessionRepository, SessionSecret};
use super::verifier::CookieAuthVerifier;
use crate::client_server::auth::{AuthRevocation, AuthSession, SignupService};

#[derive(Clone, Debug)]
pub(crate) struct CookieAuthService {
    sql_db: SqlDb,
    verifier: CookieAuthVerifier,
    signup_service: SignupService,
}

impl CookieAuthService {
    pub(crate) fn new(
        sql_db: SqlDb,
        verifier: CookieAuthVerifier,
        signup_service: SignupService,
    ) -> Self {
        Self {
            sql_db,
            verifier,
            signup_service,
        }
    }

    pub(crate) async fn signup(
        &self,
        body: &[u8],
        signup_token: Option<&SignupCode>,
    ) -> HttpResult<CookieSessionCreation> {
        let token = self.verify(body)?;
        let user = self
            .signup_service
            .create_new_user(token.public_key(), signup_token)
            .await?;
        let session_secret = self.create_session(user.id, token.capabilities()).await?;

        Ok(CookieSessionCreation {
            public_key: user.public_key,
            session_secret,
            capabilities: token.capabilities().clone(),
        })
    }

    pub(crate) async fn signin(&self, body: &[u8]) -> HttpResult<CookieSessionCreation> {
        let token = self.verify(body)?;
        let public_key = token.public_key();
        let user = UserRepository::get(public_key, &mut self.sql_db.pool().into())
            .await
            .map_err(|e| match e {
                sqlx::Error::RowNotFound => HttpError::not_found(),
                e => e.into(),
            })?;
        let session_secret = self.create_session(user.id, token.capabilities()).await?;

        Ok(CookieSessionCreation {
            public_key: user.public_key,
            session_secret,
            capabilities: token.capabilities().clone(),
        })
    }

    pub(crate) async fn resolve_session_from_cookie(
        &self,
        cookie_value: Option<String>,
        public_key: &PublicKey,
    ) -> Option<AuthSession> {
        let session_secret = SessionSecret::new(cookie_value?).ok()?;
        let session = self
            .resolve_active_session_for_user(&session_secret, public_key)
            .await
            .ok()
            .flatten()?;

        Some(AuthSession::Cookie(session))
    }

    pub(crate) async fn signout(&self, auth: Option<AuthSession>) -> HttpResult<()> {
        if let Some(AuthSession::Cookie(cookie_session)) = auth {
            let mut tx = self.sql_db.pool().begin().await?;
            SessionRepository::delete(&cookie_session.secret, uexecutor!(tx)).await?;
            AuthRevocation::notify_cookie_session_in_transaction(cookie_session.id, uexecutor!(tx))
                .await?;
            tx.commit().await?;
        }

        Ok(())
    }

    /// Recheck that this exact session row still exists before opening a
    /// private long-lived stream.
    pub(crate) async fn validate_active_session(&self, session: &SessionEntity) -> HttpResult<()> {
        match self
            .resolve_active_session_for_user(&session.secret, &session.user_pubkey)
            .await
        {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(HttpError::unauthorized()),
            Err(sqlx::Error::RowNotFound) => Err(HttpError::unauthorized()),
            Err(error) => Err(error.into()),
        }
    }

    fn verify(&self, body: &[u8]) -> Result<AuthToken, pubky_common::auth::Error> {
        self.verifier.verify(body)
    }

    async fn create_session(
        &self,
        user_id: i32,
        capabilities: &Capabilities,
    ) -> Result<SessionSecret, sqlx::Error> {
        SessionRepository::create(user_id, capabilities, &mut self.sql_db.pool().into()).await
    }

    async fn get_session(&self, secret: &SessionSecret) -> Result<SessionEntity, sqlx::Error> {
        SessionRepository::get_by_secret(secret, &mut self.sql_db.pool().into()).await
    }

    /// Resolve a cookie session through the same active-row and tenant checks
    /// used by both normal cookie authentication and private stream setup.
    async fn resolve_active_session_for_user(
        &self,
        secret: &SessionSecret,
        public_key: &PublicKey,
    ) -> Result<Option<SessionEntity>, sqlx::Error> {
        let session = self.get_session(secret).await?;
        Ok((&session.user_pubkey == public_key).then_some(session))
    }
}

pub(crate) struct CookieSessionCreation {
    pub(crate) public_key: PublicKey,
    pub(crate) session_secret: SessionSecret,
    pub(crate) capabilities: Capabilities,
}

impl CookieSessionCreation {
    pub(crate) fn to_record(&self) -> CookieSessionRecord {
        CookieSessionRecord::new(&self.public_key, self.capabilities.clone(), None)
    }
}
