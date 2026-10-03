//! Browser persistence and locks injected by the WASM binding.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use pubky_common::auth::grant_session_responses::GrantSessionResponse;
use reqwest::{RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};

use super::{
    credential::{GrantCredential, GrantCredentialState, REFRESH_SLACK_SECS, now_unix},
    grant_exchange::post_grant_session,
};
use crate::{PubkyHttpClient, Result, errors::AuthError};

/// Browser-owned state. A pending exchange may have invalidated the saved bearer.
#[doc(hidden)]
#[derive(Clone, Serialize, Deserialize)]
pub struct SharedGrantSession {
    pub response: GrantSessionResponse,
    pub refresh_pending: bool,
    pub logout_pending: bool,
}

impl fmt::Debug for SharedGrantSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedGrantSession")
            .field("session", &self.response.session)
            .field("refresh_pending", &self.refresh_pending)
            .field("logout_pending", &self.logout_pending)
            .finish_non_exhaustive()
    }
}

/// Acquires a browser lock shared by every credential for the stored grant.
#[doc(hidden)]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait GrantSessionCoordinator: fmt::Debug + Send + Sync {
    async fn acquire(&self, exclusive: bool) -> Result<Box<dyn GrantSessionLease>>;
}

/// Holds the browser lock until dropped. Writes require an exclusive lease.
#[doc(hidden)]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait GrantSessionLease: fmt::Debug + Send + Sync {
    async fn load(&self) -> Result<Option<SharedGrantSession>>;
    async fn store(&self, session: &SharedGrantSession) -> Result<()>;
    async fn remove(&self) -> Result<()>;
}

impl GrantCredentialState {
    pub(super) fn response(&self) -> GrantSessionResponse {
        GrantSessionResponse {
            token: self.bearer.clone(),
            session: self.session.clone(),
        }
    }

    pub(super) fn adopt(&mut self, response: GrantSessionResponse) -> Result<()> {
        let session = &response.session;
        if session.homeserver != self.homeserver_pk
            || session.pubky != self.grant_claims.iss
            || session.grant_id != self.grant_claims.jti
            || session.client_id != self.grant_claims.client_id
            || session.capabilities != self.grant_claims.caps
            || session.grant_expires_at != self.grant_claims.exp
        {
            return Err(
                AuthError::Validation("Shared session does not match its grant".into()).into(),
            );
        }
        self.bearer = response.token;
        self.session = response.session;
        Ok(())
    }
}

impl GrantCredential {
    pub(crate) async fn coordinator(&self) -> Option<Arc<dyn GrantSessionCoordinator>> {
        self.state.lock().await.coordinator.clone()
    }

    /// Join shared state while the caller holds its exclusive browser lease.
    pub(crate) async fn coordinate(
        &self,
        coordinator: Arc<dyn GrantSessionCoordinator>,
        lease: &dyn GrantSessionLease,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        if let Some(shared) = lease.load().await? {
            state.adopt(shared.response)?;
        } else {
            lease
                .store(&SharedGrantSession {
                    response: state.response(),
                    refresh_pending: state.bearer.is_empty(),
                    logout_pending: false,
                })
                .await?;
        }
        state.coordinator = Some(coordinator);
        Ok(())
    }

    pub(crate) async fn refresh_shared(
        &self,
        client: &PubkyHttpClient,
        coordinator: &dyn GrantSessionCoordinator,
        rejected_bearer: Option<&str>,
    ) -> Result<()> {
        let lease = coordinator.acquire(true).await?;
        let mut shared = active_session(lease.as_ref()).await?;
        let mut state = self.state.lock().await;
        state.adopt(shared.response.clone())?;
        if !shared.refresh_pending
            && !state.needs_refresh(now_unix(), REFRESH_SLACK_SECS / 2)
            && rejected_bearer != Some(state.bearer.as_str())
        {
            return Ok(());
        }
        shared.refresh_pending = true;
        lease.store(&shared).await?;
        let response = post_grant_session(
            client,
            &state.grant_jws,
            &state.grant_claims,
            &state.client_signer,
            &state.homeserver_pk,
        )
        .await?;
        shared.response = response;
        shared.refresh_pending = false;
        lease.store(&shared).await?;
        state.adopt(shared.response)
    }

    pub(crate) async fn send_shared(
        &self,
        mut request: RequestBuilder,
        client: &PubkyHttpClient,
        coordinator: &dyn GrantSessionCoordinator,
    ) -> Result<Response> {
        let mut retried = false;
        loop {
            let lease = coordinator.acquire(false).await?;
            let shared = active_session(lease.as_ref()).await?;
            let (bearer, refresh) = {
                let mut state = self.state.lock().await;
                state.adopt(shared.response)?;
                (
                    state.bearer.clone(),
                    shared.refresh_pending
                        || state.needs_refresh(now_unix(), REFRESH_SLACK_SECS / 2),
                )
            };
            if refresh {
                drop(lease);
                self.refresh_shared(client, coordinator, None).await?;
                continue;
            }
            let retry = request.try_clone();
            let response = request.bearer_auth(&bearer).send().await?;
            drop(lease);
            // A delayed exchange from a closed tab can still replace our bearer.
            // Only retry a replayable request rejected before authentication.
            if !retried
                && response.status() == StatusCode::UNAUTHORIZED
                && let Some(retry) = retry
            {
                self.refresh_shared(client, coordinator, Some(&bearer))
                    .await?;
                request = retry;
                retried = true;
                continue;
            }
            return Ok(response);
        }
    }
}

pub(crate) async fn active_session(lease: &dyn GrantSessionLease) -> Result<SharedGrantSession> {
    let shared = lease
        .load()
        .await?
        .ok_or_else(|| AuthError::Validation("Browser session was removed".into()))?;
    if shared.logout_pending {
        return Err(AuthError::Validation("Browser session logout is pending".into()).into());
    }
    Ok(shared)
}
