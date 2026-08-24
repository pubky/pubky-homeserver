//! Auth-specific sub-state for the auth module.

use crate::app_context::AppContext;
use crate::observability::Metrics;
use crate::shared::HttpResult;

use super::cookie::service::CookieAuthService;
use super::{AuthSession, GrantAuthService, RevocationListener};

/// Auth-specific state. Auth route handlers extract this instead of the
/// global `AppState`, keeping the auth module fully self-contained.
#[derive(Clone, Debug)]
pub struct AuthState {
    pub(crate) grant_auth_service: GrantAuthService,
    pub(crate) cookie_auth_service: CookieAuthService,
    pub(crate) metrics: Metrics,
    /// Cross-instance signals that close private SSE streams after revocation.
    pub(crate) revocation_listener: RevocationListener,
}

impl AuthState {
    pub fn new(context: &AppContext) -> Self {
        Self {
            grant_auth_service: GrantAuthService::from_context(context),
            cookie_auth_service: CookieAuthService::from_context(context),
            metrics: context.metrics.clone(),
            revocation_listener: context.revocation_listener.clone(),
        }
    }

    /// Confirm that a session resolved by middleware is still valid immediately
    /// before it authorizes a private long-lived stream.
    pub(crate) async fn validate_private_stream_session(
        &self,
        session: &AuthSession,
    ) -> HttpResult<()> {
        match session {
            AuthSession::Cookie(cookie) => {
                self.cookie_auth_service
                    .validate_active_session(cookie)
                    .await
            }
            AuthSession::Grant(grant) => self
                .grant_auth_service
                .validate_active_grant_session(grant)
                .await
                .map(|_| ())
                .map_err(Into::into),
        }
    }
}
