//! Grant-based route handlers.
//!
//! Grant session creation and grant management endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use pubky_common::auth::{grant_session_responses::GrantInfo, jws::GrantId};
use serde::Deserialize;

use super::crypto::jws_crypto::JwsCompact;
use super::persistence::grant::GrantEntity;
use super::service::GrantAuthService;
use crate::client_server::auth::AuthSession;
use crate::client_server::auth::AuthState;
use crate::persistence::sql::signup_code::SignupCode;
use crate::shared::{HttpError, HttpResult};

// ── Request/response types ─────────────────────────────────────────────────

/// JSON request body for grant-based session creation.
#[derive(Deserialize)]
pub struct CreateGrantSessionRequest {
    /// Grant JWS (user-signed).
    pub grant: JwsCompact,
    /// PoP proof JWS (client-signed).
    pub pop: JwsCompact,
}

/// Query parameters for the signup endpoint.
#[derive(Deserialize)]
pub(crate) struct SignupParams {
    signup_token: Option<String>,
}

fn grant_info_from_entity(g: GrantEntity) -> GrantInfo {
    GrantInfo {
        grant_id: g.id,
        client_id: g.client_id.to_string(),
        capabilities: g.capabilities.to_string(),
        issued_at: g.issued_at as u64,
        expires_at: g.expires_at as u64,
    }
}

fn parse_signup_token(token: Option<String>) -> HttpResult<Option<SignupCode>> {
    token
        .map(SignupCode::new)
        .transpose()
        .map_err(|e| HttpError::bad_request(format!("Invalid signup token format: {e}")))
}

// ── Grant session creation ─────────────────────────────────────────────────

/// `POST /auth/grant/session` — exchange grant + PoP for an opaque bearer.
pub async fn create_grant_session(
    State(state): State<AuthState>,
    Json(request): Json<CreateGrantSessionRequest>,
) -> HttpResult<impl IntoResponse> {
    let response = state
        .grant_auth_service
        .create_grant_session(&request.grant, &request.pop)
        .await?;
    Ok(Json(response))
}

/// `POST /auth/grant/signup` — create a new user with a grant + PoP proof.
///
/// Same input shape as session creation, but does not store the grant or mint a bearer.
/// Optional `signup_token` query param when signup tokens are required.
pub async fn signup(
    State(state): State<AuthState>,
    Query(params): Query<SignupParams>,
    Json(request): Json<CreateGrantSessionRequest>,
) -> HttpResult<impl IntoResponse> {
    let signup_token = parse_signup_token(params.signup_token)?;
    state
        .grant_auth_service
        .signup_grant_account(&request.grant, &request.pop, signup_token.as_ref())
        .await?;
    state.metrics.record_signup();
    Ok(StatusCode::NO_CONTENT)
}

// ── Session info & signout ─────────────────────────────────────────────────

/// `GET /auth/grant/session` — returns grant session info as JSON.
pub async fn get_session(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> HttpResult<impl IntoResponse> {
    let AuthSession::Grant(session) = auth else {
        return Err(HttpError::unauthorized());
    };
    let info = state
        .grant_auth_service
        .get_grant_session_info(&session)
        .await?;
    Ok(Json(info))
}

/// `DELETE /auth/grant/session` — idempotently revokes the grant (if any).
///
/// Takes `Option<AuthSession>` rather than `AuthSession` so a second signout with an
/// already-revoked bearer is a 200 no-op rather than a 401.
pub async fn signout(
    State(state): State<AuthState>,
    auth: Option<AuthSession>,
) -> HttpResult<impl IntoResponse> {
    if let Some(AuthSession::Grant(session)) = auth {
        state
            .grant_auth_service
            .signout_grant_session(&session)
            .await?;
    }
    Ok(StatusCode::OK)
}

// ── Grant management ───────────────────────────────────────────────────────

/// `GET /sessions` — list all active grants for the authenticated user.
///
/// Requires root capability.
pub async fn list_grants(
    State(state): State<AuthState>,
    auth: AuthSession,
) -> HttpResult<impl IntoResponse> {
    GrantAuthService::require_root_capability(&auth)?;

    let user_id = state.grant_auth_service.resolve_user_id(&auth).await?;
    let grants: Vec<GrantInfo> = state
        .grant_auth_service
        .list_active_grants(user_id)
        .await?
        .into_iter()
        .map(grant_info_from_entity)
        .collect();
    Ok(Json(grants))
}

/// `DELETE /session/{gid}` — revoke a specific grant and all its sessions.
///
/// Requires root capability.
pub async fn revoke_grant(
    State(state): State<AuthState>,
    auth: AuthSession,
    Path(grant_id): Path<String>,
) -> HttpResult<impl IntoResponse> {
    GrantAuthService::require_root_capability(&auth)?;

    let grant_id = GrantId::parse(&grant_id).map_err(|_| {
        HttpError::new_with_message(StatusCode::BAD_REQUEST, "Invalid grant ID format")
    })?;

    state
        .grant_auth_service
        .revoke_user_grant(&grant_id, &auth)
        .await?;
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use pubky_common::{
        auth::jws::GrantId,
        capabilities::{Capabilities, Capability},
        crypto::Keypair,
    };

    use crate::client_server::auth::grant::session::GrantSession;

    fn bearer_auth(caps: Capabilities) -> AuthSession {
        let now = chrono::Utc::now().timestamp() as u64;
        AuthSession::Grant(GrantSession::test(
            Keypair::random().public_key(),
            caps,
            GrantId::generate(),
            now + 3600,
        ))
    }

    #[test]
    fn test_require_root_capability_accepts_root() {
        let auth = bearer_auth(Capabilities::builder().cap(Capability::root()).finish());
        assert!(GrantAuthService::require_root_capability(&auth).is_ok());
    }

    #[test]
    fn test_require_root_capability_rejects_read_only() {
        let auth = bearer_auth(Capabilities::builder().read("/").unwrap().finish());
        let err = GrantAuthService::require_root_capability(&auth).unwrap_err();
        let resp = HttpError::from(err).into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_require_root_capability_rejects_scoped_rw() {
        let auth = bearer_auth(
            Capabilities::builder()
                .read_write("/pub/app/")
                .unwrap()
                .finish(),
        );
        let err = GrantAuthService::require_root_capability(&auth).unwrap_err();
        let resp = HttpError::from(err).into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
