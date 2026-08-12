use super::super::app_state::AppState;
use crate::shared::{HttpResult, Z32Pubkey};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

/// Disable a user account.
///
/// # Errors
///
/// - `400` if the pubkey is invalid.
/// - `404` if the user does not exist.
///
pub async fn disable_user(
    State(state): State<AppState>,
    Path(pubkey): Path<Z32Pubkey>,
) -> HttpResult<impl IntoResponse> {
    state.user_service.admin_disable(&pubkey.0).await?;
    Ok((StatusCode::OK, "Ok"))
}

/// Enable a user account.
///
/// # Errors
///
/// - `400` if the pubkey is invalid.
/// - `404` if the user does not exist.
///
pub async fn enable_user(
    State(state): State<AppState>,
    Path(pubkey): Path<Z32Pubkey>,
) -> HttpResult<impl IntoResponse> {
    state.user_service.admin_enable(&pubkey.0).await?;
    Ok((StatusCode::OK, "Ok"))
}

#[cfg(test)]
mod tests {
    use super::super::super::app_state::AppState;
    use super::*;
    use crate::{persistence::files::FileService, AppContext};
    use axum::routing::post;
    use axum::Router;
    use pubky_common::crypto::Keypair;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_disable_enable_user() {
        let context = AppContext::test().await;
        let pubkey = Keypair::random().public_key();

        // Create new user
        context.user_service.create(&pubkey).await.unwrap();

        // Check that the tenant is enabled
        let user = context.user_service.get(&pubkey).await.unwrap();
        assert!(!user.disabled);

        // Setup server
        let app_state = AppState::new(
            context.sql_db.clone(),
            FileService::new_from_context(&context).unwrap(),
            "",
            context.user_service.clone(),
            context.events_service.clone(),
            context.metrics.clone(),
        );
        let router = Router::new()
            .route("/users/{pubkey}/disable", post(disable_user))
            .route("/users/{pubkey}/enable", post(enable_user))
            .with_state(app_state);

        // Disable the tenant
        let server = axum_test::TestServer::new(router).unwrap();
        let pubkey_path = pubkey.z32();
        let response = server
            .post(format!("/users/{}/disable", pubkey_path).as_str())
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);

        // Check that the tenant is disabled
        let user = context.user_service.get(&pubkey).await.unwrap();
        assert!(user.disabled);

        // Enable the tenant again
        let response = server
            .post(format!("/users/{}/enable", pubkey_path).as_str())
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);

        // Check that the tenant is enabled
        let user = context.user_service.get(&pubkey).await.unwrap();
        assert!(!user.disabled);
    }
}
