use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Serialize;

use crate::shared::quota::{UserQuota, UserQuotaPatch};
use crate::shared::{HttpError, HttpResult, Z32Pubkey};

use super::super::app_state::AppState;

/// Response for `GET /users/{pubkey}/quota`.
///
/// Contains both the effective quota (overrides merged with system defaults)
/// and the raw per-user overrides, so callers can see what applies and what
/// was explicitly customised in a single request.
#[derive(Debug, Serialize)]
pub struct UserQuotaResponse {
    /// The effective quota: overrides merged with system defaults.
    /// All fields are always present (no fields omitted).
    pub effective: UserQuota,
    /// Only the per-user overrides. Fields using the system default are omitted.
    pub overrides: UserQuota,
}

/// GET /users/{pubkey}/quota — return both effective and override quotas.
pub async fn get_user_quota(
    State(state): State<AppState>,
    Path(pubkey): Path<Z32Pubkey>,
) -> HttpResult<impl IntoResponse> {
    let user = state
        .context
        .user_service
        .get_or_http_error(&pubkey.0, false)
        .await?;

    let overrides = user.quota();
    let effective = overrides.resolve_with_defaults(
        state.context.config_toml.storage.default_quota_mb,
        &state.context.config_toml.default_quotas,
    );

    Ok(Json(UserQuotaResponse {
        effective,
        overrides,
    }))
}

/// PATCH /users/{pubkey}/quota — update per-user custom limits.
///
/// Only fields present in the JSON body are updated; absent fields are left unchanged.
/// All fields follow the same semantics:
/// - absent → keep existing value
/// - `null` → reset to Default (use system default)
/// - `"unlimited"` → Unlimited (no limit)
/// - value → explicit custom limit
pub async fn patch_user_quota(
    State(state): State<AppState>,
    Path(pubkey): Path<Z32Pubkey>,
    Json(patch): Json<UserQuotaPatch>,
) -> HttpResult<impl IntoResponse> {
    patch
        .validate()
        .map_err(|e| HttpError::new_with_message(StatusCode::UNPROCESSABLE_ENTITY, e))?;

    state
        .context
        .user_service
        .patch_quota(&pubkey.0, &patch)
        .await?;

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use axum_test::TestServer;

    use pubky_common::crypto::Keypair;

    use super::*;
    use crate::admin_server::AdminAuthExt;
    use crate::shared::quota::BandwidthQuota;
    use crate::AppContext;

    fn create_test_server(context: &Arc<AppContext>) -> TestServer {
        AppState::test_server(context)
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_user_quota_crud() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let pubkey = Keypair::random().public_key();

        context.user_service.create(&pubkey).await.unwrap();

        let url = format!("/users/{}/quota", pubkey.z32());

        // GET fresh user: overrides empty, effective all "unlimited" (no system defaults)
        let response = server.get(&url).admin_auth().expect_success().await;
        response.assert_status_ok();
        let json: serde_json::Value = response.json();
        assert_eq!(json["overrides"], serde_json::json!({}));
        assert_eq!(json["effective"]["storage_quota_mb"], "unlimited");
        assert_eq!(json["effective"]["rate_read"], "unlimited");
        assert_eq!(json["effective"]["rate_write"], "unlimited");

        // PATCH with partial body (absent fields = keep existing)
        let body = serde_json::json!({
            "storage_quota_mb": 500,
            "rate_read": "100mb/m"
        });
        server
            .patch(&url)
            .admin_auth()
            .content_type("application/json")
            .bytes(serde_json::to_vec(&body).unwrap().into())
            .expect_success()
            .await;

        // GET after PATCH: effective shows overrides + defaults, overrides shows only patched
        let response = server.get(&url).admin_auth().expect_success().await;
        let json: serde_json::Value = response.json();
        assert_eq!(json["effective"]["storage_quota_mb"], 500);
        assert_eq!(json["effective"]["rate_read"], "100mb/m");
        assert_eq!(json["effective"]["rate_write"], "unlimited");
        assert_eq!(json["overrides"]["storage_quota_mb"], 500);
        assert_eq!(json["overrides"]["rate_read"], "100mb/m");
        assert!(json["overrides"].get("rate_write").is_none());

        // PATCH with null fields to reset to Default
        let body = serde_json::json!({
            "storage_quota_mb": null,
            "rate_read": null,
            "rate_write": null
        });
        server
            .patch(&url)
            .admin_auth()
            .content_type("application/json")
            .bytes(serde_json::to_vec(&body).unwrap().into())
            .expect_success()
            .await;

        // GET after reset: overrides empty again
        let response = server.get(&url).admin_auth().expect_success().await;
        let json: serde_json::Value = response.json();
        assert_eq!(json["overrides"], serde_json::json!({}));
    }

    /// GET resolves Default fields against system-wide defaults in `effective`.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_effective_resolves_defaults() {
        let context = AppContext::test_with_config(|c| {
            c.storage.default_quota_mb = Some(100);
            c.default_quotas.rate_read = Some(BandwidthQuota::from_str("10mb/s").unwrap());
            c.default_quotas.rate_write = Some(BandwidthQuota::from_str("5mb/s").unwrap());
        })
        .await;
        let server = create_test_server(&context);
        let pubkey = Keypair::random().public_key();

        context.user_service.create(&pubkey).await.unwrap();

        let url = format!("/users/{}/quota", pubkey.z32());

        // Fresh user: effective shows system defaults, overrides empty
        let response = server.get(&url).admin_auth().expect_success().await;
        let json: serde_json::Value = response.json();
        assert_eq!(json["effective"]["storage_quota_mb"], 100);
        assert_eq!(json["effective"]["rate_read"], "10mb/s");
        assert_eq!(json["effective"]["rate_write"], "5mb/s");
        assert_eq!(json["overrides"], serde_json::json!({}));

        // PATCH one field to a custom value
        let body = serde_json::json!({"storage_quota_mb": 500});
        server
            .patch(&url)
            .admin_auth()
            .content_type("application/json")
            .bytes(serde_json::to_vec(&body).unwrap().into())
            .expect_success()
            .await;

        // effective: storage overridden, rates still show system defaults
        let response = server.get(&url).admin_auth().expect_success().await;
        let json: serde_json::Value = response.json();
        assert_eq!(json["effective"]["storage_quota_mb"], 500);
        assert_eq!(json["effective"]["rate_read"], "10mb/s");
        assert_eq!(json["effective"]["rate_write"], "5mb/s");
        assert_eq!(json["overrides"]["storage_quota_mb"], 500);
        assert!(json["overrides"].get("rate_read").is_none());

        // PATCH rate_read to unlimited
        let body = serde_json::json!({"rate_read": "unlimited"});
        server
            .patch(&url)
            .admin_auth()
            .content_type("application/json")
            .bytes(serde_json::to_vec(&body).unwrap().into())
            .expect_success()
            .await;

        // effective: unlimited overrides the system default
        let response = server.get(&url).admin_auth().expect_success().await;
        let json: serde_json::Value = response.json();
        assert_eq!(json["effective"]["storage_quota_mb"], 500);
        assert_eq!(json["effective"]["rate_read"], "unlimited");
        assert_eq!(json["effective"]["rate_write"], "5mb/s");
        // overrides shows only the two explicit overrides
        assert_eq!(json["overrides"]["storage_quota_mb"], 500);
        assert_eq!(json["overrides"]["rate_read"], "unlimited");
        assert!(json["overrides"].get("rate_write").is_none());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_user_quota_invalid_rate_rejected() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let pubkey = Keypair::random().public_key();

        context.user_service.create(&pubkey).await.unwrap();

        let url = format!("/users/{}/quota", pubkey.z32());

        let body = serde_json::json!({
            "rate_read": "rubbish"
        });
        let response = server
            .patch(&url)
            .admin_auth()
            .content_type("application/json")
            .bytes(serde_json::to_vec(&body).unwrap().into())
            .expect_failure()
            .await;
        response.assert_status(axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_user_quota_nonexistent_user() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let pubkey = pubky_common::crypto::Keypair::random().public_key();

        let url = format!("/users/{}/quota", pubkey.z32());

        let response = server.get(&url).admin_auth().expect_failure().await;
        response.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    /// Default vs Unlimited are distinguishable in the overrides section.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_default_vs_unlimited_distinguishable() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let pubkey = Keypair::random().public_key();

        context.user_service.create(&pubkey).await.unwrap();

        let url = format!("/users/{}/quota", pubkey.z32());

        // PATCH: rate_read = "unlimited", rate_write absent (unchanged = Default)
        let body = serde_json::json!({
            "rate_read": "unlimited"
        });
        server
            .patch(&url)
            .admin_auth()
            .content_type("application/json")
            .bytes(serde_json::to_vec(&body).unwrap().into())
            .expect_success()
            .await;

        let response = server.get(&url).admin_auth().expect_success().await;
        let json: serde_json::Value = response.json();
        // Unlimited → present as "unlimited" in overrides
        assert_eq!(json["overrides"]["rate_read"], "unlimited");
        // Default → absent from overrides
        assert!(json["overrides"].get("rate_write").is_none());
        assert!(json["overrides"].get("storage_quota_mb").is_none());
    }

    /// PATCH only updates the fields present in the body; absent fields are left unchanged.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_patch_user_quota_merges() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let pubkey = Keypair::random().public_key();

        context.user_service.create(&pubkey).await.unwrap();

        let url = format!("/users/{}/quota", pubkey.z32());

        // 1) Set all fields
        let body = serde_json::json!({
            "storage_quota_mb": 500,
            "rate_read": "100mb/m",
            "rate_write": "50mb/m"
        });
        server
            .patch(&url)
            .admin_auth()
            .content_type("application/json")
            .bytes(serde_json::to_vec(&body).unwrap().into())
            .expect_success()
            .await;

        // 2) PATCH only storage_quota_mb — others should be unchanged
        let patch = serde_json::json!({
            "storage_quota_mb": 200
        });
        server
            .patch(&url)
            .admin_auth()
            .content_type("application/json")
            .bytes(serde_json::to_vec(&patch).unwrap().into())
            .expect_success()
            .await;

        // 3) Verify overrides: storage_quota_mb changed, all others preserved
        let response = server.get(&url).admin_auth().expect_success().await;
        let json: serde_json::Value = response.json();
        assert_eq!(json["overrides"]["storage_quota_mb"], 200);
        assert_eq!(json["overrides"]["rate_read"], "100mb/m");
        assert_eq!(json["overrides"]["rate_write"], "50mb/m");

        // 4) PATCH rate_write to "unlimited", leave rest unchanged
        let patch = serde_json::json!({
            "rate_write": "unlimited"
        });
        server
            .patch(&url)
            .admin_auth()
            .content_type("application/json")
            .bytes(serde_json::to_vec(&patch).unwrap().into())
            .expect_success()
            .await;

        let response = server.get(&url).admin_auth().expect_success().await;
        let json: serde_json::Value = response.json();
        assert_eq!(json["overrides"]["storage_quota_mb"], 200);
        assert_eq!(json["overrides"]["rate_read"], "100mb/m");
        assert_eq!(json["overrides"]["rate_write"], "unlimited");

        // 5) Empty PATCH should change nothing
        let patch = serde_json::json!({});
        server
            .patch(&url)
            .admin_auth()
            .content_type("application/json")
            .bytes(serde_json::to_vec(&patch).unwrap().into())
            .expect_success()
            .await;

        let response = server.get(&url).admin_auth().expect_success().await;
        let json: serde_json::Value = response.json();
        assert_eq!(json["overrides"]["storage_quota_mb"], 200);
        assert_eq!(json["overrides"]["rate_read"], "100mb/m");
        assert_eq!(json["overrides"]["rate_write"], "unlimited");
    }

    /// PATCH with invalid rate string should be rejected with 422.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_patch_invalid_rate_rejected() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let pubkey = Keypair::random().public_key();

        context.user_service.create(&pubkey).await.unwrap();

        let url = format!("/users/{}/quota", pubkey.z32());
        let patch = serde_json::json!({
            "rate_read": "rubbish"
        });
        let response = server
            .patch(&url)
            .admin_auth()
            .content_type("application/json")
            .bytes(serde_json::to_vec(&patch).unwrap().into())
            .expect_failure()
            .await;
        response.assert_status(axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }
}
