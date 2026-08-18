use std::num::NonZeroU16;

use super::super::app_state::AppState;
use crate::{
    persistence::sql::signup_code::{
        SignupCode, SignupCodeEntity, SignupCodeListQuery, SignupCodeListState,
        SignupCodeRepository,
    },
    shared::HttpResult,
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::NaiveDateTime;

#[derive(Deserialize)]
pub(crate) struct SignupTokensQuery {
    limit: Option<NonZeroU16>,
    cursor: Option<SignupCode>,
    state: Option<SignupCodeListState>,
}

impl SignupTokensQuery {
    fn list_query(self) -> SignupCodeListQuery {
        SignupCodeListQuery {
            state: self.state.unwrap_or(SignupCodeListState::All),
            limit: self.limit.map(NonZeroU16::get),
            cursor: self.cursor,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct SignupTokenItem {
    token: SignupCode,
    created_at: NaiveDateTime,
    used_at: Option<NaiveDateTime>,
    used_by: Option<String>,
}

impl From<SignupCodeEntity> for SignupTokenItem {
    fn from(code: SignupCodeEntity) -> Self {
        Self {
            token: code.id,
            created_at: code.created_at,
            used_at: code.used_at,
            used_by: code.used_by.map(|pubkey| pubkey.z32()),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct SignupTokensResponse {
    items: Vec<SignupTokenItem>,
    next_cursor: Option<SignupCode>,
}

/// List signup tokens with usage information.
pub async fn list_signup_tokens(
    State(state): State<AppState>,
    Query(params): Query<SignupTokensQuery>,
) -> HttpResult<(StatusCode, Json<SignupTokensResponse>)> {
    let page =
        SignupCodeRepository::list(params.list_query(), &mut state.context.sql_db.pool().into())
            .await?;
    let items = page.items.into_iter().map(SignupTokenItem::from).collect();

    Ok((
        StatusCode::OK,
        Json(SignupTokensResponse {
            items,
            next_cursor: page.next_cursor,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum_test::TestServer;

    use super::*;
    use crate::admin_server::AdminAuthExt;
    use crate::{
        persistence::sql::signup_code::{SignupCode, SignupCodeRepository},
        shared::user_quota::UserQuota,
        AppContext,
    };

    fn create_test_server(context: &Arc<AppContext>) -> TestServer {
        AppState::test_server(context)
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_signup_tokens_returns_used_by_and_used_at() {
        use pubky_common::crypto::Keypair;

        let context = AppContext::test().await;
        let server = create_test_server(&context);

        let response = server
            .get("/generate_signup_token")
            .admin_auth()
            .expect_success()
            .await;
        let token = response.text();

        let used_by = Keypair::random().public_key();
        let token_id = SignupCode::new(token.clone()).unwrap();
        SignupCodeRepository::mark_as_used(&token_id, &used_by, &mut context.sql_db.pool().into())
            .await
            .unwrap();

        let response = server
            .get("/signup_tokens")
            .admin_auth()
            .expect_success()
            .await;
        response.assert_status_ok();

        let body: serde_json::Value = response.json();
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["token"], token);
        assert_eq!(items[0]["used_by"], used_by.z32());
        assert!(items[0]["used_at"].as_str().is_some());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_signup_tokens_filters_by_state() {
        use pubky_common::crypto::Keypair;

        let context = AppContext::test().await;
        let server = create_test_server(&context);

        let used_token = server
            .get("/generate_signup_token")
            .admin_auth()
            .expect_success()
            .await
            .text();
        let unused_token = server
            .get("/generate_signup_token")
            .admin_auth()
            .expect_success()
            .await
            .text();

        let used_by = Keypair::random().public_key();
        let used_token_id = SignupCode::new(used_token.clone()).unwrap();
        SignupCodeRepository::mark_as_used(
            &used_token_id,
            &used_by,
            &mut context.sql_db.pool().into(),
        )
        .await
        .unwrap();

        let response = server
            .get("/signup_tokens?state=used")
            .admin_auth()
            .expect_success()
            .await;
        let body: serde_json::Value = response.json();
        let used_items = body["items"].as_array().unwrap();
        assert_eq!(used_items.len(), 1);
        assert_eq!(used_items[0]["token"], used_token);

        let response = server
            .get("/signup_tokens?state=unused")
            .admin_auth()
            .expect_success()
            .await;
        let body: serde_json::Value = response.json();
        let unused_items = body["items"].as_array().unwrap();
        assert_eq!(unused_items.len(), 1);
        assert_eq!(unused_items[0]["token"], unused_token);

        let response = server
            .get("/signup_tokens?state=all")
            .admin_auth()
            .expect_success()
            .await;
        let body: serde_json::Value = response.json();
        assert_eq!(body["items"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_signup_tokens_paginates_with_cursor() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let token1 = SignupCode::new("0000-0000-0001".to_string()).unwrap();
        let token2 = SignupCode::new("0000-0000-0002".to_string()).unwrap();
        let token3 = SignupCode::new("0000-0000-0003".to_string()).unwrap();

        for token in [&token1, &token2, &token3] {
            SignupCodeRepository::create(
                token,
                &UserQuota::default(),
                &mut context.sql_db.pool().into(),
            )
            .await
            .unwrap();
        }

        let response = server
            .get("/signup_tokens?limit=2")
            .admin_auth()
            .expect_success()
            .await;
        let body: serde_json::Value = response.json();
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["token"], token1.to_string());
        assert_eq!(items[1]["token"], token2.to_string());
        assert_eq!(body["next_cursor"], token2.to_string());

        let response = server
            .get(&format!("/signup_tokens?limit=2&cursor={token2}"))
            .admin_auth()
            .expect_success()
            .await;
        let body: serde_json::Value = response.json();
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["token"], token3.to_string());
        assert_eq!(body["next_cursor"], serde_json::Value::Null);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_signup_tokens_rejects_bad_query() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);

        let response = server
            .get("/signup_tokens?state=unknown")
            .admin_auth()
            .expect_failure()
            .await;
        response.assert_status_bad_request();

        let response = server
            .get("/signup_tokens?cursor=invalid")
            .admin_auth()
            .expect_failure()
            .await;
        response.assert_status_bad_request();

        let response = server
            .get("/signup_tokens?limit=0")
            .admin_auth()
            .expect_failure()
            .await;
        response.assert_status_bad_request();
    }
}
