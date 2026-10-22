use std::num::NonZeroU16;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use pubky_common::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::NaiveDateTime;

use super::super::app_state::AppState;
use super::user_quota::UserQuotaResponse;
use crate::{
    persistence::sql::user::{
        UserEntity, UserListQuery, UserListSortBy, UserListState, UserRepository,
    },
    shared::{HttpError, HttpResult, Z32Pubkey},
    ConfigToml,
};

#[derive(Deserialize)]
pub(crate) struct UsersQuery {
    limit: Option<NonZeroU16>,
    cursor: Option<Z32Pubkey>,
    state: Option<UserListState>,
    sort_by: Option<UserListSortBy>,
    reverse: Option<bool>,
}

impl UsersQuery {
    fn list_query(self) -> UserListQuery {
        UserListQuery {
            state: self.state.unwrap_or_default(),
            sort_by: self.sort_by.unwrap_or_default(),
            reverse: self.reverse.unwrap_or(false),
            limit: self.limit.map(NonZeroU16::get),
            cursor: self.cursor.map(|pubkey| pubkey.0),
        }
    }
}

/// One user, as returned by `GET /users` and `GET /users/{pubkey}`.
#[derive(Serialize)]
pub(crate) struct UserItem {
    pubkey: String,
    created_at: NaiveDateTime,
    disabled: bool,
    used_bytes: u64,
    /// Same shape as `GET /users/{pubkey}/quota`.
    quota: UserQuotaResponse,
}

impl UserItem {
    fn new(user: &UserEntity, config: &ConfigToml) -> Self {
        Self {
            pubkey: user.public_key.z32(),
            created_at: user.created_at,
            disabled: user.disabled,
            used_bytes: user.used_bytes,
            quota: UserQuotaResponse::new(user, config),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct UsersResponse {
    items: Vec<UserItem>,
    next_cursor: Option<String>,
}

/// GET /users — paginated list of users with their storage usage and quota.
pub async fn list_users(
    State(state): State<AppState>,
    Query(params): Query<UsersQuery>,
) -> HttpResult<(StatusCode, Json<UsersResponse>)> {
    let page = UserRepository::list(params.list_query(), &mut state.context.sql_db.pool().into())
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => HttpError::bad_request("Unknown cursor"),
            e => e.into(),
        })?;
    let items = page
        .items
        .into_iter()
        .map(|user| UserItem::new(&user, &state.context.config_toml))
        .collect();

    Ok((
        StatusCode::OK,
        Json(UsersResponse {
            items,
            next_cursor: page.next_cursor.as_ref().map(PublicKey::z32),
        }),
    ))
}

/// GET /users/{pubkey} — one user in the same shape as the `GET /users` items.
pub async fn get_user(
    State(state): State<AppState>,
    Path(pubkey): Path<Z32Pubkey>,
) -> HttpResult<Json<UserItem>> {
    let user = state
        .context
        .user_service
        .get_or_http_error(&pubkey.0, false)
        .await?;
    Ok(Json(UserItem::new(&user, &state.context.config_toml)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum_test::TestServer;
    use pubky_common::crypto::Keypair;

    use super::*;
    use crate::admin_server::AdminAuthExt;
    use crate::AppContext;

    fn create_test_server(context: &Arc<AppContext>) -> TestServer {
        AppState::test_server(context)
    }

    /// Create a user with the given `used_bytes` and disabled flag.
    async fn create_user(context: &AppContext, used_bytes: u64, disabled: bool) -> PublicKey {
        let pubkey = Keypair::random().public_key();
        let mut user = context.user_service.create(&pubkey).await.unwrap();
        user.used_bytes = used_bytes;
        user.disabled = disabled;
        UserRepository::update(&user, &mut context.sql_db.pool().into())
            .await
            .unwrap();
        pubkey
    }

    fn pubkeys(body: &serde_json::Value) -> Vec<String> {
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["pubkey"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_users_item_shape() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let pubkey = create_user(&context, 42, true).await;

        server
            .patch(&format!("/users/{}/quota", pubkey.z32()))
            .admin_auth()
            .json(&serde_json::json!({ "storage_quota_mb": 500 }))
            .expect_success()
            .await;

        let body: serde_json::Value = server.get("/users").admin_auth().await.json();
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item["pubkey"], pubkey.z32());
        assert!(item["created_at"].as_str().is_some());
        assert_eq!(item["disabled"], true);
        assert_eq!(item["used_bytes"], 42);
        assert_eq!(
            item["quota"]["overrides"],
            serde_json::json!({ "storage_quota_mb": 500 })
        );
        assert_eq!(item["quota"]["effective"]["storage_quota_mb"], 500);
        assert!(item["quota"]["effective"]["rate_read"].as_str().is_some());
        assert!(body["next_cursor"].is_null());

        // GET /users/{pubkey} returns the same item.
        let single: serde_json::Value = server
            .get(&format!("/users/{}", pubkey.z32()))
            .admin_auth()
            .await
            .json();
        assert_eq!(&single, item);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_users_filters_by_state() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let enabled = create_user(&context, 0, false).await;
        let disabled = create_user(&context, 0, true).await;

        let body: serde_json::Value = server
            .get("/users?state=disabled")
            .admin_auth()
            .await
            .json();
        assert_eq!(pubkeys(&body), vec![disabled.z32()]);

        let body: serde_json::Value = server.get("/users?state=enabled").admin_auth().await.json();
        assert_eq!(pubkeys(&body), vec![enabled.z32()]);

        let body: serde_json::Value = server.get("/users?state=all").admin_auth().await.json();
        assert_eq!(pubkeys(&body), vec![enabled.z32(), disabled.z32()]);

        server
            .get("/users?state=bogus")
            .admin_auth()
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_users_sort_and_reverse() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        let first = create_user(&context, 300, false).await;
        let second = create_user(&context, 100, false).await;
        let third = create_user(&context, 200, false).await;

        // Default: oldest first.
        let body: serde_json::Value = server.get("/users").admin_auth().await.json();
        assert_eq!(pubkeys(&body), vec![first.z32(), second.z32(), third.z32()]);

        let body: serde_json::Value = server.get("/users?reverse=true").admin_auth().await.json();
        assert_eq!(pubkeys(&body), vec![third.z32(), second.z32(), first.z32()]);

        let body: serde_json::Value = server
            .get("/users?sort_by=used_bytes")
            .admin_auth()
            .await
            .json();
        assert_eq!(pubkeys(&body), vec![second.z32(), third.z32(), first.z32()]);

        let body: serde_json::Value = server
            .get("/users?sort_by=used_bytes&reverse=true")
            .admin_auth()
            .await
            .json();
        assert_eq!(pubkeys(&body), vec![first.z32(), third.z32(), second.z32()]);

        server
            .get("/users?sort_by=bogus")
            .admin_auth()
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }

    /// Walk every page of `query` and return the pubkeys in order.
    async fn walk_pages(server: &TestServer, query: &str) -> Vec<String> {
        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let url = match &cursor {
                Some(cursor) => format!("/users?{query}&cursor={cursor}"),
                None => format!("/users?{query}"),
            };
            let body: serde_json::Value = server.get(&url).admin_auth().await.json();
            seen.extend(pubkeys(&body));
            match body["next_cursor"].as_str() {
                Some(next) => cursor = Some(next.to_string()),
                None => return seen,
            }
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_list_users_pagination() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);
        // Ties on used_bytes exercise the id tie-break in the cursor: with
        // limit=1 the page boundary falls between the tied users, and in
        // reverse order the newer of them comes first.
        let a = create_user(&context, 100, false).await;
        let b = create_user(&context, 100, false).await;
        let c = create_user(&context, 50, true).await;

        assert_eq!(
            walk_pages(&server, "sort_by=used_bytes&reverse=true&limit=1").await,
            vec![b.z32(), a.z32(), c.z32()]
        );
        assert_eq!(
            walk_pages(&server, "sort_by=used_bytes&limit=1").await,
            vec![c.z32(), a.z32(), b.z32()]
        );
        // Default sort pages by created_at; the state filter applies on every page.
        assert_eq!(
            walk_pages(&server, "limit=1").await,
            vec![a.z32(), b.z32(), c.z32()]
        );
        assert_eq!(
            walk_pages(&server, "state=enabled&limit=1").await,
            vec![a.z32(), b.z32()]
        );
        assert_eq!(
            walk_pages(&server, "reverse=true&limit=2").await,
            vec![c.z32(), b.z32(), a.z32()]
        );

        server
            .get(&format!(
                "/users?cursor={}",
                Keypair::random().public_key().z32()
            ))
            .admin_auth()
            .await
            .assert_status(StatusCode::BAD_REQUEST);

        server
            .get("/users?limit=0")
            .admin_auth()
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_user_not_found() {
        let context = AppContext::test().await;
        let server = create_test_server(&context);

        server
            .get(&format!("/users/{}", Keypair::random().public_key().z32()))
            .admin_auth()
            .await
            .assert_status(StatusCode::NOT_FOUND);

        server
            .get("/users/not-a-pubkey")
            .admin_auth()
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
}
