use crate::persistence::sql::entry::{EntryEntity, EntryRepository};
use crate::shared::{HttpError, HttpResult};
use crate::{
    client_server::{
        auth::{has_read_permission, AuthSession},
        middleware::request_tenant::RequestTenant,
        query_params::ListQueryParams,
        AppState,
    },
    shared::webdav::{EntryPath, WebDavPathAxum},
};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, Response, StatusCode},
    response::IntoResponse,
};
use httpdate::HttpDate;
use sqlx::types::chrono::{DateTime, Utc};
use std::str::FromStr;
use std::time::SystemTime;

pub async fn legacy_head(
    State(state): State<AppState>,
    session: Option<AuthSession>,
    tenant: RequestTenant,
    Path(path): Path<WebDavPathAxum>,
) -> HttpResult<impl IntoResponse> {
    let entry_path = EntryPath::new(tenant.public_key().clone(), path.inner().clone());
    let mut response = head(State(state), session, entry_path).await?;
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("pubky-host"));
    Ok(response)
}

pub async fn head(
    State(state): State<AppState>,
    session: Option<AuthSession>,
    entry_path: EntryPath,
) -> HttpResult<Response<Body>> {
    has_read_permission(
        session.as_ref(),
        Some(entry_path.pubkey()),
        entry_path.path(),
    )?;

    state
        .user_service
        .get_or_http_error(entry_path.pubkey(), false)
        .await?;

    let entry = state
        .file_service
        .get_info(&entry_path, &mut state.sql_db.pool().into())
        .await?;
    let response = entry.to_response_headers().into_response();
    Ok(response)
}

#[axum::debug_handler]
pub async fn legacy_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    session: Option<AuthSession>,
    tenant: RequestTenant,
    Path(path): Path<WebDavPathAxum>,
    params: ListQueryParams,
) -> HttpResult<impl IntoResponse> {
    let entry_path = EntryPath::new(tenant.public_key().clone(), path.inner().clone());
    let mut response = get(State(state), headers, session, entry_path, params).await?;
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("pubky-host"));
    Ok(response)
}

#[axum::debug_handler]
pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    session: Option<AuthSession>,
    entry_path: EntryPath,
    params: ListQueryParams,
) -> HttpResult<Response<Body>> {
    has_read_permission(
        session.as_ref(),
        Some(entry_path.pubkey()),
        entry_path.path(),
    )?;

    if entry_path.path().is_directory() {
        return list(state, &entry_path, params).await;
    }

    let entry = state
        .file_service
        .get_info(&entry_path, &mut state.sql_db.pool().into())
        .await?;

    // Per RFC 7232 §3: If-None-Match has precedence over If-Modified-Since.
    if let Some(request_etag) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok())
    {
        let current_etag = format!(
            "\"{}\"",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                entry.content_hash.as_bytes()
            )
        );
        if request_etag
            .trim()
            .split(',')
            .map(|s| s.trim())
            .any(|tag| tag == current_etag)
        {
            return not_modified_response(&entry);
        }
    } else if let Some(condition_http_date) = headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| HttpDate::from_str(s).ok())
    {
        let entry_http_date: HttpDate = to_http_date(&entry.modified_at);
        if condition_http_date >= entry_http_date {
            return not_modified_response(&entry);
        }
    }

    let stream = state.file_service.get_stream(&entry_path).await?;
    let body_stream = Body::from_stream(stream);
    let mut response = entry.to_response_headers().into_response();
    *response.body_mut() = body_stream;
    Ok(response)
}

async fn list(
    state: AppState,
    entry_path: &EntryPath,
    params: ListQueryParams,
) -> HttpResult<Response<Body>> {
    let contains_dir =
        EntryRepository::contains_directory(entry_path, &mut state.sql_db.pool().into()).await?;
    if !contains_dir {
        return Err(HttpError::new_with_message(
            StatusCode::NOT_FOUND,
            "Directory Not Found",
        ));
    }

    let parsed_cursor = match parse_cursor(params.cursor) {
        Ok(cursor) => cursor,
        Err(_) => {
            return Err(HttpError::new_with_message(
                StatusCode::BAD_REQUEST,
                "Invalid cursor",
            ))
        }
    };

    let entries = if params.shallow {
        EntryRepository::list_shallow(
            entry_path,
            params.limit,
            parsed_cursor,
            params.reverse,
            &mut state.sql_db.pool().into(),
        )
        .await?
    } else {
        EntryRepository::list_deep(
            entry_path,
            params.limit,
            parsed_cursor,
            params.reverse,
            &mut state.sql_db.pool().into(),
        )
        .await?
    };
    let pubky_urls = entries
        .iter()
        .map(|entry| format!("pubky://{}", entry))
        .collect::<Vec<_>>();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(pubky_urls.join("\n")))?)
}

/// Parse the cursor if it is present.
/// If the cursor is not present, returns None.
/// If the cursor is present and valid, returns the EntryPath.
fn parse_cursor(cursor: Option<String>) -> anyhow::Result<Option<EntryPath>> {
    let cursor = match cursor {
        Some(cursor) => cursor,
        None => return Ok(None),
    };

    let cursor = cursor.trim_start_matches("pubky://");
    let path = EntryPath::from_str(cursor)?;
    Ok(Some(path))
}

/// Creates the Not Modified response based on the entry data.
fn not_modified_response(entry: &EntryEntity) -> HttpResult<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(
            header::ETAG,
            format!(
                "\"{}\"",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    entry.content_hash.as_bytes()
                )
            ),
        )
        .header(
            header::LAST_MODIFIED,
            to_http_date(&entry.modified_at).to_string().as_str(),
        )
        .header(header::CACHE_CONTROL, "private, must-revalidate")
        .body(Body::empty())?)
}

/// Convert a `NaiveDateTime` to a `HttpDate`.
fn to_http_date(date: &sqlx::types::chrono::NaiveDateTime) -> HttpDate {
    let sys_datetime = SystemTime::from(DateTime::<Utc>::from_naive_utc_and_offset(*date, Utc));
    httpdate::HttpDate::from(sys_datetime)
}

impl EntryEntity {
    pub fn to_response_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, self.content_length.into());
        headers.insert(
            header::LAST_MODIFIED,
            HeaderValue::from_str(to_http_date(&self.modified_at).to_string().as_str())
                .expect("http date is valid header value"),
        );
        headers.insert(
            header::CONTENT_TYPE,
            self.content_type
                .clone()
                .try_into()
                .or(HeaderValue::from_str(""))
                .expect("valid header value"),
        );
        headers.insert(
            header::ETAG,
            format!(
                "\"{}\"",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    self.content_hash.as_bytes()
                )
            )
            .try_into()
            .expect("base64 string is valid"),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, must-revalidate"),
        );
        headers
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{header, HeaderMap, Method, StatusCode};
    use axum::Router;
    use axum_test::TestServer;
    use pubky_common::{
        auth::AuthToken,
        capabilities::Capability,
        crypto::{Keypair, PublicKey},
    };

    use crate::app_context::AppContext;
    use crate::client_server::ClientServer;

    async fn create_user_with_capabilities(
        server: &axum_test::TestServer,
        keypair: &Keypair,
        capabilities: Vec<Capability>,
    ) -> anyhow::Result<String> {
        let auth_token = AuthToken::sign(keypair, capabilities);
        let body_bytes: axum::body::Bytes = auth_token.serialize().into();
        let response = server
            .post("/signup")
            .add_header("host", keypair.public_key().to_z32())
            .bytes(body_bytes)
            .expect_success()
            .await;

        let header_value = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|h| h.to_str().ok())
            .expect("should return a set-cookie header")
            .to_string();

        Ok(header_value)
    }

    pub async fn create_root_user(
        server: &axum_test::TestServer,
        keypair: &Keypair,
    ) -> anyhow::Result<String> {
        create_user_with_capabilities(server, keypair, vec![Capability::root()]).await
    }

    async fn sign_in_with_capabilities(
        server: &axum_test::TestServer,
        keypair: &Keypair,
        capabilities: Vec<Capability>,
    ) -> anyhow::Result<String> {
        let auth_token = AuthToken::sign(keypair, capabilities);
        let body_bytes: axum::body::Bytes = auth_token.serialize().into();
        let response = server
            .post("/session")
            .add_header("host", keypair.public_key().to_z32())
            .bytes(body_bytes)
            .expect_success()
            .await;

        Ok(response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|h| h.to_str().ok())
            .expect("should return a set-cookie header")
            .to_string())
    }

    async fn create_environment_with_keypair(
    ) -> anyhow::Result<(AppContext, Router, TestServer, Keypair, String)> {
        let context = AppContext::test().await;
        let router = ClientServer::create_router(&context)?;
        let server = axum_test::TestServer::new(router.clone()).unwrap();

        let keypair = Keypair::random();
        let cookie = create_root_user(&server, &keypair).await?.to_string();

        Ok((context, router, server, keypair, cookie))
    }

    pub async fn create_environment(
    ) -> anyhow::Result<(AppContext, Router, TestServer, PublicKey, String)> {
        let (context, router, server, keypair, cookie) = create_environment_with_keypair().await?;
        let public_key = keypair.public_key();

        Ok((context, router, server, public_key, cookie))
    }

    fn header_value(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
        headers.get(name).and_then(|value| value.to_str().ok())
    }

    fn assert_does_not_vary_on(headers: &HeaderMap, ignored_header: &str) {
        let varies_on_ignored_header = header_value(headers, header::VARY)
            .into_iter()
            .flat_map(|vary| vary.split(','))
            .any(|name| name.trim().eq_ignore_ascii_case(ignored_header));
        assert!(
            !varies_on_ignored_header,
            "response must not vary on {ignored_header}"
        );
    }

    fn assert_private_cache_policy(headers: &HeaderMap) {
        assert_eq!(
            header_value(headers, header::CACHE_CONTROL),
            Some("no-store")
        );
        assert_eq!(
            header_value(headers, header::VARY),
            Some("pubky-host, Authorization, Cookie")
        );
    }

    fn assert_no_validators(headers: &HeaderMap) {
        assert!(!headers.contains_key(header::ETAG));
        assert!(!headers.contains_key(header::LAST_MODIFIED));
    }

    fn assert_validators_present(headers: &HeaderMap) {
        assert!(headers.contains_key(header::ETAG));
        assert!(headers.contains_key(header::LAST_MODIFIED));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn invalid_path_aliases_cannot_modify_target_file() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        server
            .put("/pub/report")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .text("original")
            .expect_success()
            .await;

        for alias in [
            "/pub/report%20",
            "/pub/report%C2%A0",
            "/pub/report%E3%80%80",
            "/pub/scope/%5C..%5Creport",
        ] {
            server
                .put(alias)
                .add_header("host", public_key.z32())
                .add_header(header::COOKIE, cookie.clone())
                .text("overwritten")
                .expect_failure()
                .await
                .assert_status(StatusCode::BAD_REQUEST);

            server
                .delete(alias)
                .add_header("host", public_key.z32())
                .add_header(header::COOKIE, cookie.clone())
                .expect_failure()
                .await
                .assert_status(StatusCode::BAD_REQUEST);
        }

        let response = server
            .get("/pub/report")
            .add_header("host", public_key.z32())
            .expect_success()
            .await;
        assert_eq!(response.text(), "original");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn if_last_modified() {
        let (_context, _router, server, public_key, cookie) = create_environment().await.unwrap();

        let data = vec![1_u8, 2, 3, 4, 5];

        server
            .put("/pub/foo")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .bytes(data.into())
            .expect_success()
            .await;

        let response = server
            .get("/pub/foo")
            .add_header("host", public_key.z32())
            .expect_success()
            .await;

        let response = server
            .get("/pub/foo")
            .add_header("host", public_key.z32())
            .add_header(
                header::IF_MODIFIED_SINCE,
                response.headers().get(header::LAST_MODIFIED).unwrap(),
            )
            .await;

        response.assert_status(StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn if_none_match() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        let data = vec![1_u8, 2, 3, 4, 5];

        server
            .put("/pub/foo")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .bytes(data.into())
            .expect_success()
            .await;

        let response = server
            .get("/pub/foo")
            .add_header("host", public_key.z32())
            .expect_success()
            .await;

        let response = server
            .get("/pub/foo")
            .add_header("host", public_key.z32())
            .add_header(
                header::IF_NONE_MATCH,
                response.headers().get(header::ETAG).unwrap(),
            )
            .await;

        response.assert_status(StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_content_with_magic_bytes() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        let data = vec![0x89_u8, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

        server
            .put("/pub/foo")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .bytes(data.into())
            .expect_success()
            .await;

        let response = server
            .get("/pub/foo")
            .add_header("host", public_key.z32())
            .await;

        response.assert_header(header::CONTENT_TYPE, "image/png");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_content_by_extension() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        let data = vec![108, 111, 114, 101, 109, 32, 105, 112, 115, 117, 109];

        server
            .put("/pub/text.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .bytes(data.into())
            .expect_success()
            .await;

        let response = server
            .get("/pub/text.txt")
            .add_header("host", public_key.z32())
            .await;

        response.assert_header(header::CONTENT_TYPE, "text/plain");
    }
    #[tokio::test]
    async fn if_none_match_precedes_if_modified_since() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        // Write v1
        server
            .put("/pub/foo")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(Vec::from("alice").into())
            .expect_success()
            .await;

        // Baseline GET to capture ETag and Last-Modified
        let base = server
            .get("/pub/foo")
            .add_header("host", public_key.z32())
            .expect_success()
            .await;
        let etag_v1 = base
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let lm_v1 = base.headers().get(header::LAST_MODIFIED).unwrap().clone();

        // Overwrite with different content but same-second timestamp likely
        server
            .put("/pub/foo")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(Vec::from("bob").into())
            .expect_success()
            .await;

        // Conditional GET that sends both validators; must return 200 because ETag changed.
        let r = server
            .get("/pub/foo")
            .add_header("host", public_key.z32())
            .add_header(header::IF_NONE_MATCH, etag_v1)
            .add_header(header::IF_MODIFIED_SINCE, lm_v1)
            .await;
        r.assert_status(StatusCode::OK);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn pub_get_stays_anonymous_after_dual_root_switch() {
        // Regression: switching the read extractor to the dual-root one must
        // not break anonymous `/pub/` reads.
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        server
            .put("/pub/foo.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .bytes(Vec::from("public").into())
            .expect_success()
            .await;

        // No cookie → still 200.
        server
            .get("/pub/foo.txt")
            .add_header("host", public_key.z32())
            .expect_success()
            .await;
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn priv_get_requires_authentication() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        // Owner writes a private file.
        server
            .put("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(Vec::from("top secret").into())
            .expect_success()
            .await;

        // Anonymous read → 401.
        server
            .get("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .await
            .assert_status(StatusCode::UNAUTHORIZED);

        // Owner read → 200 with the body.
        let resp = server
            .get("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .expect_success()
            .await;
        assert_eq!(resp.text(), "top secret");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn priv_get_is_not_an_existence_oracle() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        // One private file exists; another path is absent.
        server
            .put("/priv/exists.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(Vec::from("data").into())
            .expect_success()
            .await;

        // Anonymous: existing and absent must return the SAME status (401), so
        // the response cant be used to probe which private paths exist.
        server
            .get("/priv/exists.txt")
            .add_header("host", public_key.z32())
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
        server
            .get("/priv/absent.txt")
            .add_header("host", public_key.z32())
            .await
            .assert_status(StatusCode::UNAUTHORIZED);

        // Authorized: 404 for the absent file.
        server
            .get("/priv/absent.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn priv_head_mirrors_get() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        server
            .put("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(Vec::from("hello").into())
            .expect_success()
            .await;

        // Anonymous HEAD → 401.
        server
            .method(Method::HEAD, "/priv/secret.txt")
            .add_header("host", public_key.z32())
            .await
            .assert_status(StatusCode::UNAUTHORIZED);

        // Owner HEAD on the existing file → 200.
        server
            .method(Method::HEAD, "/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .await
            .assert_status(StatusCode::OK);

        // Owner HEAD on an absent file → 404.
        server
            .method(Method::HEAD, "/priv/absent.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn priv_conditional_get_is_authorized_first() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        server
            .put("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(Vec::from("v1").into())
            .expect_success()
            .await;

        // Capture the real ETag as the owner.
        let owned = server
            .get("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .expect_success()
            .await;
        let etag = owned.headers().get(header::ETAG).unwrap().clone();

        // Anonymous GET with the real ETag → still 401, not 304.
        server
            .get("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::IF_NONE_MATCH, etag)
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn priv_directory_listing_requires_auth() {
        // listing a `/priv/` directory is gated exactly like a file read.
        // Anonymous callers can't enumerate private paths, the owner can.
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        // Owner writes two files under a private directory.
        for name in ["a.txt", "b.txt"] {
            server
                .put(&format!("/priv/app/{name}"))
                .add_header("host", public_key.z32())
                .add_header(header::COOKIE, cookie.clone())
                .bytes(Vec::from("x").into())
                .expect_success()
                .await;
        }

        // Anonymous listing of the private directory → 401 (no enumeration), and
        // the same for a nonexistent directory.
        server
            .get("/priv/app/")
            .add_header("host", public_key.z32())
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
        server
            .get("/priv/nope/")
            .add_header("host", public_key.z32())
            .await
            .assert_status(StatusCode::UNAUTHORIZED);

        // Owner lists the directory → 200 with both entries.
        let resp = server
            .get("/priv/app/")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .expect_success()
            .await;
        let body = resp.text();
        assert!(
            body.contains("/priv/app/a.txt"),
            "listing should include a.txt, got: {body}"
        );
        assert!(
            body.contains("/priv/app/b.txt"),
            "listing should include b.txt, got: {body}"
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn priv_responses_use_no_store_and_auth_vary() {
        let (_, _, server, keypair, cookie) = create_environment_with_keypair().await.unwrap();
        let public_key = keypair.public_key();

        server
            .put("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(Vec::from("top secret").into())
            .expect_success()
            .await;
        server
            .put("/priv/app/a.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(Vec::from("a").into())
            .expect_success()
            .await;

        let ok = server
            .get("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .expect_success()
            .await;
        assert_private_cache_policy(ok.headers());
        assert_validators_present(ok.headers());

        let not_modified = server
            .get("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .add_header(
                header::IF_NONE_MATCH,
                ok.headers().get(header::ETAG).unwrap(),
            )
            .await;
        not_modified.assert_status(StatusCode::NOT_MODIFIED);
        assert_private_cache_policy(not_modified.headers());
        assert_validators_present(not_modified.headers());

        let head = server
            .method(Method::HEAD, "/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .await;
        head.assert_status(StatusCode::OK);
        assert_private_cache_policy(head.headers());
        assert_validators_present(head.headers());

        let listing = server
            .get("/priv/app/")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .expect_success()
            .await;
        assert_private_cache_policy(listing.headers());

        let unauthorized = server
            .get("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .await;
        unauthorized.assert_status(StatusCode::UNAUTHORIZED);
        assert_private_cache_policy(unauthorized.headers());
        assert_no_validators(unauthorized.headers());

        let write_only_cookie = sign_in_with_capabilities(
            &server,
            &keypair,
            vec![Capability::write("/priv/").unwrap()],
        )
        .await
        .unwrap();
        let forbidden = server
            .get("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, write_only_cookie)
            .await;
        forbidden.assert_status(StatusCode::FORBIDDEN);
        assert_private_cache_policy(forbidden.headers());
        assert_no_validators(forbidden.headers());

        let missing = server
            .get("/priv/missing.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .await;
        missing.assert_status(StatusCode::NOT_FOUND);
        assert_private_cache_policy(missing.headers());
        assert_no_validators(missing.headers());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn pub_headers_are_unchanged_by_private_cache_policy() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        server
            .put("/pub/file.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(Vec::from("public").into())
            .expect_success()
            .await;
        server
            .put("/pub/app/a.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .bytes(Vec::from("a").into())
            .expect_success()
            .await;

        let ok = server
            .get("/pub/file.txt")
            .add_header("host", public_key.z32())
            .expect_success()
            .await;
        assert_eq!(
            header_value(ok.headers(), header::CACHE_CONTROL),
            Some("private, must-revalidate")
        );
        assert_eq!(header_value(ok.headers(), header::VARY), Some("pubky-host"));
        assert_validators_present(ok.headers());

        let not_modified = server
            .get("/pub/file.txt")
            .add_header("host", public_key.z32())
            .add_header(
                header::IF_NONE_MATCH,
                ok.headers().get(header::ETAG).unwrap(),
            )
            .await;
        not_modified.assert_status(StatusCode::NOT_MODIFIED);
        assert_eq!(
            header_value(not_modified.headers(), header::CACHE_CONTROL),
            Some("private, must-revalidate")
        );
        assert_eq!(
            header_value(not_modified.headers(), header::VARY),
            Some("pubky-host")
        );
        assert_validators_present(not_modified.headers());

        let listing = server
            .get("/pub/app/")
            .add_header("host", public_key.z32())
            .expect_success()
            .await;
        assert!(header_value(listing.headers(), header::CACHE_CONTROL).is_none());
        assert_eq!(
            header_value(listing.headers(), header::VARY),
            Some("pubky-host")
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn path_addressed_get_and_head_ignore_legacy_tenant_headers() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();
        let other = Keypair::random().public_key();

        server
            .put("/pub/file.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie)
            .text("path addressed")
            .expect_success()
            .await;

        let url = format!(
            "/storage/{}/pub/file.txt?pubky-host={}",
            public_key.z32(),
            other.z32()
        );
        let response = server
            .get(&url)
            .add_header("pubky-host", other.z32())
            .expect_success()
            .await;
        assert_eq!(response.text(), "path addressed");
        assert_does_not_vary_on(response.headers(), "pubky-host");

        let head = server
            .method(Method::HEAD, &url)
            .add_header("pubky-host", "invalid")
            .await;
        head.assert_status(StatusCode::OK);
        assert_does_not_vary_on(head.headers(), "pubky-host");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn path_addressed_listing_preserves_pagination() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        for name in ["a.txt", "b.txt"] {
            server
                .put(&format!("/pub/app/{name}"))
                .add_header("host", public_key.z32())
                .add_header(header::COOKIE, cookie.clone())
                .text(name)
                .expect_success()
                .await;
        }

        let base = format!("/storage/{}/pub/app/", public_key.z32());
        let first = server
            .get(&format!("{base}?limit=1"))
            .expect_success()
            .await;
        let first_entry = first.text();
        assert_eq!(first_entry.lines().count(), 1);
        assert_does_not_vary_on(first.headers(), "pubky-host");

        let cursor = first_entry.trim_start_matches("pubky://");
        let second = server
            .get(&format!("{base}?limit=1&cursor={cursor}"))
            .expect_success()
            .await;
        let second_entry = second.text();
        assert_eq!(second_entry.lines().count(), 1);
        assert_ne!(first_entry, second_entry);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn path_addressed_private_reads_use_path_owner_cookie_and_cache_policy() {
        let (_, _, server, public_key, cookie) = create_environment().await.unwrap();

        server
            .put("/priv/secret.txt")
            .add_header("host", public_key.z32())
            .add_header(header::COOKIE, cookie.clone())
            .text("private")
            .expect_success()
            .await;

        let url = format!("/storage/{}/priv/secret.txt", public_key.z32());
        server
            .get(&url)
            .await
            .assert_status(StatusCode::UNAUTHORIZED);

        let response = server
            .get(&url)
            .add_header(header::COOKIE, cookie)
            .expect_success()
            .await;
        assert_eq!(response.text(), "private");
        assert_eq!(
            header_value(response.headers(), header::CACHE_CONTROL),
            Some("no-store")
        );
        assert_eq!(
            header_value(response.headers(), header::VARY),
            Some("Authorization, Cookie")
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn malformed_path_addressing_is_a_client_error_and_writes_require_authentication() {
        let (_, _, server, public_key, _) = create_environment().await.unwrap();

        let malformed = [
            "/storage".to_string(),
            "/storage/".to_string(),
            "/storage/short/pub/file.txt".to_string(),
            format!("/storage/pubky{}/pub/file.txt", public_key.z32()),
            format!("/storage/{}/", public_key.z32()),
        ];
        for path in malformed {
            let response = server
                .get(&path)
                .add_header(header::ORIGIN, "https://app.example")
                .await;
            response.assert_status(StatusCode::BAD_REQUEST);
            assert!(response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        }

        server
            .put(&format!("/storage/{}/pub/file.txt", public_key.z32()))
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }
}
