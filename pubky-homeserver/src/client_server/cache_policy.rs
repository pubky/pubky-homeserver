use axum::{
    extract::Request,
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use percent_encoding::percent_decode_str;

use crate::client_server::middleware::request_tenant::RequestTenant;
use crate::{constants::PRIVATE_ROOT, shared::webdav::StoragePath};

pub(crate) const CACHE_CONTROL_NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
/// A private file may stay in the caller's own cache, but every use must be
/// revalidated with its `ETag`, so a browser downloads an unchanged file once
/// and shared caches never store it.
const CACHE_CONTROL_PRIVATE_NO_CACHE: HeaderValue = HeaderValue::from_static("private, no-cache");
pub(crate) const VARY_PRIVATE_LEGACY: HeaderValue =
    HeaderValue::from_static("pubky-host, Authorization, Cookie");
pub(crate) const VARY_PRIVATE_PATH: HeaderValue = HeaderValue::from_static("Authorization, Cookie");

pub(crate) async fn private_cache_policy(request: Request, next: Next) -> Response {
    let tenant = request.extensions().get::<RequestTenant>().cloned();
    let request_path = request.uri().path();
    let storage_path = tenant
        .as_ref()
        .and_then(RequestTenant::storage_path)
        .map_or(request_path, StoragePath::as_str);
    let is_private = is_private_tenant_request_path(storage_path);
    let vary_on_pubky_host = tenant
        .as_ref()
        .is_none_or(|tenant| tenant.storage_path().is_none());
    let mut response = next.run(request).await;

    if is_private {
        let cache_control = private_cache_control(&response);
        apply_private_cache_headers(&mut response, cache_control, vary_on_pubky_host);
        if response.status().as_u16() >= 400 {
            remove_validators(&mut response);
        }
    }

    response
}

pub(crate) async fn sse_cache_policy(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    apply_private_cache_headers(&mut response, CACHE_CONTROL_NO_STORE, true);
    response
}

/// Only a served or unchanged file carries an `ETag`, and only such a response
/// is worth keeping for revalidation. Errors, listings and writes stay
/// `no-store`.
fn private_cache_control(response: &Response) -> HeaderValue {
    let served_or_unchanged =
        matches!(response.status(), StatusCode::OK | StatusCode::NOT_MODIFIED);
    if served_or_unchanged && response.headers().contains_key(header::ETAG) {
        CACHE_CONTROL_PRIVATE_NO_CACHE
    } else {
        CACHE_CONTROL_NO_STORE
    }
}

fn apply_private_cache_headers(
    response: &mut Response,
    cache_control: HeaderValue,
    vary_on_pubky_host: bool,
) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, cache_control);
    headers.insert(
        header::VARY,
        if vary_on_pubky_host {
            VARY_PRIVATE_LEGACY
        } else {
            VARY_PRIVATE_PATH
        },
    );
}

fn remove_validators(response: &mut Response) {
    let headers = response.headers_mut();
    headers.remove(header::ETAG);
    headers.remove(header::LAST_MODIFIED);
}

fn is_private_tenant_request_path(raw_path: &str) -> bool {
    if raw_path.starts_with(PRIVATE_ROOT) {
        return true;
    }

    let decoded = percent_decode_str(raw_path)
        .decode_utf8()
        .map(|path| path.into_owned())
        .unwrap_or_else(|_| raw_path.to_string());

    if decoded.starts_with(PRIVATE_ROOT) {
        return true;
    }

    StoragePath::normalize(&decoded)
        .map(|path| path.as_str().starts_with(PRIVATE_ROOT))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{header, HeaderMap, Response, StatusCode},
        middleware,
        response::IntoResponse,
        routing::{get, post, put},
        Router,
    };
    use axum_test::TestServer;

    use super::*;

    fn header_value(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
        headers.get(name).and_then(|value| value.to_str().ok())
    }

    fn response_with_private_file_headers(status: StatusCode) -> Response<Body> {
        Response::builder()
            .status(status)
            .header(header::CACHE_CONTROL, "private, must-revalidate")
            .header(header::VARY, "pubky-host")
            .header(header::ETAG, "\"hash\"")
            .header(header::LAST_MODIFIED, "Wed, 21 Oct 2015 07:28:00 GMT")
            .body(Body::empty())
            .unwrap()
    }

    async fn success() -> impl IntoResponse {
        response_with_private_file_headers(StatusCode::OK)
    }

    async fn missing() -> impl IntoResponse {
        response_with_private_file_headers(StatusCode::NOT_FOUND)
    }

    async fn not_modified() -> impl IntoResponse {
        response_with_private_file_headers(StatusCode::NOT_MODIFIED)
    }

    async fn created() -> impl IntoResponse {
        response_with_private_file_headers(StatusCode::CREATED)
    }

    /// A directory listing: served, but with nothing to revalidate.
    async fn listing() -> impl IntoResponse {
        (
            StatusCode::OK,
            [(header::VARY, "pubky-host")],
            "pubky://x/priv/app/a.txt\n",
        )
    }

    #[test]
    fn tenant_private_path_detection_uses_normalized_path() {
        assert!(is_private_tenant_request_path("/priv/secret.txt"));
        assert!(is_private_tenant_request_path("/pub/../priv/secret.txt"));
        assert!(is_private_tenant_request_path(
            "/pub/%2e%2e/priv/secret.txt"
        ));
        assert!(is_private_tenant_request_path("/priv/%00"));

        assert!(!is_private_tenant_request_path("/pub/file.txt"));
        assert!(!is_private_tenant_request_path("/priv"));
        assert!(!is_private_tenant_request_path("/privstuff/file.txt"));
        assert!(!is_private_tenant_request_path("/../../priv/secret.txt"));
    }

    #[tokio::test]
    async fn private_cache_policy_lets_private_file_reads_revalidate() {
        let server = TestServer::new(
            Router::new()
                .route("/priv/secret.txt", get(success).head(success))
                .route("/priv/unchanged.txt", get(not_modified))
                .layer(middleware::from_fn(private_cache_policy)),
        );

        for response in [
            server.get("/priv/secret.txt").await,
            server
                .method(axum::http::Method::HEAD, "/priv/secret.txt")
                .await,
            server.get("/priv/unchanged.txt").await,
        ] {
            assert_eq!(
                header_value(response.headers(), header::CACHE_CONTROL),
                Some("private, no-cache")
            );
            assert_eq!(
                header_value(response.headers(), header::VARY),
                Some("pubky-host, Authorization, Cookie")
            );
            assert!(response.headers().contains_key(header::ETAG));
            assert!(response.headers().contains_key(header::LAST_MODIFIED));
        }
    }

    #[tokio::test]
    async fn private_cache_policy_keeps_listings_and_writes_no_store() {
        let server = TestServer::new(
            Router::new()
                .route("/priv/app/", get(listing))
                .route("/priv/secret.txt", put(created))
                .layer(middleware::from_fn(private_cache_policy)),
        );

        for response in [
            server.get("/priv/app/").await,
            server.put("/priv/secret.txt").await,
        ] {
            assert_eq!(
                header_value(response.headers(), header::CACHE_CONTROL),
                Some("no-store")
            );
            assert_eq!(
                header_value(response.headers(), header::VARY),
                Some("pubky-host, Authorization, Cookie")
            );
        }
    }

    #[tokio::test]
    async fn private_cache_policy_rewrites_normalized_private_paths() {
        let server = TestServer::new(
            Router::new()
                .route("/{*path}", get(success))
                .layer(middleware::from_fn(private_cache_policy)),
        );

        let response = server.get("/pub/../priv/secret.txt").await;

        assert_eq!(
            header_value(response.headers(), header::CACHE_CONTROL),
            Some("private, no-cache")
        );
        assert_eq!(
            header_value(response.headers(), header::VARY),
            Some("pubky-host, Authorization, Cookie")
        );
    }

    #[tokio::test]
    async fn private_cache_policy_strips_error_validators() {
        let server = TestServer::new(
            Router::new()
                .route("/{*path}", post(missing))
                .layer(middleware::from_fn(private_cache_policy)),
        );

        let response = server.post("/priv/missing.txt").await;

        response.assert_status(StatusCode::NOT_FOUND);
        assert_eq!(
            header_value(response.headers(), header::CACHE_CONTROL),
            Some("no-store")
        );
        assert_eq!(
            header_value(response.headers(), header::VARY),
            Some("pubky-host, Authorization, Cookie")
        );
        assert!(!response.headers().contains_key(header::ETAG));
        assert!(!response.headers().contains_key(header::LAST_MODIFIED));
    }

    #[tokio::test]
    async fn private_cache_policy_leaves_public_responses_unchanged() {
        let server = TestServer::new(
            Router::new()
                .route("/{*path}", get(success))
                .layer(middleware::from_fn(private_cache_policy)),
        );

        let response = server.get("/pub/file.txt").await;

        assert_eq!(
            header_value(response.headers(), header::CACHE_CONTROL),
            Some("private, must-revalidate")
        );
        assert_eq!(
            header_value(response.headers(), header::VARY),
            Some("pubky-host")
        );
    }

    #[tokio::test]
    async fn sse_cache_policy_stamps_success_and_error_responses() {
        let server = TestServer::new(
            Router::new()
                .route("/events-stream", get(success).post(missing))
                .layer(middleware::from_fn(sse_cache_policy)),
        );

        for response in [
            server.get("/events-stream").await,
            server.post("/events-stream").await,
        ] {
            assert_eq!(
                header_value(response.headers(), header::CACHE_CONTROL),
                Some("no-store")
            );
            assert_eq!(
                header_value(response.headers(), header::VARY),
                Some("pubky-host, Authorization, Cookie")
            );
        }
    }
}
