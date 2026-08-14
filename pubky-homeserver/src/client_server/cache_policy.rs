use axum::{
    extract::Request,
    http::{header, HeaderValue},
    middleware::Next,
    response::Response,
};
use percent_encoding::percent_decode_str;

use crate::client_server::middleware::request_tenant::RequestTenant;
use crate::{constants::PRIVATE_ROOT, shared::webdav::StoragePath};

pub(crate) const CACHE_CONTROL_NO_STORE: HeaderValue = HeaderValue::from_static("no-store");
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
        apply_private_cache_headers(&mut response, vary_on_pubky_host);
        if response.status().as_u16() >= 400 {
            remove_validators(&mut response);
        }
    }

    response
}

pub(crate) async fn sse_cache_policy(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    apply_private_cache_headers(&mut response, true);
    response
}

fn apply_private_cache_headers(response: &mut Response, vary_on_pubky_host: bool) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, CACHE_CONTROL_NO_STORE);
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
        routing::{get, post},
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
    async fn private_cache_policy_rewrites_private_success_headers() {
        let server = TestServer::new(
            Router::new()
                .route("/{*path}", get(success))
                .layer(middleware::from_fn(private_cache_policy)),
        )
        .unwrap();

        let response = server.get("/priv/secret.txt").await;

        assert_eq!(
            header_value(response.headers(), header::CACHE_CONTROL),
            Some("no-store")
        );
        assert_eq!(
            header_value(response.headers(), header::VARY),
            Some("pubky-host, Authorization, Cookie")
        );
        assert!(response.headers().contains_key(header::ETAG));
        assert!(response.headers().contains_key(header::LAST_MODIFIED));
    }

    #[tokio::test]
    async fn private_cache_policy_rewrites_normalized_private_paths() {
        let server = TestServer::new(
            Router::new()
                .route("/{*path}", get(success))
                .layer(middleware::from_fn(private_cache_policy)),
        )
        .unwrap();

        let response = server.get("/pub/../priv/secret.txt").await;

        assert_eq!(
            header_value(response.headers(), header::CACHE_CONTROL),
            Some("no-store")
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
        )
        .unwrap();

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
        )
        .unwrap();

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
        )
        .unwrap();

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
