//! Request-count rate limiting layer.
//!
//! Enforces per-path request-count quotas (`[[drive.rate_limits]]` in config).
//! Each path+method pattern has a governor rate limiter keyed by IP or user.

use axum::response::{IntoResponse, Response};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use futures_util::future::BoxFuture;
use std::{convert::Infallible, task::Poll};
use tower::{Layer, Service};

use crate::shared::quota::PathLimit;
use crate::shared::HttpError;

use super::limiter_pool::LimitTuple;

/// A Tower Layer for request-count rate limiting.
///
/// Matches requests by path and method against configured limits and
/// returns 429 TOO MANY REQUESTS when a limit is exceeded.
///
/// Returns 400 BAD REQUEST if the rate-limit key (IP or request tenant)
/// cannot be extracted.
#[derive(Debug, Clone)]
pub struct RequestRateLimitLayer {
    limits: Vec<LimitTuple>,
}

impl RequestRateLimitLayer {
    pub fn from_path_limits(limits: Vec<PathLimit>) -> Result<Self, String> {
        if limits.is_empty() {
            tracing::info!("No path-based request-count rate limits configured ([[drive.rate_limits]] is empty).");
        } else {
            let limits_str = limits
                .iter()
                .map(|limit| format!("\"{limit}\""))
                .collect::<Vec<_>>()
                .join(", ");
            tracing::info!("Path-based rate limits configured: {limits_str}");
        }
        let limits = limits
            .into_iter()
            .map(LimitTuple::new)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { limits })
    }
}

impl<S> Layer<S> for RequestRateLimitLayer {
    type Service = RequestRateLimitMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        let limits = self.limits.clone();
        RequestRateLimitMiddleware { inner, limits }
    }
}

#[derive(Debug, Clone)]
pub struct RequestRateLimitMiddleware<S> {
    inner: S,
    limits: Vec<LimitTuple>,
}

impl<S> Service<Request<Body>> for RequestRateLimitMiddleware<S>
where
    S: Service<Request<Body>, Response = Response, Error = Infallible> + Send + 'static + Clone,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();

        if !self.limits.iter().any(|l| l.is_match(&req)) {
            return Box::pin(async move { inner.call(req).await });
        }

        let limits = self.limits.clone();

        Box::pin(async move {
            if let Err(resp) = check_request_count_limits(&limits, &req) {
                return Ok(resp);
            }
            inner.call(req).await
        })
    }
}

/// Check request-count path limits. Returns an error response if any limit is exceeded.
#[allow(clippy::result_large_err)]
fn check_request_count_limits(limits: &[LimitTuple], req: &Request<Body>) -> Result<(), Response> {
    for limit in limits {
        if !limit.is_match(req) {
            continue;
        }
        let key = match limit.extract_key(req) {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!(
                    "{} {} Failed to extract key for rate limiting: {}",
                    limit.limit.path.0,
                    limit.limit.method.0,
                    e
                );
                return Err(HttpError::new_with_message(
                    StatusCode::BAD_REQUEST,
                    "Failed to extract key for rate limiting",
                )
                .into_response());
            }
        };
        if limit.limit.is_whitelisted(&key) {
            continue;
        }
        if let Err(e) = limit.limiter.check_key(&key) {
            tracing::debug!(
                "Rate limit of {} exceeded for {key}: {}",
                limit.limit.quota,
                e
            );
            return Err(HttpError::new_with_message(
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded",
            )
            .into_response());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::http::Method;
    use axum::{
        middleware,
        routing::{get, post},
        Router,
    };
    use axum_server::Server;
    use pubky_common::crypto::{Keypair, PublicKey};
    use reqwest::{Client, Response};
    use tokio::task::JoinHandle;
    use tower_cookies::CookieManagerLayer;

    use crate::client_server::middleware::request_tenant::RequestTenant;
    use crate::shared::quota::{GlobPattern, HttpMethod, LimitKeyType};
    use crate::shared::HttpResult;

    use super::*;
    use axum::response::IntoResponse;

    async fn upload_handler() -> HttpResult<impl IntoResponse> {
        Ok((StatusCode::CREATED, ()))
    }

    async fn download_handler() -> HttpResult<impl IntoResponse> {
        Ok((StatusCode::OK, ()))
    }

    async fn start_server(config: Vec<PathLimit>) -> SocketAddr {
        let app = Router::new()
            .route("/upload", post(upload_handler))
            .route("/download", get(download_handler))
            .route("/storage/{user_z32}/{*path}", get(download_handler))
            .layer(
                RequestRateLimitLayer::from_path_limits(config)
                    .expect("valid test request-count rate limit"),
            )
            .layer(CookieManagerLayer::new())
            .layer(middleware::from_fn(RequestTenant::resolve));

        let listener = tokio::net::TcpListener::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            0,
        ))
        .await
        .unwrap();
        let socket = listener.local_addr().unwrap();
        let server = Server::<SocketAddr>::from_listener(listener);

        tokio::spawn(async move {
            server
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .unwrap();
        });

        socket
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_limit_parallel_requests_with_ip_key() {
        let path_limit = PathLimit {
            path: GlobPattern::new("/upload"),
            method: HttpMethod(Method::POST),
            quota: "1r/m".parse().unwrap(),
            key: LimitKeyType::Ip,
            burst: None,
            whitelist: Vec::new(),
        };
        let socket = start_server(vec![path_limit]).await;

        fn send_request(socket: SocketAddr) -> JoinHandle<Response> {
            tokio::spawn(async move {
                let client = Client::new();
                client
                    .post(format!("http://{}/upload", socket))
                    .send()
                    .await
                    .unwrap()
            })
        }

        let handle1 = send_request(socket);
        let handle2 = send_request(socket);

        let (res1, res2) = tokio::try_join!(handle1, handle2).unwrap();
        assert_eq!(res1.status(), StatusCode::CREATED);
        assert_eq!(res2.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_limit_parallel_requests_with_user_key() {
        let path_limit = PathLimit {
            path: GlobPattern::new("/upload"),
            method: HttpMethod(Method::POST),
            quota: "1r/m".parse().unwrap(),
            key: LimitKeyType::User,
            burst: None,
            whitelist: Vec::new(),
        };
        let socket = start_server(vec![path_limit]).await;

        fn send_request(socket: SocketAddr, user_pubkey: PublicKey) -> JoinHandle<Response> {
            tokio::spawn(async move {
                let client = Client::new();
                client
                    .post(format!(
                        "http://{}/upload?pubky-host={}",
                        socket,
                        user_pubkey.z32()
                    ))
                    .send()
                    .await
                    .unwrap()
            })
        }

        let user1_pubkey = Keypair::random().public_key();
        let handle1 = send_request(socket, user1_pubkey.clone());
        let handle2 = send_request(socket, user1_pubkey.clone());
        let user2_pubkey = Keypair::random().public_key();
        let handle3 = send_request(socket, user2_pubkey.clone());

        let (res1, res2, res3) = tokio::try_join!(handle1, handle2, handle3).unwrap();

        let mut user1_statuses = [res1.status(), res2.status()];
        user1_statuses.sort_by_key(|s| s.as_u16());
        assert_eq!(
            user1_statuses,
            [StatusCode::CREATED, StatusCode::TOO_MANY_REQUESTS],
            "user1 should have exactly one success and one rate-limited response"
        );
        assert_eq!(res3.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn path_addressed_storage_uses_storage_path_and_owner_for_limits() {
        let path_limit = PathLimit {
            path: GlobPattern::new("/pub/*"),
            method: HttpMethod(Method::GET),
            quota: "1r/m".parse().unwrap(),
            key: LimitKeyType::User,
            burst: None,
            whitelist: Vec::new(),
        };
        let socket = start_server(vec![path_limit]).await;
        let owner = Keypair::random().public_key();
        let other = Keypair::random().public_key();
        let url = format!("http://{socket}/storage/{}/pub/file.txt", owner.z32());
        let client = Client::new();

        let first = client
            .get(&url)
            .header("pubky-host", other.z32())
            .send()
            .await
            .unwrap();
        let second = client
            .get(&url)
            .header("pubky-host", other.z32())
            .send()
            .await
            .unwrap();

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_path_limit_accepts_request_count_quota() {
        let limit = PathLimit {
            path: GlobPattern::new("/session"),
            method: HttpMethod(Method::POST),
            quota: "10r/m".parse().unwrap(),
            key: LimitKeyType::Ip,
            burst: None,
            whitelist: Vec::new(),
        };
        assert!(limit.validate().is_ok());
    }
}
