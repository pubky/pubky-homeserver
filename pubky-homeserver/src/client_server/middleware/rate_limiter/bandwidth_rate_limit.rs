//! Bandwidth (speed) rate limiting layer.
//!
//! Throttles upload and download body streams using governor-based
//! per-key bandwidth limits. Supports per-user overrides from `UserQuota`
//! and unauthenticated IP-keyed read limits.

use axum::response::{IntoResponse, Response};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use futures_util::future::BoxFuture;
use governor::RateLimiter;
use std::sync::Arc;
use std::time::Duration;
use std::{convert::Infallible, task::Poll};
use tower::{Layer, Service};

use crate::client_server::middleware::pubky_host::PubkyHost;
use crate::quota_config::LimitKey;
use crate::services::user_service::UserService;
use crate::shared::HttpError;
use crate::DefaultQuotasToml;

use super::limiter_pool::{KeyedRateLimiter, LimiterPool};
use super::request_info::{is_write_method, RequestInfo};
use super::throttle::{throttle_request, throttle_response};
use super::CLEANUP_INTERVAL_SECS;

/// A Tower Layer for bandwidth (speed) rate limiting.
///
/// Throttles request and response body streams based on auth status:
/// - Authenticated users: per-user rate from DB (`UserQuota`), falling back
///   to server defaults from `[default_quotas]`.
/// - Unauthenticated requests: IP-keyed read rate from
///   `unauthenticated_ip_rate_read`.
///
/// Requires a `PubkyHostLayer` to be applied first.
#[derive(Debug, Clone)]
pub struct BandwidthQuotaLimitLayer {
    user_service: UserService,
    defaults: DefaultQuotasToml,
}

impl BandwidthQuotaLimitLayer {
    pub fn new(user_service: UserService, defaults: DefaultQuotasToml) -> Self {
        Self {
            user_service,
            defaults,
        }
    }
}

impl<S> Layer<S> for BandwidthQuotaLimitLayer {
    type Service = BandwidthQuotaLimitMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        let state = BandwidthState::new(self.user_service.clone(), self.defaults.clone());
        BandwidthQuotaLimitMiddleware { inner, state }
    }
}

/// Runtime state for bandwidth throttling, shared between middleware clones.
#[derive(Debug, Clone)]
struct BandwidthState {
    user_service: UserService,
    defaults: DefaultQuotasToml,
    user_read_limiters: LimiterPool,
    user_write_limiters: LimiterPool,
    unauthenticated_read_limiter: Option<Arc<KeyedRateLimiter>>,
}

impl BandwidthState {
    fn new(user_service: UserService, defaults: DefaultQuotasToml) -> Self {
        let unauthenticated_read_limiter =
            defaults.unauthenticated_ip_rate_read.as_ref().map(|rate| {
                let quota = rate.to_governor_quota(None);
                let limiter = Arc::new(RateLimiter::keyed(quota));

                let weak = Arc::downgrade(&limiter);
                tokio::spawn(async move {
                    let mut interval =
                        tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
                    interval.tick().await;
                    loop {
                        interval.tick().await;
                        let Some(limiter) = weak.upgrade() else {
                            break;
                        };
                        limiter.retain_recent();
                        limiter.shrink_to_fit();
                    }
                });

                limiter
            });

        Self {
            user_service,
            defaults,
            user_read_limiters: LimiterPool::new(),
            user_write_limiters: LimiterPool::new(),
            unauthenticated_read_limiter,
        }
    }

    /// Returns `true` when there is something to check for this request.
    fn should_limit(&self, req: &Request<Body>) -> bool {
        let has_user = req.extensions().get::<PubkyHost>().is_some();
        let has_bandwidth = self.unauthenticated_read_limiter.is_some();
        has_user || has_bandwidth
    }

    /// Resolve which bandwidth throttler applies to this request.
    ///
    /// Returns at most one throttler: either a per-user limiter (authenticated)
    /// or an IP-keyed limiter (unauthenticated / unknown user).
    #[allow(clippy::result_large_err)]
    async fn resolve_bandwidth_throttler(
        &self,
        info: &RequestInfo,
    ) -> Result<Option<(LimitKey, Arc<KeyedRateLimiter>)>, Response> {
        let Some(pubkey) = info.user_pubkey.as_ref() else {
            return Ok(self.ip_throttler(&info.client_ip));
        };

        // Resolve per-user quota from cache/DB.
        let quota = self.user_service.resolve_quota(pubkey).await.map_err(|e| {
            tracing::error!("Failed to resolve user limits for {}: {e}", pubkey.z32());
            HttpError::new_with_message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to resolve user limits",
            )
            .into_response()
        })?;

        // Unknown user (e.g. spoofed cookie) → fall back to IP throttle.
        let Some(quota) = quota else {
            return Ok(self.ip_throttler(&info.client_ip));
        };

        // Pick read vs write fields based on HTTP method.
        let is_write = is_write_method(&info.method);
        let (rate_override, default_rate, user_burst, default_burst, pool) = if is_write {
            (
                &quota.rate_write,
                self.defaults.rate_write.as_ref(),
                quota.rate_write_burst,
                self.defaults.rate_write_burst,
                &self.user_write_limiters,
            )
        } else {
            (
                &quota.rate_read,
                self.defaults.rate_read.as_ref(),
                quota.rate_read_burst,
                self.defaults.rate_read_burst,
                &self.user_read_limiters,
            )
        };

        // Resolve effective rate: user override → server default → None (no throttle).
        let Some(rate) = rate_override.resolve_with_default(default_rate) else {
            return Ok(None);
        };

        let burst = user_burst.or(default_burst);
        let limiter = pool.get_or_create(&rate, burst);
        Ok(Some((LimitKey::User(pubkey.clone()), limiter)))
    }

    /// Try to resolve the unauthenticated IP throttler for the client IP.
    fn ip_throttler(
        &self,
        client_ip: &Result<std::net::IpAddr, anyhow::Error>,
    ) -> Option<(LimitKey, Arc<KeyedRateLimiter>)> {
        let limiter = self.unauthenticated_read_limiter.as_ref()?;
        match client_ip {
            Ok(ip) => Some((LimitKey::Ip(*ip), limiter.clone())),
            Err(e) => {
                tracing::warn!("Failed to extract IP for unauthenticated rate limiting: {e}");
                None
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct BandwidthQuotaLimitMiddleware<S> {
    inner: S,
    state: BandwidthState,
}

impl<S> Service<Request<Body>> for BandwidthQuotaLimitMiddleware<S>
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

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();

        if !self.state.should_limit(&req) {
            return Box::pin(async move { inner.call(req).await });
        }

        let state = self.state.clone();

        Box::pin(async move {
            // Resolve bandwidth throttler based on auth status.
            let info = RequestInfo::from_request(&req);
            let throttler = match state.resolve_bandwidth_throttler(&info).await {
                Ok(t) => t,
                Err(resp) => return Ok(resp),
            };

            if let Some((ref key, ref limiter)) = throttler {
                req = throttle_request(req, key, limiter);
            }

            let mut response = inner.call(req).await?;

            if let Some((ref key, ref limiter)) = throttler {
                response = throttle_response(response, key, limiter);
            }

            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use axum::middleware::{from_fn, Next};
    use axum::routing::{get, post};
    use axum::{body::Body, Router};
    use axum_server::Server;
    use futures_util::StreamExt;
    use pubky_common::auth::jws::GrantId;
    use pubky_common::capabilities::{Capabilities, Capability};
    use pubky_common::crypto::Keypair;
    use pubky_common::crypto::PublicKey;
    use reqwest::Client;
    use tokio::{task::JoinHandle, time::Instant};
    use tower_cookies::CookieManagerLayer;

    use crate::client_server::auth::grant::session::GrantSession;
    use crate::client_server::auth::AuthSession;
    use crate::client_server::middleware::pubky_host::PubkyHost;
    use crate::client_server::middleware::pubky_host::PubkyHostLayer;
    use crate::data_directory::quota_config::BandwidthQuota;
    use crate::persistence::sql::SqlDb;
    use crate::services::user_service::UserService;
    use crate::shared::user_quota::{QuotaOverride, UserQuota};
    use crate::shared::HttpResult;

    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    async fn upload_handler(body: Body) -> HttpResult<impl IntoResponse> {
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await.transpose()? {
            let _ = chunk;
        }
        Ok((StatusCode::CREATED, ()))
    }

    async fn download_handler() -> HttpResult<impl IntoResponse> {
        let response_body = vec![0u8; 3 * 1024]; // 3kb
        Ok((StatusCode::OK, response_body))
    }

    async fn start_server(
        user_service: UserService,
        defaults: crate::DefaultQuotasToml,
        auth_public_key: Option<PublicKey>,
    ) -> SocketAddr {
        let app = Router::new()
            .route("/upload", post(upload_handler))
            .route("/download", get(download_handler))
            .layer(BandwidthQuotaLimitLayer::new(user_service, defaults))
            .layer(from_fn(move |mut req: Request<Body>, next: Next| {
                let auth_public_key = auth_public_key.clone();
                async move {
                    if let (Some(public_key), Some(_)) =
                        (auth_public_key, req.extensions().get::<PubkyHost>())
                    {
                        req.extensions_mut().insert(auth_session(public_key));
                    }
                    next.run(req).await
                }
            }))
            .layer(CookieManagerLayer::new())
            .layer(PubkyHostLayer);

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

    fn auth_session(public_key: PublicKey) -> AuthSession {
        AuthSession::Grant(GrantSession::test(
            public_key,
            Capabilities::builder().cap(Capability::root()).finish(),
            GrantId::generate(),
            chrono::Utc::now().timestamp() as u64 + 3600,
        ))
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_throttle_unauthenticated_download() {
        let db = SqlDb::test().await;
        let user_service = UserService::new(db);
        let rate: BandwidthQuota = "1kb/s".parse().unwrap();
        let defaults = crate::DefaultQuotasToml {
            unauthenticated_ip_rate_read: Some(rate),
            ..Default::default()
        };
        let socket = start_server(user_service, defaults, None).await;

        fn download_data(socket: SocketAddr) -> JoinHandle<()> {
            tokio::spawn(async move {
                let client = Client::new();
                let response = client
                    .get(format!("http://{}/download", socket))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                response.bytes().await.unwrap();
            })
        }

        let start = Instant::now();
        let handle1 = download_data(socket);
        let handle2 = download_data(socket);

        let _ = tokio::try_join!(handle1, handle2);

        let time_taken = start.elapsed();
        assert!(
            time_taken > Duration::from_secs(5),
            "Should take >5s: downloads limited to 1kb/s and sum is 6kb. Took: {:?}",
            time_taken
        );
    }

    #[tokio::test]
    async fn test_user_rate_override_direction_detection() {
        let write_rate: BandwidthQuota = "5mb/s".parse().unwrap();
        let read_rate: BandwidthQuota = "10mb/s".parse().unwrap();
        let quota = UserQuota {
            rate_write: QuotaOverride::Value(write_rate.clone()),
            rate_read: QuotaOverride::Value(read_rate.clone()),
            ..Default::default()
        };

        assert_eq!(quota.rate_write.as_value(), Some(&write_rate));
        assert_eq!(quota.rate_read.as_value(), Some(&read_rate));

        let default_quota = UserQuota::default();
        assert!(default_quota.rate_write.is_default());
        assert!(default_quota.rate_read.is_default());
    }

    #[tokio::test]
    async fn test_user_rate_override_unlimited_bypass() {
        let quota = UserQuota {
            rate_write: QuotaOverride::Unlimited,
            ..Default::default()
        };

        assert!(quota.rate_write.is_unlimited());
    }

    #[test]
    fn test_user_without_override_uses_server_default() {
        let quota = UserQuota::default();
        assert!(quota.rate_write.is_default());
        assert!(quota.rate_read.is_default());

        let default_read: BandwidthQuota = "10mb/s".parse().unwrap();
        assert_eq!(
            quota.rate_read.resolve_with_default(Some(&default_read)),
            Some(default_read)
        );
        assert_eq!(quota.rate_write.resolve_with_default(None), None);
    }

    #[test]
    fn test_resolve_bandwidth_rate_with_user_override() {
        let default_read: BandwidthQuota = "10mb/s".parse().unwrap();

        let custom_rate: BandwidthQuota = "20mb/s".parse().unwrap();
        let quota = UserQuota {
            rate_read: QuotaOverride::Value(custom_rate.clone()),
            ..Default::default()
        };
        assert_eq!(
            quota.rate_read.resolve_with_default(Some(&default_read)),
            Some(custom_rate)
        );

        let unlimited_quota = UserQuota {
            rate_read: QuotaOverride::Unlimited,
            ..Default::default()
        };
        assert_eq!(
            unlimited_quota
                .rate_read
                .resolve_with_default(Some(&default_read)),
            None
        );
    }

    /// Integration test: authenticated user with a per-user DB rate override.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_authenticated_user_gets_per_user_rate_from_db() {
        use crate::persistence::sql::user::UserRepository;

        let db = SqlDb::test().await;
        let user_service = UserService::new(db.clone());

        let keypair = Keypair::random();
        let pubkey = keypair.public_key();
        let user = UserRepository::create(&pubkey, &mut db.pool().into())
            .await
            .unwrap();
        let quota = UserQuota {
            rate_read: QuotaOverride::Value("100mb/s".parse().unwrap()),
            ..Default::default()
        };
        UserRepository::set_quota(user.id, &quota, &mut db.pool().into())
            .await
            .unwrap();

        let defaults = crate::DefaultQuotasToml {
            rate_read: Some("1kb/s".parse().unwrap()),
            unauthenticated_ip_rate_read: Some("1kb/s".parse().unwrap()),
            ..Default::default()
        };

        let socket = start_server(user_service, defaults, Some(pubkey.clone())).await;
        let z32 = pubkey.z32();

        let start = Instant::now();
        let client = Client::new();
        let response = client
            .get(format!("http://{}/download?pubky-host={}", socket, z32))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.bytes().await.unwrap();
        let authenticated_time = start.elapsed();

        let start = Instant::now();
        let response = client
            .get(format!("http://{}/download", socket))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.bytes().await.unwrap();
        let unauthenticated_time = start.elapsed();

        assert!(
            authenticated_time < Duration::from_secs(2),
            "Authenticated download with 100mb/s override should be fast, took: {:?}",
            authenticated_time
        );
        assert!(
            unauthenticated_time > Duration::from_secs(2),
            "Unauthenticated download at 1kb/s should take >2s for 3kb, took: {:?}",
            unauthenticated_time
        );
    }
}
