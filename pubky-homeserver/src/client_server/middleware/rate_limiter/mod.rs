/// How often (in seconds) background cleanup tasks run to evict expired
/// rate-limiter entries and shrink internal maps.
const CLEANUP_INTERVAL_SECS: u64 = 60;

mod bandwidth_rate_limit;
mod extract_ip;
mod limiter_pool;
mod request_info;
mod request_rate_limit;
mod throttle;

pub use bandwidth_rate_limit::BandwidthQuotaLimitLayer;
pub use request_rate_limit::RequestRateLimitLayer;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use axum::middleware;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::Router;
    use axum_server::Server;
    use futures_util::StreamExt;
    use reqwest::Client;
    use tokio::time::Instant;
    use tower_cookies::CookieManagerLayer;

    use crate::client_server::middleware::request_tenant::RequestTenant;
    use crate::data_directory::quota_config::BandwidthQuota;
    use crate::persistence::sql::SqlDb;
    use crate::quota_config::{GlobPattern, HttpMethod, LimitKeyType, PathLimit};
    use crate::services::user_service::UserService;
    use crate::shared::HttpResult;

    use super::{BandwidthQuotaLimitLayer, RequestRateLimitLayer};

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

    async fn start_combined_server(
        path_limits: Vec<PathLimit>,
        user_service: UserService,
        defaults: crate::DefaultQuotasToml,
    ) -> SocketAddr {
        // Stack both layers in the same order as app.rs:
        // RequestRateLimitLayer is outermost (checked first),
        // BandwidthQuotaLimitLayer is inner.
        let app = Router::new()
            .route("/upload", post(upload_handler))
            .route("/download", get(download_handler))
            .layer(BandwidthQuotaLimitLayer::new(user_service, defaults))
            .layer(
                RequestRateLimitLayer::from_path_limits(path_limits)
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

    /// Both layers stacked: request-count limit rejects before bandwidth
    /// throttling kicks in, and allowed requests are still throttled.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_combined_request_count_and_bandwidth() {
        let db = SqlDb::test().await;
        let user_service = UserService::new(db);

        let path_limit = PathLimit {
            path: GlobPattern::new("/upload"),
            method: HttpMethod(Method::POST),
            quota: "1r/m".parse().unwrap(),
            key: LimitKeyType::Ip,
            burst: None,
            whitelist: Vec::new(),
        };

        let rate: BandwidthQuota = "1kb/s".parse().unwrap();
        let defaults = crate::DefaultQuotasToml {
            unauthenticated_ip_rate_read: Some(rate),
            ..Default::default()
        };

        let socket = start_combined_server(vec![path_limit], user_service, defaults).await;
        let client = Client::new();

        // First upload succeeds (within request-count limit).
        let res = client
            .post(format!("http://{}/upload", socket))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        // Second upload is rejected by request-count limiter.
        let res = client
            .post(format!("http://{}/upload", socket))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

        // Download is not affected by the upload request-count limit
        // but is throttled by bandwidth (1kb/s for 3kb = >2s).
        let start = Instant::now();
        let res = client
            .get(format!("http://{}/download", socket))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        res.bytes().await.unwrap();
        let time_taken = start.elapsed();

        assert!(
            time_taken > Duration::from_secs(2),
            "Download should be bandwidth-throttled at 1kb/s for 3kb, took: {:?}",
            time_taken
        );
    }

    /// Request-count rejection is fast — no bandwidth overhead added.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_request_count_rejects_before_bandwidth_resolution() {
        let db = SqlDb::test().await;
        let user_service = UserService::new(db);

        let path_limit = PathLimit {
            path: GlobPattern::new("/download"),
            method: HttpMethod(Method::GET),
            quota: "1r/m".parse().unwrap(),
            key: LimitKeyType::Ip,
            burst: None,
            whitelist: Vec::new(),
        };

        let defaults = crate::DefaultQuotasToml {
            unauthenticated_ip_rate_read: Some("1kb/s".parse().unwrap()),
            ..Default::default()
        };

        let socket = start_combined_server(vec![path_limit], user_service, defaults).await;
        let client = Client::new();

        // First request uses the one allowed slot.
        let res = client
            .get(format!("http://{}/download", socket))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        res.bytes().await.unwrap();

        // Second request should be rejected quickly by request-count layer,
        // not delayed by bandwidth throttling.
        let start = Instant::now();
        let res = client
            .get(format!("http://{}/download", socket))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        let rejection_time = start.elapsed();

        assert!(
            rejection_time < Duration::from_secs(1),
            "Request-count rejection should be near-instant, took: {:?}",
            rejection_time
        );
    }
}
