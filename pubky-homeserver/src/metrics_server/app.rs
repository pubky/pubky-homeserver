use std::net::SocketAddr;
use std::time::Duration;

use crate::observability::Metrics;
use crate::AppContext;
use crate::AppContextBuildError;
use axum::routing::get;
use axum::Router;
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_server::Handle;
use tokio::task::JoinHandle;

fn create_app(metrics: Metrics) -> axum::routing::IntoMakeService<Router> {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics)
        .into_make_service()
}

/// Errors that can occur when building a `MetricsServer`.
#[derive(thiserror::Error, Debug)]
pub enum MetricsServerBuildError {
    /// Failed to create metrics server.
    #[error("Failed to create metrics server: {0}")]
    Server(anyhow::Error),

    /// Failed to bootstrap from the data directory.
    #[error("Failed to bootstrap from the data directory: {0}")]
    DataDir(AppContextBuildError),
}

/// Metrics server
///
/// This server exposes Prometheus metrics on a separate port.
/// It should be isolated from the public network and only accessible to monitoring systems.
///
/// When dropped, the server will stop.
pub struct MetricsServer {
    http_handle: Handle<SocketAddr>,
    join_handle: JoinHandle<()>,
    socket: SocketAddr,
}

impl MetricsServer {
    /// Run the metrics server.
    pub async fn start(context: &AppContext) -> Result<Self, MetricsServerBuildError> {
        let metrics = context.metrics.clone();
        let socket = context.config_toml.metrics.listen_socket;
        let app = create_app(metrics);
        let listener = std::net::TcpListener::bind(socket)
            .map_err(|e| MetricsServerBuildError::Server(e.into()))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| MetricsServerBuildError::Server(e.into()))?;
        let socket = listener
            .local_addr()
            .map_err(|e| MetricsServerBuildError::Server(e.into()))?;
        let http_handle = Handle::new();
        let inner_http_handle = http_handle.clone();
        let server = axum_server::from_tcp(listener)
            .map_err(|e| MetricsServerBuildError::Server(e.into()))?;
        let join_handle = tokio::spawn(async move {
            server
                .handle(inner_http_handle)
                .serve(app)
                .await
                .unwrap_or_else(|e| tracing::error!("Metrics server error: {}", e));
        });
        Ok(Self {
            http_handle,
            socket,
            join_handle,
        })
    }

    /// Get the socket address the metrics server is listening on.
    pub fn listen_socket(&self) -> SocketAddr {
        self.socket
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        self.http_handle
            .graceful_shutdown(Some(Duration::from_secs(5)));
        self.join_handle.abort();
    }
}

/// HTTP handler for the /metrics endpoint
pub async fn metrics_handler(State(metrics): State<Metrics>) -> impl IntoResponse {
    match metrics.render() {
        Ok(body) => (StatusCode::OK, body).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("# Failed to render metrics: {}\n", e),
        )
            .into_response(),
    }
}
