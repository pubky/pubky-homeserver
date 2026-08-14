use std::sync::Arc;

use axum::{extract::Request, Router};
use tower_http::trace::{
    DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, OnFailure, OnRequest, OnResponse,
    TraceLayer,
};
use tracing::{Level, Span};

use super::request_tenant::RequestTenant;

// Silence events path from logs to avoid noisy logs. Only log when there is an error.
const TRACING_EXCLUDED_PATHS: [&str; 1] = ["/events/"];

pub fn with_trace_layer(router: Router) -> Router {
    let excluded_paths = Arc::new(
        TRACING_EXCLUDED_PATHS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
    );

    router.layer(
        TraceLayer::new_for_http()
            .make_span_with(move |request: &Request| {
                let uri = if let Some(tenant) = request.extensions().get::<RequestTenant>() {
                    tenant.pubky_url(request.uri())
                } else {
                    request.uri().to_string()
                };

                if excluded_paths.contains(&request.uri().path().to_string()) {
                    tracing::span!(
                        Level::INFO,
                        "request",
                        method = %request.method(),
                        uri = ?uri,
                        version = ?request.version(),
                        events=true
                    )
                } else {
                    tracing::span!(
                        Level::INFO,
                        "request",
                        method = %request.method(),
                        uri = ?uri,
                        version = ?request.version(),
                    )
                }
            })
            .on_request(|request: &Request, span: &Span| {
                // Skip logging for excluded spans
                if span.has_field("events") {
                    return;
                }
                // Use the default behavior for other spans
                DefaultOnRequest::new().on_request(request, span);
            })
            .on_response(
                |response: &axum::response::Response, latency: std::time::Duration, span: &Span| {
                    // Skip logging for excluded spans
                    if span.has_field("events") && response.status().is_success() {
                        return;
                    }
                    // Use the default behavior for other spans
                    DefaultOnResponse::new().on_response(response, latency, span);
                },
            )
            .on_failure(
                |error: tower_http::classify::ServerErrorsFailureClass,
                 latency: std::time::Duration,
                 span: &Span| {
                    // Use the default behavior for other spans
                    DefaultOnFailure::new().on_failure(error, latency, span);
                },
            ),
    )
}
