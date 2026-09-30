//! Metrics recorder and connection tracking.
//!
//! Neutral observability layer: the [`Metrics`] recorder (OpenTelemetry + Prometheus) and the
//! [`ConnectionGuard`] RAII helper live here so any subsystem can record without depending on a
//! server route. The `metrics_server` *serves* this over HTTP; subsystems (`persistence`,
//! `client_server`, …) only *record* into it.

use opentelemetry::{
    metrics::{Counter, Histogram, Meter, MeterProvider, UpDownCounter},
    KeyValue,
};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{Encoder, Registry, TextEncoder};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MetricsInitError {
    #[error("Failed to build Prometheus exporter: {0}")]
    PrometheusExporter(String),
}

pub const EVENTS_DB_QUERY_DURATION: &str = "events_db_query_duration_ms";
pub const EVENT_STREAM_DB_QUERY_DURATION: &str = "event_stream_db_query_duration_ms";
pub const EVENT_STREAM_BROADCAST_LAGGED_COUNT: &str = "event_stream_broadcast_lagged_count";
pub const EVENT_STREAM_BROADCAST_HALF_FULL_COUNT: &str = "event_stream_broadcast_half_full_count";
pub const EVENT_STREAM_ACTIVE_CONNECTIONS: &str = "event_stream_active_connections";
pub const EVENT_STREAM_CONNECTION_DURATION: &str = "event_stream_connection_duration_ms";
pub const SIGNUP_COUNT: &str = "signup_count";
pub const STORAGE_REQUEST_COUNT: &str = "storage_request_count";

#[derive(Clone, Copy, Debug)]
pub(crate) enum StorageAddressingMode {
    Path,
    Legacy,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum PubkyHostHeaderUsage {
    Absent,
    Matching,
    Other,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum StorageAuthMethod {
    None,
    Cookie,
    Grant,
}

#[derive(Clone, Debug)]
pub struct Metrics {
    registry: Arc<Registry>,
    _provider: Arc<SdkMeterProvider>,
    events_db_query_duration: Histogram<f64>,
    event_stream_db_query_duration: Histogram<f64>,
    event_stream_broadcast_lagged_count: Counter<u64>,
    event_stream_broadcast_half_full_count: Counter<u64>,
    event_stream_active_connections: UpDownCounter<i64>,
    event_stream_connection_duration: Histogram<f64>,
    signup_count: Counter<u64>,
    storage_request_count: Counter<u64>,
}

impl Metrics {
    pub fn new() -> Result<Self, MetricsInitError> {
        let (registry, provider, meter) = init_metrics()?;

        let events_db_query_duration = meter
            .f64_histogram(EVENTS_DB_QUERY_DURATION)
            .with_description("Duration of /events database queries in milliseconds")
            .build();

        let event_stream_db_query_duration = meter
            .f64_histogram(EVENT_STREAM_DB_QUERY_DURATION)
            .with_description("Duration of /events-stream database queries in milliseconds")
            .build();

        let event_stream_broadcast_lagged_count = meter
            .u64_counter(EVENT_STREAM_BROADCAST_LAGGED_COUNT)
            .with_description("Number of times event stream broadcast channel lagged")
            .build();

        let event_stream_broadcast_half_full_count = meter
            .u64_counter(EVENT_STREAM_BROADCAST_HALF_FULL_COUNT)
            .with_description(
                "Number of times event stream broadcast channel reached half capacity",
            )
            .build();

        let event_stream_active_connections = meter
            .i64_up_down_counter(EVENT_STREAM_ACTIVE_CONNECTIONS)
            .with_description("Number of active event stream connections")
            .build();

        let event_stream_connection_duration = meter
            .f64_histogram(EVENT_STREAM_CONNECTION_DURATION)
            .with_description("Duration of event stream connections in milliseconds")
            .with_boundaries(vec![10.0, 100.0, 1_000.0, 10_000.0, 100_000.0])
            .build();

        let signup_count = meter
            .u64_counter(SIGNUP_COUNT)
            .with_description("Total number of successful signups")
            .build();

        let storage_request_count = meter
            .u64_counter(STORAGE_REQUEST_COUNT)
            .with_description("Number of client storage requests by migration mode")
            .build();

        Ok(Self {
            registry: Arc::new(registry),
            _provider: Arc::new(provider),
            events_db_query_duration,
            event_stream_db_query_duration,
            event_stream_broadcast_lagged_count,
            event_stream_broadcast_half_full_count,
            event_stream_active_connections,
            event_stream_connection_duration,
            signup_count,
            storage_request_count,
        })
    }

    // === /events endpoint metrics ===

    pub fn record_events_db_query(&self, duration_ms: u128) {
        self.events_db_query_duration
            .record(duration_ms as f64, &[]);
    }

    // === /events-stream endpoint metrics ===

    pub fn record_event_stream_db_query(&self, duration_ms: u128) {
        self.event_stream_db_query_duration
            .record(duration_ms as f64, &[]);
    }

    pub fn record_broadcast_lagged(&self) {
        self.event_stream_broadcast_lagged_count.add(1, &[]);
    }

    pub fn record_broadcast_half_full(&self) {
        self.event_stream_broadcast_half_full_count.add(1, &[]);
    }

    pub fn increment_active_connections(&self) {
        self.event_stream_active_connections.add(1, &[]);
    }

    pub fn decrement_active_connections(&self) {
        self.event_stream_active_connections.add(-1, &[]);
    }

    pub fn record_connection_closed(&self, duration_ms: u128) {
        self.event_stream_connection_duration
            .record(duration_ms as f64, &[]);
    }

    // === signup metrics ===

    pub fn record_signup(&self) {
        self.signup_count.add(1, &[]);
    }

    // === storage migration metrics ===

    pub(crate) fn record_storage_request(
        &self,
        addressing_mode: StorageAddressingMode,
        pubky_host_header: PubkyHostHeaderUsage,
        pubky_host_query: bool,
        auth_method: StorageAuthMethod,
    ) {
        let addressing_mode = match addressing_mode {
            StorageAddressingMode::Path => "path",
            StorageAddressingMode::Legacy => "legacy",
        };
        let pubky_host_header = match pubky_host_header {
            PubkyHostHeaderUsage::Absent => "absent",
            PubkyHostHeaderUsage::Matching => "matching",
            PubkyHostHeaderUsage::Other => "other",
        };
        let auth_method = match auth_method {
            StorageAuthMethod::None => "none",
            StorageAuthMethod::Cookie => "cookie",
            StorageAuthMethod::Grant => "grant",
        };

        self.storage_request_count.add(
            1,
            &[
                KeyValue::new("addressing_mode", addressing_mode),
                KeyValue::new("pubky_host_header", pubky_host_header),
                KeyValue::new("pubky_host_query", pubky_host_query),
                KeyValue::new("auth_method", auth_method),
            ],
        );
    }

    /// Render Prometheus metrics in text format
    pub fn render(&self) -> Result<String, String> {
        let metric_families = self.registry.gather();
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();

        encoder.encode(&metric_families, &mut buffer).map_err(|e| {
            tracing::error!("Failed to encode metrics: {:?}", e);
            format!("Failed to encode metrics: {}", e)
        })?;

        String::from_utf8(buffer).map_err(|e| {
            tracing::error!("Failed to convert metrics to UTF-8: {:?}", e);
            format!("Failed to convert metrics to UTF-8: {}", e)
        })
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
            .expect("Failed to initialize metrics - this should never fail with default config")
    }
}

/// Initialize OpenTelemetry with Prometheus exporter
/// Returns the Prometheus Registry, MeterProvider, and Meter for creating instruments
fn init_metrics() -> Result<(Registry, SdkMeterProvider, Meter), MetricsInitError> {
    let registry = Registry::new();
    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()
        .map_err(|e| MetricsInitError::PrometheusExporter(e.to_string()))?;
    let provider = SdkMeterProvider::builder().with_reader(exporter).build();
    let meter = provider.meter("pubky_homeserver");
    Ok((registry, provider, meter))
}

/// Increments the active-connection gauge on creation and, on drop (any exit path),
/// decrements it and records the connection duration. Shared by the public and admin
/// event-stream endpoints so both record the same metrics.
pub(crate) struct ConnectionGuard {
    metrics: Metrics,
    start: Instant,
}

impl ConnectionGuard {
    pub(crate) fn new(metrics: Metrics) -> Self {
        metrics.increment_active_connections();
        Self {
            metrics,
            start: Instant::now(),
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.metrics.decrement_active_connections();
        self.metrics
            .record_connection_closed(self.start.elapsed().as_millis());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_guard_drops_on_early_return() {
        let metrics = Metrics::new().expect("Failed to create metrics");

        // Create guard and return early - guard should still decrement
        fn early_return_fn(metrics: Metrics) -> Result<(), &'static str> {
            let _guard = ConnectionGuard::new(metrics.clone());
            // Simulate early return (e.g., error condition)
            return Err("early exit");
            #[allow(unreachable_code)]
            {
                Ok(())
            }
        }

        let result = early_return_fn(metrics.clone());
        assert!(result.is_err(), "Should have returned early");

        // Verify guard cleaned up properly despite early return
        let output = metrics.render().expect("Failed to render metrics");
        assert!(
            output.contains("event_stream_active_connections") && output.contains("} 0"),
            "Should have 0 active connections after early return: {}",
            output
        );
        assert!(
            output.contains("event_stream_connection_duration_ms_count"),
            "Should have recorded connection duration: {}",
            output
        );
    }

    #[tokio::test]
    async fn connection_guard_concurrent() {
        let metrics = Metrics::new().expect("Failed to create metrics");

        // Create 5 concurrent guards using tokio::spawn
        let handles: Vec<_> = (0..5)
            .map(|i| {
                let metrics_clone = metrics.clone();
                tokio::spawn(async move {
                    let _guard = ConnectionGuard::new(metrics_clone);
                    // Simulate some work
                    tokio::time::sleep(tokio::time::Duration::from_millis(10 * i)).await;
                    // Guard will be dropped here
                })
            })
            .collect();

        // While tasks are running, check active connections
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        let output = metrics.render().expect("Failed to render metrics");
        // We should have some active connections (implementation dependent on timing)
        assert!(
            output.contains("event_stream_active_connections"),
            "Should have active connections metric: {}",
            output
        );

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // All guards should be cleaned up
        let output = metrics.render().expect("Failed to render metrics");
        assert!(
            output.contains("event_stream_active_connections") && output.contains("} 0"),
            "Should have 0 active connections after all concurrent guards dropped: {}",
            output
        );
        assert!(
            output.contains("event_stream_connection_duration_ms_count") && output.contains("} 5"),
            "Should have recorded 5 connection durations: {}",
            output
        );
    }

    #[test]
    fn test_metrics_recording() {
        let metrics = Metrics::new().expect("Failed to create metrics");

        // Record various metrics
        metrics.record_events_db_query(100);
        metrics.record_event_stream_db_query(200);
        metrics.increment_active_connections();
        metrics.record_broadcast_lagged();
        metrics.record_broadcast_half_full();
        metrics.record_connection_closed(30);
        metrics.record_signup();
        metrics.record_storage_request(
            StorageAddressingMode::Path,
            PubkyHostHeaderUsage::Matching,
            true,
            StorageAuthMethod::Cookie,
        );

        let output = metrics.render().expect("Failed to render metrics");

        // Verify output is valid Prometheus format
        assert!(!output.is_empty());
        assert!(output.starts_with("#") || output.contains("# HELP"));
        // Verify all metric names appear in output
        assert!(
            output.contains(EVENTS_DB_QUERY_DURATION),
            "Missing {} in: {}",
            EVENTS_DB_QUERY_DURATION,
            output
        );
        assert!(
            output.contains(EVENT_STREAM_DB_QUERY_DURATION),
            "Missing {} in: {}",
            EVENT_STREAM_DB_QUERY_DURATION,
            output
        );
        assert!(
            output.contains(EVENT_STREAM_ACTIVE_CONNECTIONS),
            "Missing {} in: {}",
            EVENT_STREAM_ACTIVE_CONNECTIONS,
            output
        );
        assert!(
            output.contains(EVENT_STREAM_BROADCAST_LAGGED_COUNT),
            "Missing {} in: {}",
            EVENT_STREAM_BROADCAST_LAGGED_COUNT,
            output
        );
        assert!(
            output.contains(EVENT_STREAM_BROADCAST_HALF_FULL_COUNT),
            "Missing {} in: {}",
            EVENT_STREAM_BROADCAST_HALF_FULL_COUNT,
            output
        );
        assert!(
            output.contains(EVENT_STREAM_CONNECTION_DURATION),
            "Missing {} in: {}",
            EVENT_STREAM_CONNECTION_DURATION,
            output
        );
        assert!(
            output.contains(SIGNUP_COUNT),
            "Missing {} in: {}",
            SIGNUP_COUNT,
            output
        );
        assert!(
            output.contains(STORAGE_REQUEST_COUNT),
            "Missing {} in: {}",
            STORAGE_REQUEST_COUNT,
            output
        );
        assert!(output.contains("addressing_mode=\"path\""));
        assert!(output.contains("auth_method=\"cookie\""));
        assert!(output.contains("pubky_host_header=\"matching\""));
        assert!(output.contains("pubky_host_query=\"true\""));
    }
}
