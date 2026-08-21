use pubky_testnet::pubky::{ClientId, Keypair, Method, PubkyHttpClient, StatusCode};

/// Poll metrics endpoint until condition is met or timeout occurs
async fn wait_for_metric_condition<F>(
    client: &PubkyHttpClient,
    metrics_url: &str,
    mut condition: F,
    timeout_ms: u64,
) -> Result<String, String>
where
    F: FnMut(&str) -> bool,
{
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let poll_interval = std::time::Duration::from_millis(10);

    loop {
        let response = client
            .request(Method::GET, &metrics_url)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch metrics: {}", e))?;

        let metrics = response
            .text()
            .await
            .map_err(|e| format!("Failed to read metrics response: {}", e))?;

        if condition(&metrics) {
            return Ok(metrics);
        }

        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for metric condition after {}ms. Last metrics:\n{}",
                timeout_ms, metrics
            ));
        }

        tokio::time::sleep(poll_interval).await;
    }
}

#[tokio::test]
#[pubky_testnet::test]
async fn metrics_comprehensive() {
    use eventsource_stream::Eventsource;
    use futures::StreamExt;

    use pubky_testnet::pubky_homeserver::ConfigToml;
    use std::net::SocketAddr;

    use pubky_testnet::EphemeralTestnet;

    let mut config = ConfigToml::default_test_config();
    config.metrics.enabled = true;
    config.metrics.listen_socket = SocketAddr::from(([127, 0, 0, 1], 0));

    let testnet = EphemeralTestnet::builder()
        .config(config)
        .build()
        .await
        .unwrap();

    // Extract values we need before getting SDK to avoid borrow conflicts
    let (metrics_url, server_public_key, server_public_key_z32, icann_http_url) = {
        let server = testnet.homeserver_app();

        let metrics_server = server
            .metrics_server()
            .expect("metrics server should be enabled in tests");
        let metrics_socket = metrics_server.listen_socket();
        let metrics_url = format!("http://{}/metrics", metrics_socket);
        let public_key = server.public_key().clone();
        let public_key_z32 = public_key.z32();
        let icann_http_url = server.icann_http_url();

        (metrics_url, public_key, public_key_z32, icann_http_url)
    };

    let pubky = testnet.sdk().unwrap();

    // 1. Test basic endpoint accessibility and Prometheus format
    let response = pubky
        .client()
        .request(Method::GET, &metrics_url)
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Metrics endpoint should be accessible"
    );

    let body = response.text().await.unwrap();
    assert!(!body.is_empty(), "Metrics output should not be empty");
    assert!(
        body.contains("# HELP") || body.contains("# TYPE"),
        "Metrics should be in Prometheus format with HELP/TYPE comments"
    );

    // 2. Test metric recording with concurrent connections
    let keypair1 = Keypair::random();
    let keypair2 = Keypair::random();
    let signer1 = pubky.signer(keypair1);
    let signer2 = pubky.signer(keypair2);

    let session1 = signer1
        .signup_cookie(&server_public_key, None)
        .await
        .unwrap();
    let session2 = signer2
        .signup_cookie(&server_public_key, None)
        .await
        .unwrap();

    let user_pubky1 = signer1.public_key();
    let user_pubky2 = signer2.public_key();

    // Create events to generate metrics
    session1
        .storage()
        .put("/pub/test1.txt", vec![1])
        .await
        .unwrap();
    session2
        .storage()
        .put("/pub/test2.txt", vec![2])
        .await
        .unwrap();

    // Exercise grant authentication on the canonical path-addressed route.
    let grant_session = signer1
        .signin(ClientId::new("metrics.test").unwrap())
        .await
        .unwrap();
    let bearer = grant_session.as_grant().unwrap().current_bearer().await;
    let grant_storage_path = "/pub/grant-metrics-secret.txt";
    let response = pubky
        .client()
        .request(
            Method::PUT,
            &format!(
                "{icann_http_url}storage/{}{}",
                user_pubky1.z32(),
                grant_storage_path
            ),
        )
        .header("Authorization", format!("Bearer {bearer}"))
        .body(vec![3])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // 3. Test concurrent stream connections to generate metrics
    let stream_url1 = format!(
        "https://{}/events-stream?user={}&live=true",
        server_public_key_z32,
        user_pubky1.z32()
    );
    let stream_url2 = format!(
        "https://{}/events-stream?user={}&live=true",
        server_public_key_z32,
        user_pubky2.z32()
    );

    let response1 = pubky
        .client()
        .request(Method::GET, &stream_url1)
        .send()
        .await
        .unwrap();
    let response2 = pubky
        .client()
        .request(Method::GET, &stream_url2)
        .send()
        .await
        .unwrap();

    let mut stream1 = response1.bytes_stream().eventsource();
    let mut stream2 = response2.bytes_stream().eventsource();

    // Read initial events from both streams
    stream1.next().await;
    stream2.next().await;

    // Poll metrics endpoint until 2 active connections are reported
    let metrics = wait_for_metric_condition(
        pubky.client(),
        &metrics_url,
        |m| m.contains("event_stream_active_connections") && m.contains("} 2"),
        2000, // 2 second timeout
    )
    .await
    .expect("Should have 2 active connections");

    assert!(
        metrics.contains("event_stream_active_connections") && metrics.contains("} 2"),
        "Should have 2 active connections: {}",
        metrics
    );

    // Verify expected metrics are present now that we've recorded data
    let expected_metrics = [
        "event_stream_db_query_duration_ms",
        "event_stream_active_connections",
    ];

    for metric in expected_metrics {
        assert!(
            metrics.contains(metric),
            "Metrics should contain {}: {}",
            metric,
            metrics
        );
    }

    // Verify stream DB query metrics recorded
    assert!(
        metrics.contains("event_stream_db_query_duration_ms_count"),
        "Should have event_stream_db_query_duration_ms_count metric"
    );

    // Close one stream
    drop(stream1);

    // Poll metrics endpoint until 1 active connection is reported
    let metrics = wait_for_metric_condition(
        pubky.client(),
        &metrics_url,
        |m| m.contains("event_stream_active_connections") && m.contains("} 1"),
        2000, // 2 second timeout
    )
    .await
    .expect("Should have 1 active connection after closing one");

    assert!(
        metrics.contains("event_stream_active_connections") && metrics.contains("} 1"),
        "Should have 1 active connection after closing one: {}",
        metrics
    );

    // Close second stream
    drop(stream2);

    // Poll metrics endpoint until 0 active connections are reported
    let final_metrics = wait_for_metric_condition(
        pubky.client(),
        &metrics_url,
        |m| m.contains("event_stream_active_connections") && m.contains("} 0"),
        2000, // 2 second timeout
    )
    .await
    .expect("Should have 0 active connections after closing all");

    assert!(
        final_metrics.contains("event_stream_active_connections") && final_metrics.contains("} 0"),
        "Should have 0 active connections after closing all: {}",
        final_metrics
    );

    assert!(
        final_metrics.contains("event_stream_connection_duration_ms_count"),
        "Should have event_stream_connection_duration_ms_count metric"
    );

    // Verify all core metrics are present after full test run
    // Note: broadcast_lagged_count is only present if lag actually occurred
    let all_expected_metrics = [
        "event_stream_db_query_duration_ms",
        "event_stream_active_connections",
        "event_stream_connection_duration_ms",
        "signup_count",
    ];

    for metric in all_expected_metrics {
        assert!(
            final_metrics.contains(metric),
            "Final metrics should contain {}: {}",
            metric,
            final_metrics
        );
    }

    // Verify signup_count reflects exactly 2 signups (keypair1 and keypair2)
    assert!(
        final_metrics.contains("signup_count_total{otel_scope_name=\"pubky_homeserver\"} 2"),
        "Should have exactly 2 signups recorded, metrics:\n{}",
        final_metrics
    );

    let grant_sample = final_metrics
        .lines()
        .find(|line| {
            line.starts_with("storage_request_count_total{")
                && line.contains("addressing_mode=\"path\"")
                && line.contains("auth_method=\"grant\"")
        })
        .expect("canonical grant storage request should be recorded");
    assert!(
        grant_sample.ends_with(" 1"),
        "unexpected sample: {grant_sample}"
    );
    assert!(!final_metrics.contains(&bearer));
    assert!(!final_metrics.contains(&user_pubky1.z32()));
    assert!(!final_metrics.contains(grant_storage_path));
}
