use super::*;
use tokio::time::{timeout, Duration};

#[tokio::test]
#[pubky_testnet::test]
async fn events_stream_validation_errors() {
    use eventsource_stream::Eventsource;
    use futures::StreamExt;

    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let server_host = server.public_key().z32();
    let pubky = testnet.sdk().unwrap();

    let keypair1 = Keypair::random();
    let keypair2 = Keypair::random();

    // Sign up user1, leave user2 not registered
    let signer1 = pubky.signer(keypair1);
    let session1 = signer1
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    let pubky1 = signer1.public_key();
    let pubky2 = keypair2.public_key(); // Not registered
    let invalid_pubkey = "invalid_key_not_zbase32";

    // Test 1: No user parameter
    let stream_url = format!("https://{}/events-stream", server_host);
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "No user parameter"
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("user parameter is required"));

    // Test 2: Too many users (>50)
    let mut query_params = vec![];
    for _i in 0..51 {
        let keypair = Keypair::random();
        query_params.push(format!("user={}", keypair.public_key().z32()));
    }
    let stream_url = format!(
        "https://{}/events-stream?{}",
        server_host,
        query_params.join("&")
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Too many users");
    let body = response.text().await.unwrap();
    assert!(body.contains("Too many users") || body.contains("Maximum allowed: 50"));

    // Test 3: Invalid public key format
    let stream_url = format!(
        "https://{}/events-stream?user={}",
        server_host, invalid_pubkey
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Invalid key format"
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("Invalid public key"));

    // Test 4: Valid key but user not registered
    let stream_url = format!(
        "https://{}/events-stream?user={}",
        server_host,
        pubky2.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "User not registered"
    );

    // Test 5: Mix of valid registered and unregistered user
    let stream_url = format!(
        "https://{}/events-stream?user={}&user={}",
        server_host,
        pubky1.z32(),
        pubky2.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "Mixed valid/unregistered"
    );

    // Test 6: Mix of valid user and invalid key format
    let stream_url = format!(
        "https://{}/events-stream?user={}&user={}",
        server_host,
        pubky1.z32(),
        invalid_pubkey
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Mixed valid/invalid"
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("Invalid public key"));

    // Test 7: Multiple invalid keys
    let stream_url = format!(
        "https://{}/events-stream?user={}&user={}",
        server_host, invalid_pubkey, "another_invalid_key"
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Multiple invalid keys"
    );

    // Test 8: Incompatible live=true with reverse=true
    let stream_url = format!(
        "https://{}/events-stream?user={}&live=true&reverse=true",
        server_host,
        pubky1.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "live+reverse incompatible"
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("Cannot use live mode with reverse ordering"));

    // Test 9: Invalid cursor formats
    // Create an event first to get a valid cursor for comparison
    session1
        .storage()
        .put("/pub/test.txt", vec![1])
        .await
        .unwrap();

    // Test 9a: Malformed cursor (non-numeric)
    let stream_url = format!(
        "https://{}/events-stream?user={}:abc123xyz",
        server_host,
        pubky1.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Malformed cursor should fail"
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("Invalid cursor"));

    // Test 9b: Negative cursor (invalid - cursor is u64, cannot be negative)
    let stream_url = format!(
        "https://{}/events-stream?user={}:-100&limit=10",
        server_host,
        pubky1.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Negative cursor should be rejected (cursor is u64)"
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("Invalid cursor"));

    // Test 9c: Very large cursor beyond any events (should succeed but return no events)
    let stream_url = format!(
        "https://{}/events-stream?user={}:999999999&limit=10",
        server_host,
        pubky1.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Large cursor should succeed"
    );
    let mut stream = response.bytes_stream().eventsource();
    // Should immediately close with no events
    assert!(
        stream.next().await.is_none(),
        "Large cursor beyond events should return no events"
    );

    // Test 10: Path parameter normalization
    // Test 10a: Path without leading slash - should automatically add "/" prefix
    let stream_url = format!(
        "https://{}/events-stream?user={}&path=pub/test.txt&limit=1",
        server_host,
        pubky1.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    // Path without leading slash should be normalized to "/pub/test.txt" and return events
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.bytes_stream().eventsource();
    // Should get at least 1 event (the test.txt we created earlier)
    assert!(
        stream.next().await.is_some(),
        "Path without leading slash should be automatically normalized with / prefix"
    );

    // Test 10b: Empty path parameter (should be treated as no filter)
    let stream_url = format!(
        "https://{}/events-stream?user={}&path=&limit=1",
        server_host,
        pubky1.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.bytes_stream().eventsource();
    // Should get at least 1 event (the test.txt we created)
    assert!(
        stream.next().await.is_some(),
        "Empty path should be treated as no filter"
    );
}

/// All three event APIs paginate by numeric event ID and reject anything else
/// with 400, including legacy z-base-32 timestamp cursors.
#[tokio::test]
#[pubky_testnet::test]
async fn event_apis_validate_numeric_cursors() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let signer = pubky.signer(Keypair::random());
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    for path in ["/pub/cursor-first.txt", "/pub/cursor-second.txt"] {
        session.storage().put(path, vec![1]).await.unwrap();
    }

    let host = server.public_key().z32();
    let user = signer.public_key().z32();
    let admin_socket = server.admin_server().unwrap().listen_socket();
    let admin_password = pubky_testnet::pubky_homeserver::ConfigToml::default_test_config()
        .admin
        .admin_password;
    let client = pubky.client();
    let event_uris = [
        format!("pubky://{user}/pub/cursor-first.txt"),
        format!("pubky://{user}/pub/cursor-second.txt"),
    ];

    for (cursor, expected_status, expected_events) in [
        ("0", StatusCode::OK, &event_uris[..]),
        ("1", StatusCode::OK, &event_uris[1..]),
        ("999999999", StatusCode::OK, &[]),
        ("1111111111111", StatusCode::OK, &[]),
        ("yyyyyyyyyyyyy", StatusCode::BAD_REQUEST, &[]),
        ("abc123xyz", StatusCode::BAD_REQUEST, &[]),
        ("-1", StatusCode::BAD_REQUEST, &[]),
        ("18446744073709551616", StatusCode::BAD_REQUEST, &[]),
    ] {
        let requests = [
            (
                "text feed",
                client.request(
                    Method::GET,
                    &format!("https://{host}/events/?cursor={cursor}"),
                ),
            ),
            (
                "client stream",
                client.request(
                    Method::GET,
                    &format!("https://{host}/events-stream?user={user}:{cursor}"),
                ),
            ),
            (
                "admin stream",
                client
                    .request(
                        Method::GET,
                        &format!("http://{admin_socket}/events-stream?cursor={cursor}"),
                    )
                    .header("X-Admin-Password", &admin_password),
            ),
        ];

        for (endpoint, request) in requests {
            let (status, body) = timeout(Duration::from_secs(10), async {
                let response = request.send().await.unwrap();
                let status = response.status();
                (status, response.text().await.unwrap())
            })
            .await
            .unwrap_or_else(|_| panic!("{endpoint} timed out for cursor {cursor}"));

            assert_eq!(
                status, expected_status,
                "{endpoint}, cursor {cursor}: {body}"
            );
            if expected_status == StatusCode::BAD_REQUEST {
                assert!(body.contains("Invalid cursor"), "{endpoint}: {body}");
                continue;
            }

            // Both text and SSE feeds expose each event URI as a separate word.
            let actual_events: Vec<_> = body
                .split_whitespace()
                .filter(|word| word.starts_with("pubky://"))
                .collect();
            assert_eq!(
                actual_events, expected_events,
                "{endpoint}, cursor {cursor}: {body}"
            );
        }
    }
}
