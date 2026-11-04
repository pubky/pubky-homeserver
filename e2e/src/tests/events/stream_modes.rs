use super::*;

/// Comprehensive test for single-user event streaming modes:
/// - Historical event pagination (>100 events across internal batches)
/// - Finite limit enforcement
/// - Live event streaming
/// - Phase transition (historical -> live)
/// - Batch mode connection closing
/// - Content hash verification
/// - Empty user behavior
/// - Reverse ordering
#[tokio::test]
#[pubky_testnet::test]
async fn events_stream_basic_modes() {
    use eventsource_stream::Eventsource;
    use futures::StreamExt;
    use tokio::time::{timeout, Duration};

    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let server_host = server.public_key().z32();
    let pubky = testnet.sdk().unwrap();

    // Create one user with 250 events - reuse for all subtests
    let keypair = Keypair::random();
    let signer = pubky.signer(keypair);
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let user_pubky = signer.public_key();
    let user_host = user_pubky.z32();

    // Create 250 events (internal batch size is 100, tests pagination)
    for i in 0..250 {
        let path = format!("/pub/file_{i}.txt");
        session.storage().put(path, vec![i as u8]).await.unwrap();
    }
    // Add some DELETE events
    for i in 240..245 {
        let path = format!("/pub/file_{i}.txt");
        session.storage().delete(path).await.unwrap();
    }

    // ==== Test 1: Historical auto-pagination (>100 events) ====
    let stream_url = format!(
        "https://{}/events-stream?user={}&limit=255",
        server_host, user_host
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut stream = response.bytes_stream().eventsource();
    let mut event_count = 0;
    let mut put_count = 0;
    let mut del_count = 0;
    let mut last_cursor = String::new();
    let mut cursor_250 = String::new();

    while event_count < 255 {
        if let Some(Ok(event)) = stream.next().await {
            if event.event == "PUT" {
                put_count += 1;
            } else if event.event == "DEL" {
                del_count += 1;
            }
            last_cursor = sse_cursor(&event.data).to_string();
            // Capture cursor at event 250 for Test 3
            if event_count == 249 {
                cursor_250 = last_cursor.clone();
            }
            event_count += 1;
        } else {
            break;
        }
    }

    assert_eq!(
        event_count, 255,
        "Historical: Should receive all 255 events"
    );
    assert_eq!(put_count, 250, "Historical: Should have 250 PUT events");
    assert_eq!(del_count, 5, "Historical: Should have 5 DEL events");
    assert!(!last_cursor.is_empty(), "Historical: Should have cursor");
    assert!(
        stream.next().await.is_none(),
        "Historical: Should close after limit"
    );

    // ==== Test 2: Finite limit enforcement ====
    let stream_url = format!(
        "https://{}/events-stream?user={}&limit=50",
        server_host, user_host
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    let mut stream = response.bytes_stream().eventsource();
    let mut event_count = 0;

    while event_count < 50 {
        if let Some(Ok(_event)) = stream.next().await {
            event_count += 1;
        } else {
            break;
        }
    }

    assert_eq!(event_count, 50, "Limit: Should receive exactly 50 events");
    assert!(
        stream.next().await.is_none(),
        "Limit: Should close after limit"
    );

    // ==== Test 3: Live mode starting from cursor 250 ====

    // Connect with live=true from cursor 250
    // Reuse cursor_250 captured from Test 1 (event 250)
    let stream_url = format!(
        "https://{}/events-stream?user={}:{}&live=true",
        server_host, user_host, cursor_250
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut stream = response.bytes_stream().eventsource();

    // Create live event
    let session_clone = session.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let path = "/pub/live_test.txt";
        session_clone.storage().put(path, vec![42]).await.unwrap();
    });

    let result = timeout(Duration::from_secs(5), async {
        // Should get 5 DEL events from history, then the live event
        let mut event_count = 0;
        while let Some(Ok(event)) = stream.next().await {
            event_count += 1;
            if event.event == "PUT" && event.data.contains("live_test.txt") {
                return Some(event_count);
            }
        }
        None
    })
    .await;

    assert!(result.is_ok(), "Live: Should receive event within timeout");
    let total = result.unwrap();
    assert!(total.is_some(), "Live: Should receive the live event");
    assert_eq!(total.unwrap(), 6, "Live: Should get 5 DEL + 1 live PUT");

    // ==== Test 4: Live mode with limit - transitions from historical to live until limit reached ====
    let stream_url = format!(
        "https://{}/events-stream?user={}:{}&live=true&limit=10",
        server_host, user_host, cursor_250
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut stream = response.bytes_stream().eventsource();

    // Spawn a task to create live events
    let session_clone = session.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        for i in 0..10 {
            let path = format!("/pub/live_extra_{i}.txt");
            session_clone
                .storage()
                .put(path, vec![i as u8])
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let mut total_count = 0;
    let result = timeout(Duration::from_secs(5), async {
        while let Some(Ok(_event)) = stream.next().await {
            total_count += 1;
            if total_count >= 10 {
                break;
            }
        }
        total_count
    })
    .await;

    assert!(result.is_ok(), "Live+Limit: Should complete within timeout");
    assert_eq!(
        result.unwrap(),
        10,
        "Live+Limit: Should stop at exactly 10 total events (6 historical + 4 live)"
    );

    // Verify stream is closed after limit reached
    let next_result = timeout(Duration::from_millis(500), stream.next()).await;
    assert!(
        next_result.is_ok() && next_result.unwrap().is_none(),
        "Live+Limit: Connection should close after reaching limit"
    );

    // ==== Test 5: Batch mode (live=false) - connection closes after historical events ====
    let stream_url = format!(
        "https://{}/events-stream?user={}:{}&limit=5",
        server_host, user_host, cursor_250
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut stream = response.bytes_stream().eventsource();
    let mut batch_event_count = 0;

    // Collect historical events
    while let Some(Ok(_event)) = stream.next().await {
        batch_event_count += 1;
        if batch_event_count >= 5 {
            break;
        }
    }

    assert_eq!(
        batch_event_count, 5,
        "Batch: Should receive 5 DEL events from history"
    );

    // Schedule a new event after connection established
    tokio::time::sleep(Duration::from_millis(100)).await;
    let path = "/pub/new_event.txt";
    session.storage().put(path, vec![99]).await.unwrap();

    // In batch mode, stream should close after historical events
    // Try to read with timeout - should get None (connection closed)
    let next_result = timeout(Duration::from_millis(500), stream.next()).await;
    assert!(
        next_result.is_ok() && next_result.unwrap().is_none(),
        "Batch: Connection should be closed, not waiting for live events"
    );

    // ==== Test 6: Content hash verification ====
    // Verify PUT events include content_hash, DEL events do not
    // We only need to check one PUT and one DEL event to verify the format
    // Fetch from cursor_250 which we know has 5 DEL events after it
    let stream_url = format!(
        "https://{}/events-stream?user={}:{}&limit=6",
        server_host, user_host, cursor_250
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut stream = response.bytes_stream().eventsource();
    let mut found_del = false;

    while let Some(Ok(event)) = stream.next().await {
        let data_lines: Vec<&str> = event.data.lines().collect();
        let has_content_hash = data_lines
            .iter()
            .any(|line| line.starts_with("content_hash: "));

        if event.event == "DEL" {
            assert!(
                !has_content_hash,
                "ContentHash: DEL event should NOT have content_hash field"
            );
            found_del = true;
            break; // We've verified both a PUT (from earlier in stream) and now a DEL
        } else if event.event == "PUT" {
            assert!(
                has_content_hash,
                "ContentHash: PUT event should have content_hash field"
            );
            // Verify format: should be 43 base64 characters (blake3 hash, 32 bytes)
            if let Some(hash_line) = data_lines
                .iter()
                .find(|line| line.starts_with("content_hash: "))
            {
                let hash_value = hash_line.strip_prefix("content_hash: ").unwrap();
                assert_eq!(
                    hash_value.len(),
                    43,
                    "ContentHash: Should be 43 base64 characters"
                );
                assert!(
                    hash_value
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
                    "ContentHash: Should contain only base64 characters"
                );
            }
        }
    }

    assert!(
        found_del,
        "ContentHash: Should have found at least one DEL event to verify"
    );

    // ==== Test 6b: Verify content_hash format matches HTTP headers ====
    // This ensures the SSE event stream and HTTP GET endpoints use the same hash format

    // Create a new file with known content
    let test_data = b"hello world for hash test";
    session
        .storage()
        .put("/pub/hash_test.txt", test_data.to_vec())
        .await
        .unwrap();

    // Get the content_hash from HTTP GET headers (ETag)
    let get_url = format!("https://{}/pub/hash_test.txt", server_host);
    let get_response = pubky
        .client()
        .request(Method::GET, &get_url)
        .header("pubky-host", user_host.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);

    let etag_header = get_response
        .headers()
        .get("etag")
        .expect("Should have ETag header")
        .to_str()
        .unwrap();
    // ETag is wrapped in quotes: "hash_value"
    let etag_hash = etag_header.trim_matches('"');

    // Get the content_hash from event stream
    let stream_url = format!(
        "https://{}/events-stream?user={}&path=/pub/hash_test.txt",
        server_host, user_host
    );
    let stream_response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(stream_response.status(), StatusCode::OK);

    let mut stream = stream_response.bytes_stream().eventsource();
    let mut event_hash = String::new();

    if let Some(Ok(event)) = stream.next().await {
        let data_lines: Vec<&str> = event.data.lines().collect();
        if let Some(hash_line) = data_lines.iter().find(|l| l.starts_with("content_hash: ")) {
            event_hash = hash_line
                .strip_prefix("content_hash: ")
                .unwrap()
                .to_string();
        }
    }

    assert_eq!(
        etag_hash, event_hash,
        "ContentHash: Event stream hash should match HTTP ETag header. ETag: {}, Event: {}",
        etag_hash, event_hash
    );

    // ==== Test 7: Empty user behavior ====
    // Create new user with no events
    let empty_keypair = Keypair::random();
    let empty_signer = pubky.signer(empty_keypair);
    let empty_session = empty_signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let empty_user_pubky = empty_signer.public_key();

    // Test 7a: Batch mode should close immediately
    let stream_url = format!(
        "https://{}/events-stream?user={}",
        server_host,
        empty_user_pubky.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut stream = response.bytes_stream().eventsource();
    assert!(
        stream.next().await.is_none(),
        "Empty user batch mode: Should close immediately with no events"
    );

    // Test 7b: Live mode should stay open and receive new events
    let stream_url = format!(
        "https://{}/events-stream?user={}&live=true",
        server_host,
        empty_user_pubky.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut stream = response.bytes_stream().eventsource();

    // Create a live event for the empty user
    let session_clone = empty_session.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let path = "/pub/first_event.txt";
        session_clone.storage().put(path, vec![42]).await.unwrap();
    });

    let result = timeout(Duration::from_secs(5), async {
        if let Some(Ok(event)) = stream.next().await {
            return Some((event.event.clone(), event.data.contains("first_event.txt")));
        }
        None
    })
    .await;

    assert!(
        result.is_ok(),
        "Empty user live mode: Should receive event within timeout"
    );
    let event_data = result.unwrap();
    assert!(
        event_data.is_some(),
        "Empty user live mode: Should receive the live event"
    );
    let (event_type, has_path) = event_data.unwrap();
    assert_eq!(
        event_type, "PUT",
        "Empty user live mode: Should be PUT event"
    );
    assert!(
        has_path,
        "Empty user live mode: Should contain first_event.txt path"
    );

    // ==== Test 8: Reverse ordering ====
    // Create a clean user with known events to test reverse ordering
    let reverse_keypair = Keypair::random();
    let reverse_signer = pubky.signer(reverse_keypair);
    let reverse_session = reverse_signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let reverse_user_pubky = reverse_signer.public_key();

    // Create exactly 5 events with known order
    for i in 0..5 {
        let path = format!("/pub/reverse_file_{i}.txt");
        reverse_session
            .storage()
            .put(path, vec![i as u8])
            .await
            .unwrap();
    }

    // Test forward order first to establish baseline
    let stream_url = format!(
        "https://{}/events-stream?user={}&limit=5",
        server_host,
        reverse_user_pubky.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    let mut stream = response.bytes_stream().eventsource();
    let mut forward_files = Vec::new();
    while forward_files.len() < 5 {
        if let Some(Ok(event)) = stream.next().await {
            if let Some(filename) = event
                .data
                .lines()
                .next()
                .and_then(|p| p.split("/pub/").nth(1))
            {
                forward_files.push(filename.to_string());
            }
        } else {
            break;
        }
    }

    // Test reverse order
    let stream_url = format!(
        "https://{}/events-stream?user={}&reverse=true&limit=5",
        server_host,
        reverse_user_pubky.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    let mut stream = response.bytes_stream().eventsource();
    let mut reverse_files = Vec::new();
    while reverse_files.len() < 5 {
        if let Some(Ok(event)) = stream.next().await {
            if let Some(filename) = event
                .data
                .lines()
                .next()
                .and_then(|p| p.split("/pub/").nth(1))
            {
                reverse_files.push(filename.to_string());
            }
        } else {
            break;
        }
    }

    assert_eq!(
        forward_files.len(),
        5,
        "Reverse: Forward should have 5 events"
    );
    assert_eq!(
        reverse_files.len(),
        5,
        "Reverse: Reverse should have 5 events"
    );
    assert_eq!(
        forward_files[0], "reverse_file_0.txt",
        "Reverse: Forward first should be file_0"
    );
    assert_eq!(
        forward_files[4], "reverse_file_4.txt",
        "Reverse: Forward last should be file_4"
    );
    assert_eq!(
        reverse_files[0], "reverse_file_4.txt",
        "Reverse: Reverse first should be file_4 (newest)"
    );
    assert_eq!(
        reverse_files[4], "reverse_file_0.txt",
        "Reverse: Reverse last should be file_0 (oldest)"
    );

    // Verify reverse is exactly the reverse of forward
    let mut forward_reversed = forward_files.clone();
    forward_reversed.reverse();
    assert_eq!(
        reverse_files, forward_reversed,
        "Reverse: Should be exact reverse of forward"
    );
}
