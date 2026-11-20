use super::*;

#[tokio::test]
#[pubky_testnet::test]
async fn events_stream_multiple_users() {
    use eventsource_stream::Eventsource;
    use futures::StreamExt;

    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let server_host = server.public_key().z32();
    let pubky = testnet.sdk().unwrap();

    let keypair1 = Keypair::random();
    let keypair2 = Keypair::random();
    let keypair3 = Keypair::random();

    // Create three users
    let signer1 = pubky.signer(keypair1);
    let signer2 = pubky.signer(keypair2);
    let signer3 = pubky.signer(keypair3);

    let session1 = signer1
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let session2 = signer2
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let session3 = signer3
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    let pubky1 = signer1.public_key();
    let pubky2 = signer2.public_key();
    let pubky3 = signer3.public_key();

    // Create different events for each user
    for i in 0..3 {
        let path = format!("/pub/test1_{i}.txt");
        session1.storage().put(path, vec![i as u8]).await.unwrap();
    }
    for i in 0..2 {
        let path = format!("/pub/test2_{i}.txt");
        session2.storage().put(path, vec![i as u8]).await.unwrap();
    }
    for i in 0..4 {
        let path = format!("/pub/test3_{i}.txt");
        session3.storage().put(path, vec![i as u8]).await.unwrap();
    }

    // Stream events for user1 and user2 (should get 5 events total)
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

    let status = response.status();
    if status != StatusCode::OK {
        let body = response.text().await.unwrap();
        panic!("Expected 200 OK, got {}: {}", status, body);
    }

    let mut stream = response.bytes_stream().eventsource();
    let mut events = Vec::new();

    while events.len() < 5 {
        if let Some(Ok(event)) = stream.next().await {
            if event.event == "PUT" {
                let lines: Vec<&str> = event.data.lines().collect();
                let path = lines[0].strip_prefix("pubky://").unwrap();
                events.push(path.to_string());
            }
        } else {
            break;
        }
    }

    // Verify we got events from both users
    assert_eq!(events.len(), 5, "Should receive 5 events total");
    let user1_events = events.iter().filter(|e| e.contains(&pubky1.z32())).count();
    let user2_events = events.iter().filter(|e| e.contains(&pubky2.z32())).count();

    assert_eq!(user1_events, 3, "Should receive 3 events from user1");
    assert_eq!(user2_events, 2, "Should receive 2 events from user2");

    // Verify no events from user3
    let user3_events = events.iter().filter(|e| e.contains(&pubky3.z32())).count();
    assert_eq!(user3_events, 0, "Should not receive events from user3");

    // Now test that returned cursor values are correct with per-user cursors
    // Get the first 2 events and track cursor per user
    let stream_url_for_cursor = format!(
        "https://{}/events-stream?user={}&user={}&limit=2",
        server_host,
        pubky1.z32(),
        pubky2.z32()
    );

    let response = pubky
        .client()
        .request(Method::GET, &stream_url_for_cursor)
        .send()
        .await
        .unwrap();

    let mut stream = response.bytes_stream().eventsource();
    let mut user1_cursor = String::new();
    let mut user2_cursor = String::new();
    let mut first_two_events = Vec::new();

    while first_two_events.len() < 2 {
        if let Some(Ok(event)) = stream.next().await {
            if event.event == "PUT" {
                let lines: Vec<&str> = event.data.lines().collect();
                let path = lines[0].strip_prefix("pubky://").unwrap();
                first_two_events.push(path.to_string());

                // Associate the cursor with the user the event belongs to
                let cursor = sse_cursor(&event.data).to_string();
                if lines[0].contains(&pubky1.z32()) {
                    user1_cursor = cursor;
                } else if lines[0].contains(&pubky2.z32()) {
                    user2_cursor = cursor;
                }
            }
        } else {
            break;
        }
    }

    drop(stream);

    assert_eq!(first_two_events.len(), 2, "Should get first 2 events");

    // Now request the remaining events using per-user cursors
    // This should properly handle the case where each user has a different cursor position
    // Build the URL conditionally based on whether we have cursors
    let mut url_parts = vec![format!("https://{}/events-stream?", server_host)];

    if !user1_cursor.is_empty() {
        url_parts.push(format!("user={}:{}", pubky1.z32(), user1_cursor));
    } else {
        url_parts.push(format!("user={}", pubky1.z32()));
    }

    if !user2_cursor.is_empty() {
        url_parts.push(format!("&user={}:{}", pubky2.z32(), user2_cursor));
    } else {
        url_parts.push(format!("&user={}", pubky2.z32()));
    }

    let stream_url_with_cursor = url_parts.join("");

    let response = pubky
        .client()
        .request(Method::GET, &stream_url_with_cursor)
        .send()
        .await
        .unwrap();

    let mut stream = response.bytes_stream().eventsource();
    let mut remaining_events = Vec::new();

    while remaining_events.len() < 3 {
        if let Some(Ok(event)) = stream.next().await {
            if event.event == "PUT" {
                let lines: Vec<&str> = event.data.lines().collect();
                let path = lines[0].strip_prefix("pubky://").unwrap();
                remaining_events.push(path.to_string());
            }
        } else {
            break;
        }
    }

    // We should get exactly 3 remaining events (1 from user1, 2 from user2)
    assert_eq!(
        remaining_events.len(),
        3,
        "Should receive all remaining events after cursor. Got: {:?}",
        remaining_events
    );

    let user1_remaining = remaining_events
        .iter()
        .filter(|e| e.contains(&pubky1.z32()))
        .count();
    let user2_remaining = remaining_events
        .iter()
        .filter(|e| e.contains(&pubky2.z32()))
        .count();

    // With per-user cursors, each user's position is tracked independently:
    // - First 2 events were: test1_0, test1_1 (both from user1)
    // - User1 cursor is at test1_1, so we should get: test1_2 (1 event)
    // - User2 cursor is empty (none of user2's events were in first batch), so we get: test2_0, test2_1 (2 events)
    // Total remaining: 3 events
    assert_eq!(
        user1_remaining, 1,
        "Should get 1 remaining event from user1 (test1_2). Got events: {:?}",
        remaining_events
    );
    assert_eq!(
        user2_remaining, 2,
        "Should get 2 remaining events from user2 (test2_0, test2_1). Got events: {:?}",
        remaining_events
    );
}
