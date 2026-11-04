use super::*;

/// Comprehensive test for directory filtering (`path` parameter):
/// - Basic filtering, cursor pagination, multiple users, reverse ordering, wildcard escaping
#[tokio::test]
#[pubky_testnet::test]
async fn events_stream_path_filter() {
    use eventsource_stream::Eventsource;
    use futures::StreamExt;

    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let server_host = server.public_key().z32();

    // Create 2 users upfront with diverse directory structures
    let keypair1 = Keypair::random();
    let keypair2 = Keypair::random();
    let signer1 = pubky.signer(keypair1);
    let signer2 = pubky.signer(keypair2);
    let session1 = signer1
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let session2 = signer2
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let pubky1 = signer1.public_key();
    let pubky2 = signer2.public_key();

    // User 1: Create events in different directories (used for basic filtering & reverse tests)
    for i in 0..5 {
        let path = format!("/pub/files/doc_{i}.txt");
        session1.storage().put(path, vec![i as u8]).await.unwrap();
    }
    for i in 0..3 {
        let path = format!("/pub/photos/pic_{i}.jpg");
        session1.storage().put(path, vec![i as u8]).await.unwrap();
    }
    for i in 0..2 {
        let path = format!("/pub/root_{i}.txt");
        session1.storage().put(path, vec![i as u8]).await.unwrap();
    }
    // Add DELETE events
    session1
        .storage()
        .delete("/pub/files/doc_0.txt")
        .await
        .unwrap();

    // User 2: Create events for cursor pagination and multi-user tests
    for i in 0..10 {
        let path = format!("/pub/files/item_{i}.txt");
        session2.storage().put(path, vec![i as u8]).await.unwrap();
    }
    for i in 0..5 {
        let path = format!("/pub/photos/pic_{i}.jpg");
        session2.storage().put(path, vec![i as u8]).await.unwrap();
    }
    for i in 0..3 {
        let path = format!("/pub/data/test_{i}.txt");
        session2.storage().put(path, vec![i as u8]).await.unwrap();
    }

    // ==== Test 1: Basic filtering (both specific and broad paths) ====
    let stream_url = format!(
        "https://{}/events-stream?user={}&path=/pub/files/",
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
    let mut put_count = 0;
    let mut del_count = 0;
    while let Some(Ok(event)) = stream.next().await {
        let path = event.data.lines().next().unwrap();
        assert!(
            path.contains("/pub/files/"),
            "Filter: Expected /pub/files/, got: {}",
            path
        );
        if event.event == "PUT" {
            put_count += 1;
        } else if event.event == "DEL" {
            del_count += 1;
        }
        if put_count + del_count >= 6 {
            break;
        }
    }
    assert_eq!(
        put_count + del_count,
        6,
        "Filter: Should get 6 events from /pub/files/"
    );
    assert_eq!(put_count, 5, "Filter: Should have 5 PUT events");
    assert_eq!(del_count, 1, "Filter: Should have 1 DEL event");

    // ==== Test 2: Filter with cursor pagination ====

    // Get first 5 with cursor
    let stream_url = format!(
        "https://{}/events-stream?user={}&path=/pub/files/&limit=5",
        server_host,
        pubky2.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    let mut stream = response.bytes_stream().eventsource();
    let mut first_batch = Vec::new();
    let mut cursor = String::new();

    while first_batch.len() < 5 {
        if let Some(Ok(event)) = stream.next().await {
            if event.event == "PUT" {
                let lines: Vec<&str> = event.data.lines().collect();
                assert!(
                    lines[0].contains("/pub/files/"),
                    "Cursor: Expected filtered path"
                );
                first_batch.push(lines[0].to_string());
                cursor = sse_cursor(&event.data).to_string();
            }
        } else {
            break;
        }
    }
    drop(stream);
    assert_eq!(first_batch.len(), 5, "Cursor: Should get first 5 events");

    // Get remaining 5 with cursor
    let stream_url = format!(
        "https://{}/events-stream?user={}:{}&path=/pub/files/",
        server_host,
        pubky2.z32(),
        cursor
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    let mut stream = response.bytes_stream().eventsource();
    let mut second_batch = Vec::new();

    while second_batch.len() < 5 {
        if let Some(Ok(event)) = stream.next().await {
            if event.event == "PUT" {
                let path = event.data.lines().next().unwrap();
                assert!(
                    !first_batch.contains(&path.to_string()),
                    "Cursor: Duplicate event"
                );
                second_batch.push(path.to_string());
            }
        } else {
            break;
        }
    }
    assert_eq!(
        second_batch.len(),
        5,
        "Cursor: Should get remaining 5 events"
    );

    // ==== Test 3: Filter with multiple users ====
    // Filter both users by files directory - user1 has 6 events (5 PUT + 1 DEL), user2 has 10
    let stream_url = format!(
        "https://{}/events-stream?user={}&user={}&path=/pub/files/",
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
    let mut stream = response.bytes_stream().eventsource();
    let mut multi_events = Vec::new();

    while multi_events.len() < 16 {
        if let Some(Ok(event)) = stream.next().await {
            let path = event.data.lines().next().unwrap();
            assert!(
                path.contains("/pub/files/"),
                "Multi-user: Expected filtered path"
            );
            multi_events.push(path.to_string());
        } else {
            break;
        }
    }

    assert_eq!(
        multi_events.len(),
        16,
        "Multi-user: Should get 16 filtered events (user1: 6, user2: 10)"
    );
    let user1_count = multi_events
        .iter()
        .filter(|e| e.contains(&pubky1.z32()))
        .count();
    let user2_count = multi_events
        .iter()
        .filter(|e| e.contains(&pubky2.z32()))
        .count();
    assert_eq!(user1_count, 6, "Multi-user: Should get 6 from user1");
    assert_eq!(user2_count, 10, "Multi-user: Should get 10 from user2");

    // ==== Test 4: Filter with reverse ordering ====
    // Use user1's /pub/files/ which has 5 PUT + 1 DEL = 6 events
    let stream_url = format!(
        "https://{}/events-stream?user={}&path=/pub/files/&reverse=true&limit=6",
        server_host,
        pubky1.z32()
    );
    let response = pubky
        .client()
        .request(Method::GET, &stream_url)
        .send()
        .await
        .unwrap();
    let mut stream = response.bytes_stream().eventsource();
    let mut reverse = Vec::new();
    while reverse.len() < 6 {
        if let Some(Ok(event)) = stream.next().await {
            if let Some(fname) = event
                .data
                .lines()
                .next()
                .and_then(|p| p.split("/pub/files/").nth(1))
            {
                reverse.push(format!("{}:{}", event.event, fname));
            }
        } else {
            break;
        }
    }

    assert_eq!(reverse.len(), 6, "Reverse: Should have 6 events");
    assert_eq!(
        reverse[0], "DEL:doc_0.txt",
        "Reverse: First should be DEL doc_0 (newest)"
    );
    assert_eq!(
        reverse[5], "PUT:doc_0.txt",
        "Reverse: Last should be PUT doc_0 (oldest)"
    );

    // ==== Test 5: Filter with special LIKE characters (_, %) - verify escaping ====
    session1
        .storage()
        .put("/pub/my_folder/file.txt", vec![1])
        .await
        .unwrap();
    session1
        .storage()
        .put("/pub/myfolder/file.txt", vec![2])
        .await
        .unwrap();

    let stream_url = format!(
        "https://{}/events-stream?user={}&path=/pub/my_folder/",
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
    let mut wildcard_count = 0;
    while let Some(Ok(event)) = stream.next().await {
        let path = event.data.lines().next().unwrap();
        assert!(
            path.contains("/pub/my_folder/"),
            "Wildcard: Expected /pub/my_folder/, got: {}",
            path
        );
        wildcard_count += 1;
        if wildcard_count >= 2 {
            break;
        }
    }
    assert_eq!(
        wildcard_count, 1,
        "Wildcard: Should get exactly 1 event (underscore not treated as wildcard)"
    );
}
