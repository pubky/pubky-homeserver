use super::*;
use pubky_testnet::pubky::EventCursor;
use tokio::time::{timeout, Duration};

/// Every user's public events through the SDK: `all_users()` replays both users' history in
/// batch mode, then resumes after the last cursor in live mode and delivers a new write.
#[tokio::test]
#[pubky_testnet::test]
async fn events_stream_all_users_via_sdk() {
    use futures::StreamExt;

    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let mut sessions = Vec::new();
    for name in ["alice", "bob"] {
        let signer = pubky.signer(Keypair::random());
        let session = signer
            .signup_cookie(&server.public_key(), None)
            .await
            .unwrap();
        session
            .storage()
            .put(format!("/pub/{name}.txt"), vec![1])
            .await
            .unwrap();
        sessions.push(session);
    }

    // Batch mode: both users' events, then the stream closes.
    let mut stream = pubky
        .event_stream_for(&server.public_key())
        .all_users(None)
        .subscribe()
        .await
        .unwrap();
    let mut paths = Vec::new();
    let mut last_cursor = EventCursor::new(0);
    while let Some(event) = stream.next().await {
        let event = event.unwrap();
        paths.push(event.resource.path.to_string());
        last_cursor = event.cursor;
    }
    assert_eq!(paths, ["/pub/alice.txt", "/pub/bob.txt"]);

    // Live mode resumes after the last cursor and delivers the next write.
    let mut live = pubky
        .event_stream_for(&server.public_key())
        .all_users(Some(last_cursor))
        .live()
        .subscribe()
        .await
        .unwrap();
    sessions[1]
        .storage()
        .put("/pub/bob-live.txt", vec![2])
        .await
        .unwrap();
    let event = timeout(Duration::from_secs(10), live.next())
        .await
        .expect("live event within timeout")
        .expect("stream open")
        .unwrap();
    assert_eq!(event.resource.path.to_string(), "/pub/bob-live.txt");
}

/// An all-users batch request without `limit` closes after 100 events, like the legacy
/// `/events/` feed; the next request resumes from the last cursor seen.
#[tokio::test]
#[pubky_testnet::test]
async fn events_stream_all_users_batch_defaults_to_100_events() {
    use eventsource_stream::Eventsource;
    use futures::StreamExt;

    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let server_host = server.public_key().z32();
    let pubky = testnet.sdk().unwrap();
    let session = pubky
        .signer(Keypair::random())
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    for i in 0..101 {
        session
            .storage()
            .put(format!("/pub/file_{i}.txt"), vec![1])
            .await
            .unwrap();
    }

    let response = pubky
        .client()
        .request(Method::GET, &format!("https://{server_host}/events-stream"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.bytes_stream().eventsource();
    let mut cursors = Vec::new();
    while let Ok(Some(Ok(event))) = timeout(Duration::from_secs(10), stream.next()).await {
        cursors.push(sse_cursor(&event.data).to_string());
    }
    assert_eq!(cursors.len(), 100, "default limit for an all-users batch");

    let response = pubky
        .client()
        .request(
            Method::GET,
            &format!(
                "https://{server_host}/events-stream?cursor={}",
                cursors.last().unwrap()
            ),
        )
        .send()
        .await
        .unwrap();
    let mut stream = response.bytes_stream().eventsource();
    let mut remaining = 0;
    while let Ok(Some(Ok(_))) = timeout(Duration::from_secs(10), stream.next()).await {
        remaining += 1;
    }
    assert_eq!(
        remaining, 1,
        "the request after the default page gets the rest"
    );
}

/// Without a user there is no tenant to authorize against, so an all-users stream is
/// public-only: private writes never appear in batch or live mode, and asking for a
/// private path is rejected.
#[tokio::test]
#[pubky_testnet::test]
async fn events_stream_all_users_never_shows_private_writes() {
    use eventsource_stream::Eventsource;
    use futures::StreamExt;

    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let server_host = server.public_key().z32();
    let pubky = testnet.sdk().unwrap();
    let session = pubky
        .signer(Keypair::random())
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    session
        .storage()
        .put("/pub/note.txt", vec![1])
        .await
        .unwrap();
    session
        .storage()
        .put("/priv/app/secret.txt", vec![2])
        .await
        .unwrap();

    // Batch mode: only the public write.
    let response = pubky
        .client()
        .request(Method::GET, &format!("https://{server_host}/events-stream"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.bytes_stream().eventsource();
    let mut seen = Vec::new();
    while let Ok(Some(Ok(event))) = timeout(Duration::from_secs(10), stream.next()).await {
        seen.push(event.data);
    }
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].contains("/pub/note.txt"), "{seen:?}");

    // Live mode, resumed after the batch event: a private write is skipped and
    // the public one after it arrives.
    let cursor = sse_cursor(&seen[0]);
    let response = pubky
        .client()
        .request(
            Method::GET,
            &format!("https://{server_host}/events-stream?live=true&cursor={cursor}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut live = response.bytes_stream().eventsource();
    session
        .storage()
        .put("/priv/app/later.txt", vec![3])
        .await
        .unwrap();
    session
        .storage()
        .put("/pub/later.txt", vec![4])
        .await
        .unwrap();
    let event = timeout(Duration::from_secs(10), live.next())
        .await
        .expect("live event within timeout")
        .expect("stream open")
        .expect("valid SSE event");
    assert!(event.data.contains("/pub/later.txt"), "{}", event.data);
    drop(live);

    // A private path filter needs exactly one user and a session.
    let response = pubky
        .client()
        .request(
            Method::GET,
            &format!("https://{server_host}/events-stream?path=/priv/"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
