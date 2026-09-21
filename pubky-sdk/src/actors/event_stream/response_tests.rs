use super::*;
use crate::{Keypair, ResourcePath, util::tests::serve_response};
use pubky_common::storage_path::MAX_STORAGE_PATH_TOTAL_LENGTH;
use std::time::Duration;
use tokio::{io::AsyncReadExt, net::TcpStream};

async fn response(body: &str) -> (reqwest::Response, TcpStream) {
    serve_response(
        200,
        "Content-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n",
        format!("{:x}\r\n{body}\r\n", body.len()).as_bytes(),
    )
    .await
}

#[tokio::test]
async fn response_overflow_releases_connection_and_preserves_prior_event() {
    let user = Keypair::random().public_key();
    let setting = 8192;
    let valid = format!(
        "event: DEL\ndata: pubky://{}/pub/file\ndata: cursor: 42\n\n",
        user.z32()
    );
    // An unterminated oversized path must fail without waiting for EOF.
    let body = format!(
        "event: FUTURE\ndata: ignored\n\n{valid}event: PUT\ndata: pubky://{}/pub/{}",
        user.z32(),
        "x".repeat(setting + 1)
    );
    let (response, mut socket) = response(&body).await;
    let mut events = Box::pin(EventStreamBuilder::response_event_stream(response, setting));
    let event = tokio::time::timeout(Duration::from_secs(2), events.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(event.cursor.id(), 42);
    let error = tokio::time::timeout(Duration::from_secs(2), events.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&format!("limit of {setting} bytes"))
    );
    // Retain `events`: the decoder itself must close the response on error.
    let closed = tokio::time::timeout(Duration::from_secs(2), socket.read_u8())
        .await
        .unwrap();
    assert!(closed.is_err(), "response socket must close");
    assert!(events.next().await.is_none());
}

#[tokio::test]
async fn zero_event_limit_fails_before_resolution() {
    let client = PubkyHttpClient::builder()
        .isolated_pkarr_test()
        .build()
        .unwrap();
    let key = Keypair::random().public_key();
    for builder in [
        EventStreamBuilder::for_user(client.clone(), &key, None),
        EventStreamBuilder::for_homeserver(client, &key)
            .add_users([(&key, None)])
            .unwrap(),
    ] {
        assert_eq!(builder.max_event_bytes, usize::MAX);
        assert_eq!(builder.clone().max_event_bytes(123).max_event_bytes, 123);
        let Err(error) = builder.max_event_bytes(0).subscribe().await else {
            panic!("zero limit accepted")
        };
        assert!(
            error
                .to_string()
                .contains("max_event_bytes must be greater than zero")
        );
    }
}

#[tokio::test]
async fn configured_limit_accepts_maximum_path_cursor_and_hash() {
    let user = Keypair::random().public_key();
    let path = format!(
        "/pub/{}{}",
        format!("{}/", "é".repeat(120)).repeat(3),
        "é".repeat(122)
    );
    StoragePath::new(&path).unwrap();
    assert_eq!(path.len(), MAX_STORAGE_PATH_TOTAL_LENGTH);
    let hash = base64::engine::general_purpose::STANDARD.encode([255; 32]);
    let body = format!(
        "event: PUT\ndata: pubky://{}{path}\ndata: cursor: {}\ndata: content_hash: {hash}\n\n",
        user.z32(),
        u64::MAX
    );
    let (response, _socket) = response(&body).await;
    let mut events = Box::pin(EventStreamBuilder::response_event_stream(response, 4096));
    let event = tokio::time::timeout(Duration::from_secs(2), events.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(event.cursor.id(), u64::MAX);
    assert_eq!(event.resource.path, ResourcePath::parse(&path).unwrap());
    assert_eq!(
        event.event_type.content_hash(),
        Some(&Hash::from_bytes([255; 32]))
    );
}

#[tokio::test]
async fn unbounded_default_accepts_legacy_and_large_events() {
    let user = Keypair::random().public_key();
    let hash = base64::engine::general_purpose::STANDARD.encode([255; 32]);
    // Legacy homeservers allowed 4096-byte paths, whose SSE frames exceed 4 KiB.
    for path_bytes in [4096, 16384] {
        let path = format!(
            "/pub/{}{}",
            format!("{}/", "a".repeat(255)).repeat((path_bytes - 5) / 256),
            "b".repeat((path_bytes - 5) % 256)
        );
        assert_eq!(path.len(), path_bytes);
        let body = format!(
            "event: PUT\ndata: pubky://{}{path}\ndata: cursor: {}\ndata: content_hash: {hash}\n\n",
            user.z32(),
            u64::MAX
        );
        let (response, _socket) = response(&body).await;
        let mut events = Box::pin(EventStreamBuilder::response_event_stream(
            response,
            usize::MAX,
        ));
        let event = tokio::time::timeout(Duration::from_secs(2), events.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(event.cursor.id(), u64::MAX);
        assert_eq!(event.resource.path, ResourcePath::parse(&path).unwrap());
        assert_eq!(
            event.event_type.content_hash(),
            Some(&Hash::from_bytes([255; 32]))
        );
    }
}
