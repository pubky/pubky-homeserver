use super::*;
use crate::{
    Keypair, ResourcePath,
    errors::RequestErrorKind,
    util::tests::{ServedConnection, serve_response},
};
use pubky_common::storage_path::MAX_STORAGE_PATH_TOTAL_LENGTH;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn response(body: &str) -> (reqwest::Response, ServedConnection) {
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
    let (response, connection) = response(&body).await;
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
    assert!(matches!(
        error,
        Error::Request(RequestError::Oversized { limit, .. }) if limit == setting
    ));
    // Retain `events`: the decoder itself must close the response on error.
    let mut socket = connection.into_socket().await;
    let closed = tokio::time::timeout(Duration::from_secs(2), socket.read_u8())
        .await
        .unwrap();
    assert!(closed.is_err(), "response socket must close");
    assert!(events.next().await.is_none());
}

#[tokio::test]
async fn dropped_connection_reports_a_transport_error() {
    // Declare a longer chunk than is sent, then close the connection mid-body.
    let (response, connection) = serve_response(
        200,
        "Content-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n",
        b"100\r\ndata: partial",
    )
    .await;
    drop(connection);
    let mut events = Box::pin(EventStreamBuilder::response_event_stream(response, 8192));
    let error = tokio::time::timeout(Duration::from_secs(2), events.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    let Error::Request(error @ RequestError::Transport(_)) = error else {
        panic!("unexpected error: {error:?}");
    };
    // reqwest files a truncated chunked body under decoding, not `Body`.
    assert_eq!(error.kind(), RequestErrorKind::Decode);
    assert!(events.next().await.is_none());
}

#[tokio::test]
async fn stalled_stream_reports_a_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    // Answer with headers only and keep the socket open past the deadline.
    let serve = async {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                  Transfer-Encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
        socket
    };
    let (response, _socket) = tokio::join!(client.get(url).send(), serve);
    let mut events = Box::pin(EventStreamBuilder::response_event_stream(
        response.unwrap(),
        8192,
    ));
    let error = tokio::time::timeout(Duration::from_secs(5), events.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    let Error::Request(error @ RequestError::Transport(_)) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
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
    let (response, _connection) = response(&body).await;
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
        let (response, _connection) = response(&body).await;
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
