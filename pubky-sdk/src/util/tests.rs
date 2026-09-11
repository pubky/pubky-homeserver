use crate::{Error, PubkyHttpClient, errors::RequestError};
use reqwest::{Response, StatusCode};
use std::{fmt::Write, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn client(limit: Option<usize>) -> PubkyHttpClient {
    let mut builder = PubkyHttpClient::builder();
    builder.isolated_pkarr_test();
    if let Some(limit) = limit {
        builder.max_error_body_bytes(limit);
    }
    builder.build().unwrap()
}

// Keep the server socket alive after returning headers/body. Tests decide when
// EOF happens, so a response reader cannot pass by waiting for the whole body.
async fn serve_response(status: u16, framing: &str, body: &[u8]) -> (Response, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let client = reqwest::Client::new();
    let send = client.get(url).send();
    let serve = async {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let byte = socket.read_u8().await.unwrap();
            request.push(byte);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
            assert!(request.len() < 16 * 1024);
        }
        socket
            .write_all(format!("HTTP/1.1 {status} Test\r\n{framing}\r\n").as_bytes())
            .await
            .unwrap();
        socket.write_all(body).await.unwrap();
        socket
    };
    let (response, socket) = tokio::join!(send, serve);
    (response.unwrap(), socket)
}

async fn server_error(response: Response, client: PubkyHttpClient) -> (StatusCode, String) {
    let error = tokio::time::timeout(Duration::from_secs(2), client.check_http_status(response))
        .await
        .expect("status handling must not wait for the rest of an oversized body")
        .unwrap_err();
    let Error::Request(RequestError::Server { status, message }) = error else {
        panic!("unexpected error: {error:?}");
    };
    (status, message)
}

#[tokio::test]
async fn oversized_error_stops_before_eof() {
    let body = format!("1001\r\n{}\r\n", "x".repeat(4097));
    let (response, _socket) =
        serve_response(500, "Transfer-Encoding: chunked\r\n", body.as_bytes()).await;
    let (status, message) = server_error(response, client(None)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        message,
        format!(
            "{}\n[response body truncated at 4096 bytes]",
            "x".repeat(4096)
        )
    );
}

#[tokio::test]
async fn error_body_limits_follow_client_configuration() {
    for setting in [None, Some(16), Some(8192)] {
        let client = client(setting);
        let limit = setting.unwrap_or(4096);
        for size in [0, 3, limit - 1, limit, limit + 1] {
            let body = vec![b'x'; size];
            let (response, _socket) =
                serve_response(429, &format!("Content-Length: {size}\r\n"), &body).await;
            let (status, message) = server_error(response, client.clone()).await;
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            let mut expected = "x".repeat(size.min(limit));
            if size > limit {
                write!(expected, "\n[response body truncated at {limit} bytes]").unwrap();
            }
            assert_eq!(message, expected, "limit {limit}, body size {size}");
        }
    }
}

#[tokio::test]
async fn clients_keep_independent_limits_when_cloned() {
    let small = client(Some(3));
    let larger = client(Some(5));
    for (client, limit) in [(small.clone(), 3), (larger, 5), (small, 3)] {
        let (response, _socket) =
            serve_response(500, "Content-Length: 10\r\n", b"xxxxxxxxxx").await;
        let (_, message) = server_error(response, client).await;
        assert_eq!(
            message,
            format!(
                "{}\n[response body truncated at {limit} bytes]",
                "x".repeat(limit)
            )
        );
    }
}

#[tokio::test]
async fn zero_limit_does_not_wait_for_error_bodies() {
    for (status, reason) in [
        (404, "Not Found"),
        (410, "Gone"),
        (500, "Internal Server Error"),
        (599, "Unknown Error"),
    ] {
        let (response, _socket) =
            serve_response(status, "Content-Length: 1000000000\r\n", b"").await;
        let (actual, message) = server_error(response, client(Some(0))).await;
        assert_eq!(actual.as_u16(), status);
        assert_eq!(message, reason);
    }
}

#[tokio::test]
async fn large_limit_does_not_require_a_large_allocation() {
    let (response, _socket) = serve_response(500, "Content-Length: 5\r\n", b"short").await;
    let (_, message) = server_error(response, client(Some(usize::MAX))).await;
    assert_eq!(message, "short");
}

#[tokio::test]
async fn error_limit_is_independent_of_framing_and_chunk_boundaries() {
    for framing in ["", "Content-Length: 1000000000000\r\n"] {
        let (response, _socket) = serve_response(503, framing, &vec![b'x'; 4097]).await;
        let (_, message) = server_error(response, client(None)).await;
        assert_eq!(
            message,
            format!(
                "{}\n[response body truncated at 4096 bytes]",
                "x".repeat(4096)
            )
        );
    }

    let (response, mut socket) = serve_response(500, "Transfer-Encoding: chunked\r\n", b"").await;
    let read = tokio::spawn(server_error(response, client(None)));
    for _ in 0..4096 {
        socket.write_all(b"1\r\nx\r\n").await.unwrap();
    }
    // Reaching the limit alone is not truncation; the next byte proves overflow.
    socket.write_all(b"1\r\ny\r\n").await.unwrap();
    let (_, message) = read.await.unwrap();
    assert_eq!(
        message,
        format!(
            "{}\n[response body truncated at 4096 bytes]",
            "x".repeat(4096)
        )
    );
}

#[tokio::test]
async fn checked_success_does_not_consume_the_body() {
    let (response, mut socket) = serve_response(200, "Content-Length: 5\r\n", b"").await;
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client(Some(0)).check_http_status(response),
    )
    .await
    .unwrap()
    .unwrap();
    socket.write_all(b"hello").await.unwrap();
    assert_eq!(response.text().await.unwrap(), "hello");
}

#[tokio::test]
async fn error_text_decoding_and_read_failure() {
    for body in [
        b"\xef\xbb\xbfhello".as_slice(),
        b"bad\xfftext",
        "caf\u{e9}".as_bytes(),
    ] {
        let (response, _socket) =
            serve_response(400, &format!("Content-Length: {}\r\n", body.len()), body).await;
        let (_, message) = server_error(response, client(None)).await;
        assert_eq!(message, String::from_utf8_lossy(body));
    }
    let mut body = vec![b'x'; 4095];
    body.extend_from_slice("\u{20ac}".as_bytes());
    let (response, _socket) =
        serve_response(400, &format!("Content-Length: {}\r\n", body.len()), &body).await;
    let (_, message) = server_error(response, client(None)).await;
    assert_eq!(
        message,
        format!(
            "{}\u{fffd}\n[response body truncated at 4096 bytes]",
            "x".repeat(4095)
        )
    );

    for (status, fallback) in [(500, "Internal Server Error"), (599, "Unknown Error")] {
        let (response, socket) =
            serve_response(status, "Content-Length: 100\r\n", b"partial").await;
        drop(socket);
        let (actual, message) = server_error(response, client(None)).await;
        assert_eq!(actual.as_u16(), status);
        assert_eq!(message, fallback);
    }
}

#[tokio::test]
async fn small_head_does_not_protect_against_oversized_get_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let peer = tokio::spawn(async move {
        for method in ["HEAD", "GET"] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
                assert!(request.len() < 16 * 1024);
            }
            assert!(request.starts_with(method.as_bytes()));
            if method == "HEAD" {
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            } else {
                socket.write_all(format!("HTTP/1.1 500 Error\r\nTransfer-Encoding: chunked\r\n\r\n1001\r\n{}\r\n", "x".repeat(4097)).as_bytes()).await.unwrap();
                return socket; // Withhold EOF until the checked GET has returned.
            }
        }
        unreachable!()
    });
    let http = reqwest::Client::new();
    let head = http.head(&url).send().await.unwrap();
    assert_eq!(head.headers()["content-length"], "16");
    let response = http.get(&url).send().await.unwrap();
    let _socket = peer.await.unwrap();
    let (status, message) = server_error(response, client(None)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        message,
        format!(
            "{}\n[response body truncated at 4096 bytes]",
            "x".repeat(4096)
        )
    );
}
