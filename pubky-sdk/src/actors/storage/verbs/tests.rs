use super::*;
use crate::{
    Capabilities, CookieCredential, Error, errors::RequestError, util::test_server::TestServer,
};
use pubky_common::session::CookieSessionRecord;
use std::{sync::Arc, time::Duration};

fn storage(server: &TestServer) -> SessionStorage {
    let caps = Capabilities::builder().read_write("/").unwrap().finish();
    SessionStorage {
        client: server.client.clone(),
        user: server.user.clone(),
        credential: Arc::new(CookieCredential::new(
            server.user.clone(),
            Some("test-secret".into()),
            CookieSessionRecord::new(&server.user, caps, None),
            Some(server.homeserver.clone()),
        )),
    }
}

#[tokio::test]
async fn raw_get_returns_headers_without_consuming_success_or_error_bodies() {
    for status in [200, 404, 410, 429, 500] {
        let server = TestServer::start(
            format!("HTTP/1.1 {status} Test\r\nContent-Length: 1000000000\r\nX-Test: raw\r\n\r\n")
                .into_bytes(),
        );
        let storage = storage(&server);
        let response =
            tokio::time::timeout(Duration::from_secs(2), storage.get_raw("/priv/test/file"))
                .await
                .expect("raw GET must return before body/EOF")
                .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["x-test"], "raw");
        drop(response);
        let request = server.finish().await;
        assert!(request.starts_with(&format!(
            "GET /storage/{}/priv/test/file ",
            storage.user.z32()
        )));
        assert!(request.to_ascii_lowercase().contains("cookie:"));
        assert!(request.contains("test-secret"));
    }
}

#[tokio::test]
async fn raw_get_retains_path_and_transport_errors() {
    let server = TestServer::start(Vec::new());
    let storage = storage(&server);
    assert!(matches!(
        storage.get_raw("/pub/../invalid").await,
        Err(Error::Parse(_) | Error::Request(RequestError::Validation { .. }))
    ));
    // Close the advertised endpoint; the next request must be a transport error.
    assert!(server.finish().await.is_empty());
    assert!(matches!(
        storage.get_raw("/pub/test/file").await,
        Err(Error::Request(RequestError::Transport(_)))
    ));
}
