use super::*;
use base64::Engine;

fn assert_server_status(error: Error, expected: StatusCode) {
    assert!(
        matches!(error, Error::Request(RequestError::Server { status, .. }) if status == expected),
        "expected server status {expected}, got {error:?}"
    );
}

fn admin_basic_auth(password: &str) -> String {
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("admin:{password}"));
    format!("Basic {auth}")
}

#[tokio::test]
#[pubky_testnet::test]
async fn put_get_delete() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer = pubky.signer(Keypair::random());

    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let public_key = session.public_key();
    let cookie_secret = session.as_cookie().unwrap().export_secret().unwrap();
    let (cookie_name, cookie_value) = cookie_secret.split_once(':').unwrap();
    let cookie = format!("{cookie_name}={cookie_value}");
    let storage_url = format!(
        "{}storage/{}/pub/foo.txt",
        server.icann_http_url(),
        public_key.z32()
    );
    let directory_url = format!(
        "{}storage/{}/pub/directory/",
        server.icann_http_url(),
        public_key.z32()
    );
    let unrelated_user = Keypair::random().public_key();

    // PUT and DELETE only operate on file-shaped `/storage` paths.
    let response = session
        .client()
        .request(Method::PUT, &directory_url)
        .header("Cookie", &cookie)
        .body(vec![0])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = session
        .client()
        .request(Method::DELETE, &directory_url)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = session
        .client()
        .request(
            Method::PUT,
            &format!("{storage_url}?pubky-host={}", unrelated_user.z32()),
        )
        .header("pubky-host", unrelated_user.z32())
        .header("Cookie", &cookie)
        .body(vec![0, 1, 2, 3, 4])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = session
        .client()
        .request(Method::GET, &storage_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/plain"
    );
    assert_eq!(
        response.bytes().await.unwrap(),
        bytes::Bytes::from(vec![0, 1, 2, 3, 4])
    );

    let response = session
        .client()
        .request(Method::HEAD, &storage_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-length").unwrap(), "5");
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/plain"
    );
    assert!(response.headers().contains_key("etag"));

    let response = session
        .client()
        .request(Method::DELETE, &storage_url)
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = session
        .client()
        .request(Method::GET, &storage_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // `/storage` writes and deletes emit the same public events as legacy routes.
    let response = pubky
        .client()
        .request(Method::GET, &format!("{}events/", server.icann_http_url()))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let events = response.text().await.unwrap();
    assert!(
        events.starts_with(&format!(
            "PUT pubky://{}/pub/foo.txt\nDEL pubky://{}/pub/foo.txt\n",
            public_key.z32(),
            public_key.z32()
        )),
        "unexpected event feed: {events}"
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn path_collisions_return_conflict_and_recover_after_delete() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer = pubky.signer(Keypair::random());
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    let exact = "/pub/app/foo";
    let descendant = "/pub/app/foo/bar.json";

    session.storage().put(exact, vec![1]).await.unwrap();

    let err = session
        .storage()
        .put(descendant, vec![2])
        .await
        .expect_err("descendant write should conflict with exact file");
    assert_server_status(err, StatusCode::CONFLICT);
    let err = session
        .storage()
        .get(descendant)
        .await
        .expect_err("rejected descendant should not be readable");
    assert_server_status(err, StatusCode::NOT_FOUND);

    session.storage().delete(exact).await.unwrap();
    session.storage().put(descendant, vec![3]).await.unwrap();

    let err = session
        .storage()
        .put(exact, vec![4])
        .await
        .expect_err("exact-file write should conflict with descendant");
    assert_server_status(err, StatusCode::CONFLICT);
    let err = session
        .storage()
        .get(exact)
        .await
        .expect_err("rejected exact file should not be readable");
    assert_server_status(err, StatusCode::NOT_FOUND);

    session.storage().delete(descendant).await.unwrap();
    session.storage().put(exact, vec![5]).await.unwrap();
}

#[tokio::test]
#[pubky_testnet::test]
async fn deleting_legacy_exact_file_does_not_delete_descendants() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer = pubky.signer(Keypair::random());
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let user = session.public_key().z32();

    let admin_password = pubky_testnet::pubky_homeserver::ConfigToml::default_test_config()
        .admin
        .admin_password;
    let admin_auth = admin_basic_auth(&admin_password);
    let admin_socket = server
        .admin_server()
        .expect("admin server should be enabled")
        .listen_socket();
    let admin_client = pubky_testnet::pubky::PubkyHttpClient::new().unwrap();

    let exact_url = format!("http://{admin_socket}/dav/{user}/pub/app/foo");
    let descendant_url = format!("http://{admin_socket}/dav/{user}/pub/app/foo/bar.json");
    let exact = "/pub/app/foo";
    let descendant = "/pub/app/foo/bar.json";

    let response = admin_client
        .request(Method::PUT, &exact_url)
        .header("Authorization", &admin_auth)
        .body(vec![1])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = admin_client
        .request(Method::PUT, &descendant_url)
        .header("Authorization", &admin_auth)
        .body(vec![2])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    session.storage().delete(exact).await.unwrap();

    let err = session
        .storage()
        .get(exact)
        .await
        .expect_err("deleted exact file should not be readable");
    assert_server_status(err, StatusCode::NOT_FOUND);

    let descendant_bytes = session
        .storage()
        .get(descendant)
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(descendant_bytes.as_ref(), &[2]);
}

use serde::{Deserialize, Serialize};

#[tokio::test]
#[pubky_testnet::test]
async fn put_then_get_json_roundtrip() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer = pubky.signer(Keypair::random());

    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let public_key = session.public_key();

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Payload {
        msg: String,
        n: u32,
        flag: bool,
    }

    let path = "/pub/data/roundtrip.json";
    let expected = Payload {
        msg: "hello".to_string(),
        n: 42,
        flag: true,
    };

    // Ignore the result; the write still succeeds and is asserted via the subsequent GET.
    let _ = session.storage().put_json(path, &expected).await;

    // Read back as strongly-typed JSON and assert equality.
    let got: Payload = pubky
        .public_storage()
        .get_json(format!("{public_key}/{path}"))
        .await
        .unwrap();
    assert_eq!(got, expected);

    // Sanity-check MIME is JSON when fetching raw.
    let resp = session.storage().get(path).await.unwrap();
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("application/json"));

    // Cleanup
    session
        .storage()
        .delete(path)
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
}
#[tokio::test]
#[pubky_testnet::test]
async fn dont_delete_shared_blobs() {
    let testnet = build_full_testnet().await;
    let homeserver = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    // Two independent users
    let u1 = pubky.signer(Keypair::random());
    let u2 = pubky.signer(Keypair::random());

    let a1 = u1
        .signup_cookie(&homeserver.public_key(), None)
        .await
        .unwrap();
    let a2 = u2
        .signup_cookie(&homeserver.public_key(), None)
        .await
        .unwrap();

    let user_1_id = u1.public_key();
    let user_2_id = u2.public_key();

    let p1 = "/pub/pubky.app/file/file_1";
    let p2 = "/pub/pubky.app/file/file_1";

    let file = vec![1];

    // Both write identical content to their own paths
    a1.storage().put(p1, file.clone()).await.unwrap();
    a2.storage().put(p2, file.clone()).await.unwrap();

    // Delete user 1's file
    a1.storage().delete(p1).await.unwrap();

    // User 2's file must still exist and match
    let blob = a2.storage().get(p2).await.unwrap().bytes().await.unwrap();
    assert_eq!(blob, file);

    // Event feed should show PUT u1, PUT u2, DEL u1 (order preserved)
    let feed_url = format!("https://{}/events/", homeserver.public_key().z32());
    let resp = pubky
        .client()
        .request(Method::GET, &feed_url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let text = resp.text().await.unwrap();
    let lines = text.split('\n').collect::<Vec<_>>();

    assert_eq!(
        lines,
        vec![
            format!("PUT pubky://{}/pub/pubky.app/file/file_1", user_1_id.z32()),
            format!("PUT pubky://{}/pub/pubky.app/file/file_1", user_2_id.z32()),
            format!("DEL pubky://{}/pub/pubky.app/file/file_1", user_1_id.z32()),
            lines.last().unwrap().to_string(),
        ]
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn stream() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer = pubky.signer(Keypair::random());
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    let path = "/pub/foo.txt";
    let bytes = Bytes::from(vec![0; 1024 * 1024]); // 1 MiB

    // Upload large body
    session.storage().put(path, bytes.clone()).await.unwrap();

    // Read back and compare
    let got = session
        .storage()
        .get(path)
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(got, bytes);

    // Delete and verify 404 on subsequent GET
    session.storage().delete(path).await.unwrap();
    let err = session.storage().get(path).await.unwrap_err();
    assert!(
        matches!(err, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::NOT_FOUND)
    );
}
/// Test that two users can write to the same path and the content is correctly separated.
/// Mix file and reading between the two users.
#[tokio::test]
#[pubky_testnet::test]
async fn write_same_path_separate_users() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let signer_a = pubky.signer(Keypair::random());
    let session_a = signer_a
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let signer_b = pubky.signer(Keypair::random());
    let session_b = signer_b
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    let path = "/pub/foo.txt";
    let content1 = Bytes::from(b"content1".to_vec());

    // Write to user A content1
    session_a
        .storage()
        .put(path, content1.clone())
        .await
        .unwrap();
    // Read back and compare
    let response = session_a.storage().get(path).await.unwrap();
    let content_length = response
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(content_length, content1.len() as u64);
    let read_bytes_a = response.bytes().await.unwrap();
    assert_eq!(read_bytes_a, content1);

    // Write to user B content1
    session_b
        .storage()
        .put(path, content1.clone())
        .await
        .unwrap();
    // Read back and compare
    let response = session_b.storage().get(path).await.unwrap();
    let content_length = response
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(content_length, content1.len() as u64);
    let read_bytes_b = response.bytes().await.unwrap();
    assert_eq!(read_bytes_b, content1);

    let content2 = Bytes::from(b"content2_long".to_vec());

    // Write to user A content2
    session_a
        .storage()
        .put(path, content2.clone())
        .await
        .unwrap();
    // Read back and compare
    let response = session_a.storage().get(path).await.unwrap();
    let content_length = response
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(content_length, content2.len() as u64);
    let read_bytes_a = response.bytes().await.unwrap();
    assert_eq!(read_bytes_a, content2);

    // Read user B content 1 again. Make sure it's the original content1.
    let response = session_b.storage().get(path).await.unwrap();
    let content_length = response
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(content_length, content1.len() as u64);
    let read_bytes_b = response.bytes().await.unwrap();
    assert_eq!(read_bytes_b, content1);

    // Delete user A content2
    session_a.storage().delete(path).await.unwrap();
    // Read user B content 2 again. Make sure it's the original content1.
    let response = session_b.storage().get(path).await.unwrap();
    let content_length = response
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(content_length, content1.len() as u64);
    let read_bytes_b = response.bytes().await.unwrap();
    assert_eq!(read_bytes_b, content1);
}
