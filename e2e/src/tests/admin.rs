use pubky_testnet::pubky::{
    errors::RequestError, ClientId, Error, Keypair, Method, PubkyHttpClient, StatusCode,
};
use pubky_testnet::{
    pubky_homeserver::{ConfigToml, Domain},
    Testnet,
};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

#[derive(Deserialize)]
struct InfoResponse {
    public_key: String,
    pkarr_pubky_address: Option<String>,
    pkarr_icann_domain: Option<String>,
    version: String,
}

#[tokio::test]
#[pubky_testnet::test]
async fn admin_info_includes_metadata() {
    let mut config = ConfigToml::default_test_config();
    config.pkdns.public_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    config.pkdns.public_pubky_tls_port = Some(9443);
    config.pkdns.icann_domain = Some(Domain::from_str("example.test").unwrap());
    config.pkdns.public_icann_http_port = Some(8081);

    let expected_pubky_endpoint = format!(
        "{}:{}",
        config.pkdns.public_ip,
        config
            .pkdns
            .public_pubky_tls_port
            .expect("test should set pubky port"),
    );
    let expected_icann_endpoint = format!(
        "{}:{}",
        config
            .pkdns
            .icann_domain
            .as_ref()
            .expect("test should set icann domain"),
        config
            .pkdns
            .public_icann_http_port
            .expect("test should set icann port"),
    );
    let admin_password = config.admin.admin_password.clone();

    let mut testnet = Testnet::new().await.unwrap();
    let homeserver = testnet
        .create_homeserver_with(config, Keypair::random())
        .await
        .unwrap();

    let admin_socket = homeserver
        .admin_server()
        .expect("admin server should be enabled")
        .listen_socket();

    let response = PubkyHttpClient::new()
        .unwrap()
        .request(Method::GET, &format!("http://{admin_socket}/info"))
        .header("X-Admin-Password", admin_password)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body: InfoResponse = response.json().await.unwrap();
    assert_eq!(body.public_key, homeserver.public_key().z32());
    assert_eq!(body.pkarr_pubky_address, Some(expected_pubky_endpoint));
    assert_eq!(body.pkarr_icann_domain, Some(expected_icann_endpoint));
    assert_eq!(body.version, env!("CARGO_PKG_VERSION"));
}

/// Test that per-user quota set via admin API is enforced.
/// User A gets a 1 MB custom quota via admin API; user B has no custom quota (unlimited).
/// User A is blocked when exceeding 1 MB; user B can write freely.
#[tokio::test]
#[pubky_testnet::test]
async fn per_user_quota_via_admin_api() {
    let config = ConfigToml::default_test_config();
    let admin_password = config.admin.admin_password.clone();

    let mut testnet = Testnet::new().await.unwrap();
    let pubky = testnet.sdk().unwrap();
    let server = testnet
        .create_homeserver_with(config, Keypair::random())
        .await
        .unwrap();

    let admin_socket = server
        .admin_server()
        .expect("admin server should be enabled")
        .listen_socket();

    // Create two users
    let signer_a = pubky.signer(Keypair::random());
    let session_a = signer_a
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let pubkey_a = signer_a.public_key().z32();

    let signer_b = pubky.signer(Keypair::random());
    let session_b = signer_b
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    // Set a 1 MB quota on user A via admin API
    let admin_client = PubkyHttpClient::new().unwrap();
    let resp = admin_client
        .request(
            Method::PATCH,
            &format!("http://{admin_socket}/users/{pubkey_a}/quota"),
        )
        .header("X-Admin-Password", &admin_password)
        .header("content-type", "application/json")
        .body(r#"{"storage_quota_mb": 1, "rate_read": null, "rate_write": null}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // User A: 600 KB write → OK
    let data_600k: Vec<u8> = vec![0; 600_000];
    let resp = session_a
        .storage()
        .put("/pub/data", data_600k.clone())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // User A: another 600 KB at a different path (total 1.2 MB) → 507
    let err = session_a
        .storage()
        .put("/pub/data2", data_600k.clone())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Request(RequestError::Server { status, .. })
            if status == StatusCode::INSUFFICIENT_STORAGE
    ));

    // User B: has no custom quota (unlimited) — same 600 KB writes should both succeed
    let resp = session_b
        .storage()
        .put("/pub/data", data_600k.clone())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = session_b
        .storage()
        .put("/pub/data2", data_600k)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// Test that per-user write speed override set via admin API throttles uploads.
///
/// User A is overridden to 1kb/s write speed; user B keeps the server default.
/// A 3 KB upload at 1kb/s should take >2s, while user B uploads quickly.
#[tokio::test]
#[pubky_testnet::test]
async fn per_user_speed_override_throttles_via_admin_api() {
    use std::time::{Duration, Instant};

    let mut config = ConfigToml::default_test_config();
    // Server-level default write speed — user A will be overridden below.
    config.default_quotas.rate_write = Some("1mb/s".parse().unwrap());
    let admin_password = config.admin.admin_password.clone();

    let mut testnet = Testnet::new().await.unwrap();
    let pubky = testnet.sdk().unwrap();
    let server = testnet
        .create_homeserver_with(config, Keypair::random())
        .await
        .unwrap();

    let admin_socket = server
        .admin_server()
        .expect("admin server should be enabled")
        .listen_socket();

    // Create two users
    let signer_a = pubky.signer(Keypair::random());
    let session_a = signer_a
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let pubkey_a_z32 = signer_a.public_key().z32();

    let signer_b = pubky.signer(Keypair::random());
    let session_b = signer_b
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    // Override user A to 1kb/s write speed via admin API
    let admin_client = PubkyHttpClient::new().unwrap();
    let resp = admin_client
        .request(
            Method::PATCH,
            &format!("http://{admin_socket}/users/{pubkey_a_z32}/quota"),
        )
        .header("X-Admin-Password", &admin_password)
        .header("content-type", "application/json")
        .body(r#"{"storage_quota_mb": null, "rate_read": null, "rate_write": "1kb/s"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = vec![0u8; 3 * 1024]; // 3 KB

    // User A (1kb/s override): 3 KB upload should take >2s due to throttling
    let start = Instant::now();
    let resp = session_a
        .storage()
        .put("/pub/rate_test", body.clone())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let elapsed_a = start.elapsed();
    assert!(
        elapsed_a > Duration::from_secs(2),
        "User A upload should be throttled to ~1kb/s (elapsed {:?})",
        elapsed_a
    );

    // User B (no override, uses default 1mb/s): same upload should be fast (<2s)
    let start = Instant::now();
    let resp = session_b
        .storage()
        .put("/pub/rate_test", body)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let elapsed_b = start.elapsed();
    assert!(
        elapsed_b < Duration::from_secs(2),
        "User B upload should use default speed, not be throttled (elapsed {:?})",
        elapsed_b
    );
}

/// Test that per-user read speed override set via admin API throttles downloads.
///
/// User A is overridden to 1kb/s read speed; user B keeps the server default.
/// A 3 KB download at 1kb/s should take >2s, while user B downloads quickly.
#[tokio::test]
#[pubky_testnet::test]
async fn per_user_read_speed_override_throttles_via_admin_api() {
    use std::time::{Duration, Instant};

    let mut config = ConfigToml::default_test_config();
    // Server-level defaults — user A's read rate will be overridden below.
    config.default_quotas.rate_read = Some("1mb/s".parse().unwrap());
    config.default_quotas.rate_write = Some("1mb/s".parse().unwrap());
    let admin_password = config.admin.admin_password.clone();

    let mut testnet = Testnet::new().await.unwrap();
    let pubky = testnet.sdk().unwrap();
    let server = testnet
        .create_homeserver_with(config, Keypair::random())
        .await
        .unwrap();

    let admin_socket = server
        .admin_server()
        .expect("admin server should be enabled")
        .listen_socket();

    // Create two users
    let signer_a = pubky.signer(Keypair::random());
    let session_a = signer_a
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let pubkey_a_z32 = signer_a.public_key().z32();

    let signer_b = pubky.signer(Keypair::random());
    let session_b = signer_b
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    // Both users upload a 3 KB file (fast, using default 1mb/s)
    let body = vec![0u8; 3 * 1024];
    session_a
        .storage()
        .put("/pub/read_test.txt", body.clone())
        .await
        .unwrap();
    session_b
        .storage()
        .put("/pub/read_test.txt", body)
        .await
        .unwrap();

    // Override user A to 1kb/s read speed via admin API
    let admin_client = PubkyHttpClient::new().unwrap();
    let resp = admin_client
        .request(
            Method::PATCH,
            &format!("http://{admin_socket}/users/{pubkey_a_z32}/quota"),
        )
        .header("X-Admin-Password", &admin_password)
        .header("content-type", "application/json")
        .body(r#"{"rate_read": "1kb/s"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // User A (1kb/s read override): 3 KB download should take >2s
    let start = Instant::now();
    let resp = session_a.storage().get("/pub/read_test.txt").await.unwrap();
    let _ = resp.bytes().await.unwrap(); // consume body to apply throttle
    let elapsed_a = start.elapsed();
    assert!(
        elapsed_a > Duration::from_secs(2),
        "User A download should be throttled to ~1kb/s (elapsed {:?})",
        elapsed_a
    );

    // User B (no override, uses default 1mb/s): same download should be fast (<2s)
    let start = Instant::now();
    let resp = session_b.storage().get("/pub/read_test.txt").await.unwrap();
    let _ = resp.bytes().await.unwrap();
    let elapsed_b = start.elapsed();
    assert!(
        elapsed_b < Duration::from_secs(2),
        "User B download should use default speed, not be throttled (elapsed {:?})",
        elapsed_b
    );
}

/// Test that per-user `allowed_write_paths` set via admin API is enforced at the HTTP level.
///
/// User A is restricted to `/pub/tokens/` only; writes to allowed path succeed (201),
/// writes to disallowed paths are rejected (403), and reads remain unaffected.
#[tokio::test]
#[pubky_testnet::test]
async fn allowed_write_paths_enforced_via_http() {
    let config = ConfigToml::default_test_config();
    let admin_password = config.admin.admin_password.clone();

    let mut testnet = Testnet::new().await.unwrap();
    let pubky = testnet.sdk().unwrap();
    let server = testnet
        .create_homeserver_with(config, Keypair::random())
        .await
        .unwrap();

    let admin_socket = server
        .admin_server()
        .expect("admin server should be enabled")
        .listen_socket();

    // Create user
    let signer = pubky.signer(Keypair::random());
    signer.signup(&server.public_key(), None).await.unwrap();
    let session = signer
        .signin(ClientId::new("admin.allowed_write_paths").unwrap())
        .await
        .unwrap();
    let pubkey_z32 = signer.public_key().z32();

    // Write a file to a path that will later be disallowed (before restriction is applied)
    let resp = session
        .storage()
        .put("/pub/other/bar.json", vec![4, 5, 6])
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Restrict user to /pub/tokens/ only via admin API
    let admin_client = PubkyHttpClient::new().unwrap();
    let resp = admin_client
        .request(
            Method::PATCH,
            &format!("http://{admin_socket}/users/{pubkey_z32}/quota"),
        )
        .header("X-Admin-Password", &admin_password)
        .header("content-type", "application/json")
        .body(r#"{"allowed_write_paths": ["/pub/tokens/"]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Write to allowed path → 201
    let resp = session
        .storage()
        .put("/pub/tokens/foo.json", vec![1, 2, 3])
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Write to disallowed path → 403
    let err = session
        .storage()
        .put("/pub/other/bar.json", vec![4, 5, 6])
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Request(RequestError::Server { status, .. })
                if status == StatusCode::FORBIDDEN
        ),
        "Expected 403 FORBIDDEN but got: {err:?}"
    );

    // Read from allowed path still works
    let resp = session.storage().get("/pub/tokens/foo.json").await.unwrap();
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &[1, 2, 3]);

    // Delete from allowed path → succeeds
    let resp = session
        .storage()
        .delete("/pub/tokens/foo.json")
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Delete from disallowed path → 403
    // (file was written before restriction was applied)
    let err = session
        .storage()
        .delete("/pub/other/bar.json")
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Request(RequestError::Server { status, .. })
                if status == StatusCode::FORBIDDEN
        ),
        "Expected 403 FORBIDDEN on delete but got: {err:?}"
    );
}

/// End-to-end over raw HTTP/SSE: real `/pub/` and `/priv/` writes surface in the admin
/// `/events-stream` (batch + live), a wrong password is rejected, and the public client-server
/// feed stays public-only and never leaks the private path.
#[tokio::test]
#[pubky_testnet::test]
async fn admin_event_stream_exposes_private_events() {
    use eventsource_stream::Eventsource;
    use futures::StreamExt;
    use tokio::time::{timeout, Duration};

    let config = ConfigToml::default_test_config();
    let admin_password = config.admin.admin_password.clone();

    let mut testnet = Testnet::new().await.unwrap();
    let pubky = testnet.sdk().unwrap();
    let server = testnet
        .create_homeserver_with(config, Keypair::random())
        .await
        .unwrap();

    let admin_socket = server
        .admin_server()
        .expect("admin server should be enabled")
        .listen_socket();
    let stream_url = format!("http://{admin_socket}/events-stream");

    // Create a user/session and write one public and one private file.
    let signer = pubky.signer(Keypair::random());
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    session
        .storage()
        .put("/pub/note.txt", vec![1, 2, 3])
        .await
        .unwrap();
    session
        .storage()
        .put("/priv/app/secret.txt", vec![4, 5, 6])
        .await
        .unwrap();

    let admin_client = PubkyHttpClient::new().unwrap();

    // Batch mode: the SSE stream replays every event (public + private) then closes.
    let response = admin_client
        .request(Method::GET, &stream_url)
        .header("X-Admin-Password", &admin_password)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
    );
    let mut stream = response.bytes_stream().eventsource();
    let mut data = String::new();
    while let Ok(Some(Ok(event))) = timeout(Duration::from_secs(5), stream.next()).await {
        data.push_str(&event.data);
        data.push('\n');
    }
    assert!(
        data.contains("/pub/note.txt"),
        "admin stream should include the public event: {data}"
    );
    assert!(
        data.contains("/priv/app/secret.txt"),
        "admin stream should include the private event: {data}"
    );

    // A wrong admin password is rejected with 401.
    let unauthorized = admin_client
        .request(Method::GET, &stream_url)
        .header("X-Admin-Password", "wrong-password")
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    // Live mode: after replaying history, a brand-new private write is delivered.
    let response = admin_client
        .request(Method::GET, &format!("{stream_url}?live=true"))
        .header("X-Admin-Password", &admin_password)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut live = response.bytes_stream().eventsource();
    session
        .storage()
        .put("/priv/app/new.txt", vec![7, 8, 9])
        .await
        .unwrap();
    let mut saw_new = false;
    while let Ok(Some(Ok(event))) = timeout(Duration::from_secs(10), live.next()).await {
        if event.data.contains("/priv/app/new.txt") {
            saw_new = true;
            break;
        }
    }
    assert!(
        saw_new,
        "live admin stream should deliver the new private event"
    );
    drop(live); // close the live connection

    // The public client-server feed is public-only; it must NOT leak the private paths.
    let feed_url = format!("https://{}/events/", server.public_key().z32());
    let public_body = session
        .client()
        .request(Method::GET, &feed_url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        public_body.contains("/pub/note.txt"),
        "public feed should include the public event: {public_body}"
    );
    assert!(
        !public_body.contains("/priv/"),
        "public feed must not leak private paths: {public_body}"
    );
}
