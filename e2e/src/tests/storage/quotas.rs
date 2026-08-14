use super::*;

#[tokio::test]
#[pubky_testnet::test]
async fn put_quota_applied() {
    // Start a test homeserver with 1 MB user data limit
    let mut testnet = Testnet::new().await.unwrap();
    let pubky = testnet.sdk().unwrap();

    let mut mock_dir = MockDataDir::test();
    mock_dir.config_toml.storage.default_quota_mb = Some(1); // 1 MB
    let server = testnet
        .create_homeserver_app_with_mock(mock_dir)
        .await
        .unwrap();

    // Create a user/session
    let signer = pubky.signer(Keypair::random());
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let cookie_secret = session.as_cookie().unwrap().export_secret().unwrap();
    let (cookie_name, cookie_value) = cookie_secret.split_once(':').unwrap();
    let cookie = format!("{cookie_name}={cookie_value}");

    let p1 = "/pub/data";
    let p2 = "/pub/data2";

    // First 600 KB → OK (201)
    let data_600k: Vec<u8> = vec![0; 600_000];
    let resp = session.storage().put(p1, data_600k.clone()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Overwrite same 600 KB → still 201
    let resp = session.storage().put(p1, data_600k.clone()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Write 600 KB more through `/storage/{user_z32}/{path}` (total 1.2 MB) → 507.
    let storage_url = format!(
        "{}storage/{}/{}",
        server.icann_http_url(),
        session.public_key().z32(),
        p2.trim_start_matches('/')
    );
    let response = session
        .client()
        .request(Method::PUT, &storage_url)
        .header("Cookie", cookie)
        .body(data_600k.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);

    // Overwrite /pub/data with 1.1 MB → 507
    let data_1100k: Vec<u8> = vec![0; 1_100_000];
    let err = session.storage().put(p1, data_1100k).await.unwrap_err();
    assert!(matches!(
        err,
        Error::Request(RequestError::Server { status, .. })
            if status == StatusCode::INSUFFICIENT_STORAGE
    ));

    // Delete the original 600 KB → 204
    let resp = session.storage().delete(p1).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Write exactly 1025 KB → 507 (exceeds 1 MB quota)
    let data_1025k_minus_256: Vec<u8> = vec![0; 1025 * 1024 - 256];
    let err = session
        .storage()
        .put(p1, data_1025k_minus_256)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Request(RequestError::Server { status, .. })
            if status == StatusCode::INSUFFICIENT_STORAGE
    ));

    // Write exactly 1 MB (minus the same 256 fudge) → 201 (fits quota)
    let data_1mb_minus_256: Vec<u8> = vec![0; 1024 * 1024 - 256];
    let resp = session.storage().put(p1, data_1mb_minus_256).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}
/// Regression test: quota early-rejection still works when bandwidth throttling
/// is active. The bandwidth middleware wraps the request body in a throttled
/// stream that loses `body.size_hint()`. The fix reads Content-Length from
/// headers instead.
#[tokio::test]
#[pubky_testnet::test]
async fn put_quota_applied_with_bandwidth_throttling() {
    let mut testnet = Testnet::new().await.unwrap();
    let pubky = testnet.sdk().unwrap();

    let mut mock_dir = MockDataDir::test();
    mock_dir.config_toml.storage.default_quota_mb = Some(1); // 1 MB
                                                             // Enable bandwidth throttling so the BandwidthQuotaLimitLayer wraps the body.
    mock_dir.config_toml.default_quotas.rate_write = Some("10mb/s".parse().unwrap());
    let server = testnet
        .create_homeserver_app_with_mock(mock_dir)
        .await
        .unwrap();

    let signer = pubky.signer(Keypair::random());
    let session = signer
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    // First 600 KB → OK (201)
    let data_600k: Vec<u8> = vec![0; 600_000];
    let resp = session
        .storage()
        .put("/pub/data", data_600k.clone())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Write another 600 KB at a different path (total 1.2 MB) → should be rejected
    // early via Content-Length header check, even though the bandwidth layer
    // has already replaced the body stream (losing size_hint).
    let err = session
        .storage()
        .put("/pub/data2", data_600k)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Request(RequestError::Server { status, .. })
                if status == StatusCode::INSUFFICIENT_STORAGE
        ),
        "Expected 507 INSUFFICIENT_STORAGE but got: {:?}",
        err
    );
}
