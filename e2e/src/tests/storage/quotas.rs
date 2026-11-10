use std::{convert::Infallible, path::Path, time::Duration};

use futures::{stream, StreamExt};
use pubky_testnet::{
    pubky::ClientId,
    pubky_homeserver::{storage_config::StorageConfigToml, DataDir, HomeserverApp},
};
use tokio::{sync::oneshot, time::timeout};

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

async fn read_event_feed(client: &reqwest::Client, url: &reqwest::Url) -> String {
    let response = client.get(url.clone()).send().await.unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "GET {url}: {body}");
    body
}

async fn assert_quota_rejected(response: reqwest::Response) {
    let status = response.status();
    let url = response.url().clone();
    let body = response.text().await.unwrap();
    assert_eq!(
        status,
        StatusCode::INSUFFICIENT_STORAGE,
        "PUT {url}: {body}"
    );
}

async fn assert_no_staged_files(staging_dir: &Path) {
    let mut staged = tokio::fs::read_dir(staging_dir).await.unwrap();
    let leftover = staged.next_entry().await.unwrap().map(|entry| entry.path());
    assert_eq!(leftover, None, "rejected upload left a staged file");
}

/// Quota preflight must reject before reading the body, and finalization must
/// use current usage even if another upload finished while this one streamed.
#[tokio::test]
#[pubky_testnet::test]
async fn streaming_quota_checks_preserve_files_accounting_and_events() {
    let mut testnet = Testnet::new().await.unwrap();
    testnet.create_pkarr_relay().await.unwrap();
    let pubky = testnet.sdk().unwrap();
    let mut data_dir = MockDataDir::test();
    data_dir.config_toml.storage.default_quota_mb = Some(1);
    data_dir.config_toml.storage.backend = StorageConfigToml::FileSystem;
    data_dir.config_toml.default_quotas.rate_write = Some("10mb/s".parse().unwrap());
    data_dir.config_toml.pkdns.dht_bootstrap_nodes = Some(testnet.dht_bootstrap_nodes());
    data_dir.config_toml.pkdns.dht_relay_nodes = Some(testnet.dht_relay_urls());
    let staging_dir = data_dir.path().join("data/files-tmp");
    // The Testnet helper forces in-memory storage; use real staging files here.
    let server = HomeserverApp::start_with_mock_data_dir(data_dir)
        .await
        .unwrap();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let events_url = server.icann_http_url().join("events/?limit=100").unwrap();

    for use_legacy_route in [false, true] {
        let signer = pubky.signer(Keypair::random());
        signer.signup(&server.public_key(), None).await.unwrap();
        let session = signer
            .signin(ClientId::new("quota.test").unwrap())
            .await
            .unwrap();
        let grant = session.as_grant().unwrap();
        let bearer = grant.current_bearer().await;
        let owner = session.public_key().z32();
        let storage_url = server
            .icann_http_url()
            .join(&format!("storage/{owner}/pub/original"))
            .unwrap();
        let legacy_url = server.icann_http_url().join("pub/original").unwrap();
        let upload_url = if use_legacy_route {
            legacy_url
        } else {
            storage_url
        };
        let put = || {
            client
                .put(upload_url.clone())
                .bearer_auth(&bearer)
                .header("pubky-host", &owner)
        };

        session
            .storage()
            .put("/pub/original", "old content")
            .await
            .unwrap();
        let used_before = grant.account().await.unwrap().used_bytes;
        let events_before = read_event_feed(&client, &events_url).await;

        // Below the upload-size cap, but over quota. This body never yields a
        // byte, so a 507 proves Content-Length preflight rejected it early.
        let response = put()
            .header("Content-Length", 1024 * 1024)
            .body(reqwest::Body::wrap_stream(stream::pending::<
                Result<Bytes, Infallible>,
            >()))
            .send()
            .await
            .unwrap();
        assert_quota_rejected(response).await;

        // Without Content-Length, the completed stream must still get a 507.
        let body = stream::iter([Ok::<_, Infallible>(Bytes::from(vec![42; 1024 * 1024]))]);
        let response = put()
            .body(reqwest::Body::wrap_stream(body))
            .send()
            .await
            .unwrap();
        assert_quota_rejected(response).await;
        assert_eq!(grant.account().await.unwrap().used_bytes, used_before);
        assert_eq!(read_event_feed(&client, &events_url).await, events_before);
        assert_no_staged_files(&staging_dir).await;

        // This declared size fits at preflight. Pause halfway through the body
        // until another write has consumed the remaining quota.
        let (finish_upload, resume) = oneshot::channel();
        let body = stream::iter([Ok::<_, Infallible>(Bytes::from(vec![42; 300_000]))]).chain(
            stream::once(async move {
                resume.await.unwrap();
                Ok(Bytes::from(vec![42; 300_000]))
            }),
        );
        let upload = put()
            .header("Content-Length", 600_000)
            .body(reqwest::Body::wrap_stream(body))
            .send();
        let upload = tokio::spawn(upload);

        // Observe server-side staging, not just client-side delivery, before
        // issuing the competing write. No fixed sleep decides the ordering.
        timeout(Duration::from_secs(10), async {
            loop {
                let mut staged = tokio::fs::read_dir(&staging_dir).await.unwrap();
                if let Some(entry) = staged.next_entry().await.unwrap() {
                    if entry.metadata().await.unwrap().len() > 0 {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("upload should stage bytes before it finishes");

        // Completing this write while the first is paused also proves the
        // streaming request does not hold the user's database row lock.
        timeout(
            Duration::from_secs(10),
            session.storage().put("/pub/competitor", vec![7; 600_000]),
        )
        .await
        .expect("an unfinished upload must not block another write")
        .unwrap();
        let used_after_competitor = grant.account().await.unwrap().used_bytes;
        let events_after_competitor = read_event_feed(&client, &events_url).await;

        finish_upload.send(()).unwrap();
        let response = upload.await.unwrap().unwrap();
        assert_quota_rejected(response).await;
        assert_eq!(
            grant.account().await.unwrap().used_bytes,
            used_after_competitor
        );
        assert_eq!(
            read_event_feed(&client, &events_url).await,
            events_after_competitor
        );
        let stored = session
            .storage()
            .get("/pub/original")
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(stored, "old content");
        assert_no_staged_files(&staging_dir).await;
    }
}
