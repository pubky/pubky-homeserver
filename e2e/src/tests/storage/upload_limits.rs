use std::{convert::Infallible, time::Duration};

use futures::{stream, StreamExt};
use pubky_testnet::pubky_homeserver::{
    storage_config::StorageConfigToml, DataDir, HomeserverApp, MAX_UPLOAD_BYTES,
};

use super::*;

/// Reuse one small chunk so tests exercise the real limit without allocating
/// an entire upload. A streaming reqwest body has no Content-Length.
fn upload_chunks(length: usize) -> impl futures::Stream<Item = Result<Bytes, Infallible>> {
    let chunk = Bytes::from(vec![42; 64 * 1024]);
    stream::iter(
        (0..length)
            .step_by(chunk.len())
            .map(move |offset| Ok(chunk.slice(..chunk.len().min(length - offset)))),
    )
}

async fn assert_upload_status(request: reqwest::RequestBuilder, expected: StatusCode) {
    let response = request.send().await.expect("upload request failed");
    let status = response.status();
    let url = response.url().clone();
    let body = response
        .text()
        .await
        .expect("failed to read upload response");
    assert_eq!(status, expected, "PUT {url}: {body}");
}

#[tokio::test]
#[pubky_testnet::test]
async fn upload_limit_applies_to_both_routes_and_cleans_up_rejected_overwrites() {
    let mut testnet = Testnet::new().await.unwrap();
    testnet.create_pkarr_relay().await.unwrap();
    let pubky = testnet.sdk().unwrap();
    let mut data_dir = MockDataDir::test();
    data_dir.config_toml.storage.backend = StorageConfigToml::FileSystem;
    // Exercise the body wrapper that loses the original size hint too.
    data_dir.config_toml.default_quotas.rate_write = Some("1gb/s".parse().unwrap());
    data_dir.config_toml.pkdns.dht_bootstrap_nodes = Some(testnet.dht_bootstrap_nodes());
    data_dir.config_toml.pkdns.dht_relay_nodes = Some(testnet.dht_relay_urls());
    let staging_dir = data_dir.path().join("data/files-tmp");
    // Testnet's create_homeserver_app_with_mock forces in-memory storage.
    let server = HomeserverApp::start_with_mock_data_dir(data_dir)
        .await
        .unwrap();
    let session = pubky
        .signer(Keypair::random())
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let secret = session.as_cookie().unwrap().export_secret().unwrap();
    let (name, value) = secret.split_once(':').unwrap();
    let cookie = format!("{name}={value}");
    let owner = session.public_key().z32();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap();

    let storage_url = server
        .icann_http_url()
        .join(&format!("storage/{owner}/pub/limit.bin"))
        .unwrap();
    let legacy_url = server.icann_http_url().join("pub/limit.bin").unwrap();

    for (url, legacy_host) in [
        (storage_url.clone(), None),
        (legacy_url, Some(owner.as_str())),
    ] {
        let put = || {
            let request = client.put(url.clone()).header("Cookie", &cookie);
            match legacy_host {
                Some(host) => request.header("pubky-host", host),
                None => request,
            }
        };

        // The declared size is rejected without waiting for any body bytes.
        assert_upload_status(
            put()
                .header("Content-Length", MAX_UPLOAD_BYTES + 1)
                .body(reqwest::Body::wrap_stream(stream::pending::<
                    Result<Bytes, Infallible>,
                >())),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;

        // Both boundaries are accepted without Content-Length, and the full
        // body is stored at each boundary.
        for length in [0, MAX_UPLOAD_BYTES] {
            assert_upload_status(
                put().body(reqwest::Body::wrap_stream(upload_chunks(length))),
                StatusCode::CREATED,
            )
            .await;

            let response = client.head(storage_url.clone()).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["content-length"], length.to_string());
        }

        // Replace it with a small file so preservation is cheap to verify.
        assert_upload_status(put().body("old content"), StatusCode::CREATED).await;

        // One byte too many must fail before EOF, abort staging, and keep
        // the existing file. The pending tail never finishes the request.
        let body = upload_chunks(MAX_UPLOAD_BYTES + 1).chain(stream::pending());
        assert_upload_status(
            put().body(reqwest::Body::wrap_stream(body)),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;

        let mut staged_files = tokio::fs::read_dir(&staging_dir).await.unwrap();
        let leftover = staged_files
            .next_entry()
            .await
            .unwrap()
            .map(|entry| entry.path());
        assert_eq!(leftover, None, "staged file after rejected PUT {url}");

        let stored = session
            .storage()
            .get("/pub/limit.bin")
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(stored, "old content");
    }
}
