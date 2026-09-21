use std::time::Duration;

use super::*;

/// A plain SDK write to a locked path is not retried: the caller gets the
/// `423` and decides.
#[tokio::test]
#[pubky_testnet::test]
async fn write_to_locked_path_returns_locked() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let session = pubky
        .signer(Keypair::random())
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let cookie_secret = session.as_cookie().unwrap().export_secret().unwrap();
    let (cookie_name, cookie_value) = cookie_secret.split_once(':').unwrap();
    let url = format!(
        "{}storage/{}/pub/state.bin",
        server.icann_http_url(),
        session.public_key().z32()
    );
    let response = session
        .client()
        .request(Method::from_bytes(b"LOCK").unwrap(), &url)
        .header("Cookie", format!("{cookie_name}={cookie_value}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let assert_locked = |error: Error| {
        assert!(
            matches!(error, Error::Request(RequestError::Server { status, .. }) if status == StatusCode::LOCKED),
            "expected 423, got {error:?}"
        );
    };
    let storage = session.storage();
    assert_locked(storage.put("/pub/state.bin", vec![1]).await.unwrap_err());
    assert_locked(storage.put_json("/pub/state.bin", &1).await.unwrap_err());
    assert_locked(storage.delete("/pub/state.bin").await.unwrap_err());
}

/// The whole cycle through the SDK: lock, write under the lock, refresh,
/// unlock, and what each call returns once the lock is gone.
#[tokio::test]
#[pubky_testnet::test]
async fn lock_refresh_unlock() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let session = pubky
        .signer(Keypair::random())
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let cookie_secret = session.as_cookie().unwrap().export_secret().unwrap();
    let (cookie_name, cookie_value) = cookie_secret.split_once(':').unwrap();
    let url = format!(
        "{}storage/{}/pub/state.bin",
        server.icann_http_url(),
        session.public_key().z32()
    );
    let storage = session.storage();
    let status_of = |error: Error| match error {
        Error::Request(RequestError::Server { status, .. }) => status,
        error => panic!("expected a server error, got {error:?}"),
    };

    // The homeserver caps the lifetime and the lock reports what was granted.
    let mut lock = storage
        .lock("/pub/state.bin", Duration::from_secs(9999))
        .await
        .unwrap();
    assert_eq!(lock.path().as_str(), "/pub/state.bin");
    assert!(lock.token().starts_with("opaquelocktoken:"));
    assert_eq!(lock.timeout(), Duration::from_secs(60));

    // Held: a second lock and a plain write are refused, a write that
    // presents the lock goes through.
    let second = storage.lock("/pub/state.bin", Duration::from_secs(5)).await;
    assert_eq!(status_of(second.unwrap_err()), StatusCode::LOCKED);
    let plain = storage.put("/pub/state.bin", vec![1]).await;
    assert_eq!(status_of(plain.unwrap_err()), StatusCode::LOCKED);
    let response = session
        .client()
        .request(Method::PUT, &url)
        .header("Cookie", format!("{cookie_name}={cookie_value}"))
        .header("If", lock.if_header())
        .body(vec![1])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    storage
        .refresh(&mut lock, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(lock.timeout(), Duration::from_secs(10));

    // Unlocked: the path is free, and the old lock is refused everywhere.
    storage.unlock(&lock).await.unwrap();
    storage.put("/pub/state.bin", vec![2]).await.unwrap();
    let refresh = storage.refresh(&mut lock, Duration::from_secs(10)).await;
    assert_eq!(
        status_of(refresh.unwrap_err()),
        StatusCode::PRECONDITION_FAILED
    );
    let unlock = storage.unlock(&lock).await;
    assert_eq!(status_of(unlock.unwrap_err()), StatusCode::CONFLICT);

    // Only files can be locked.
    let directory = storage.lock("/pub/dir/", Duration::from_secs(5)).await;
    assert_eq!(status_of(directory.unwrap_err()), StatusCode::BAD_REQUEST);
}
