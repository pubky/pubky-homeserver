use std::time::Duration;

use futures::{channel::mpsc, SinkExt};

use super::*;

fn status_of(error: Error) -> StatusCode {
    match error {
        Error::Request(RequestError::Server { status, .. }) => status,
        error => panic!("expected a server error, got {error:?}"),
    }
}

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
    let storage = session.storage();
    storage
        .lock("/pub/state.bin", Duration::from_secs(30))
        .await
        .unwrap();

    let assert_locked = |error: Error| {
        assert_eq!(status_of(error), StatusCode::LOCKED);
    };
    assert_locked(storage.put("/pub/state.bin", vec![1]).await.unwrap_err());
    assert_locked(storage.put_json("/pub/state.bin", &1).await.unwrap_err());
    assert_locked(storage.delete("/pub/state.bin").await.unwrap_err());
}

/// The typical cycle: lock, write under the lock while every other request
/// on the path is refused, unlock, and the path is free again.
#[tokio::test]
#[pubky_testnet::test]
async fn locked_write_excludes_others_until_unlocked() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();

    let session = pubky
        .signer(Keypair::random())
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let storage = session.storage();
    let path = "/pub/state.bin";

    let lock = storage.lock(path, Duration::from_secs(30)).await.unwrap();

    // A write under the lock whose body is fed chunk by chunk, so it is still
    // in flight while the requests below are made.
    let (mut chunks, body) = mpsc::channel::<Result<Bytes, std::convert::Infallible>>(1);
    let write = {
        let (session, lock) = (session.clone(), lock.clone());
        tokio::spawn(async move {
            session
                .storage()
                .put_locked(&lock, reqwest::Body::wrap_stream(body))
                .await
        })
    };
    chunks
        .send(Ok(Bytes::from_static(b"first,")))
        .await
        .unwrap();

    // Meanwhile: nobody else gets in, with or without a lock of their own.
    let plain = storage.put(path, vec![1]).await;
    assert_eq!(status_of(plain.unwrap_err()), StatusCode::LOCKED);
    let delete = storage.delete(path).await;
    assert_eq!(status_of(delete.unwrap_err()), StatusCode::LOCKED);
    let other = storage.lock(path, Duration::from_secs(5)).await;
    assert_eq!(status_of(other.unwrap_err()), StatusCode::LOCKED);

    // The write finishes and lands whole.
    chunks
        .send(Ok(Bytes::from_static(b"second")))
        .await
        .unwrap();
    drop(chunks);
    let response = write.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let stored = storage.get(path).await.unwrap().bytes().await.unwrap();
    assert_eq!(stored, Bytes::from_static(b"first,second"));

    // Still locked until the holder says so.
    let plain = storage.put(path, vec![1]).await;
    assert_eq!(status_of(plain.unwrap_err()), StatusCode::LOCKED);
    storage.unlock(&lock).await.unwrap();

    // Unlocked: a plain write goes through, and the released lock is useless.
    storage.put(path, vec![2]).await.unwrap();
    let stale = storage.put_locked(&lock, vec![3]).await;
    assert_eq!(
        status_of(stale.unwrap_err()),
        StatusCode::PRECONDITION_FAILED
    );
    let stored = storage.get(path).await.unwrap().bytes().await.unwrap();
    assert_eq!(stored, Bytes::from_static(&[2]));
}

/// Lock, refresh and unlock through the SDK, a locked delete, and what each
/// call returns once the lock is gone.
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
    let storage = session.storage();
    let path = "/pub/state.bin";
    storage.put(path, vec![1]).await.unwrap();

    // The homeserver caps the lifetime and the lock reports what was granted.
    let mut lock = storage.lock(path, Duration::from_secs(9999)).await.unwrap();
    assert_eq!(lock.path().as_str(), path);
    assert!(lock.token().starts_with("opaquelocktoken:"));
    assert_eq!(lock.timeout(), Duration::from_secs(60));

    storage
        .refresh(&mut lock, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(lock.timeout(), Duration::from_secs(10));

    // A locked delete leaves the lock in place.
    let response = storage.delete_locked(&lock).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let plain = storage.put(path, vec![2]).await;
    assert_eq!(status_of(plain.unwrap_err()), StatusCode::LOCKED);

    // Unlocked: the old lock is refused everywhere.
    storage.unlock(&lock).await.unwrap();
    let refresh = storage.refresh(&mut lock, Duration::from_secs(10)).await;
    assert_eq!(
        status_of(refresh.unwrap_err()),
        StatusCode::PRECONDITION_FAILED
    );
    let delete = storage.delete_locked(&lock).await;
    assert_eq!(
        status_of(delete.unwrap_err()),
        StatusCode::PRECONDITION_FAILED
    );
    let unlock = storage.unlock(&lock).await;
    assert_eq!(status_of(unlock.unwrap_err()), StatusCode::CONFLICT);

    // Only files can be locked.
    let directory = storage.lock("/pub/dir/", Duration::from_secs(5)).await;
    assert_eq!(status_of(directory.unwrap_err()), StatusCode::BAD_REQUEST);
}
