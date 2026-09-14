use super::objects::assert_server_status;
use super::*;
use pubky_testnet::pubky::content_etag;

fn assert_precondition_failed(error: Error) {
    assert!(
        matches!(
            error,
            Error::Request(RequestError::PreconditionFailed { .. })
        ),
        "expected a precondition failure, got {error:?}"
    );
}

#[tokio::test]
#[pubky_testnet::test]
async fn put_if_absent_creates_once() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let session = pubky
        .signer(Keypair::random())
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let storage = session.storage();
    let path = "/pub/example.com/once.txt";

    let etag = storage.put_if_absent(path, "first").await.unwrap();
    assert_eq!(etag, content_etag(b"first"));

    let error = storage.put_if_absent(path, "second").await.unwrap_err();
    assert_precondition_failed(error);
    assert_eq!(storage.get_verified(path).await.unwrap().bytes, b"first");
}

#[tokio::test]
#[pubky_testnet::test]
async fn put_if_match_is_compare_and_set() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let session = pubky
        .signer(Keypair::random())
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let storage = session.storage();
    let path = "/pub/example.com/state.bin";

    let etag_v1 = storage.put_if_absent(path, "v1").await.unwrap();
    assert_eq!(
        storage.stats(path).await.unwrap().unwrap().strong_etag(),
        Some(etag_v1.as_str())
    );

    // Fresh tag: the update lands and reports the new tag.
    let etag_v2 = storage.put_if_match(path, "v2", &etag_v1).await.unwrap();
    assert_eq!(etag_v2, content_etag(b"v2"));

    // Stale tag: rejected, content untouched; the quoted form is accepted too.
    let error = storage
        .put_if_match(path, "v3", &format!("\"{etag_v1}\""))
        .await
        .unwrap_err();
    assert_precondition_failed(error);
    let current = storage.get_verified(path).await.unwrap();
    assert_eq!(current.bytes, b"v2");
    assert_eq!(current.etag, etag_v2);

    // The client can also present the hash of content it holds.
    storage
        .put_if_match(path, "v3", &content_etag(b"v2"))
        .await
        .unwrap();
    assert_eq!(storage.get_verified(path).await.unwrap().bytes, b"v3");
}

#[tokio::test]
#[pubky_testnet::test]
async fn delete_if_match_removes_only_the_matching_version() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let session = pubky
        .signer(Keypair::random())
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let storage = session.storage();
    let path = "/pub/example.com/doomed.txt";

    let etag_v1 = storage.put_if_absent(path, "v1").await.unwrap();
    let etag_v2 = storage.put_if_match(path, "v2", &etag_v1).await.unwrap();

    let error = storage.delete_if_match(path, &etag_v1).await.unwrap_err();
    assert_precondition_failed(error);
    assert!(storage.exists(path).await.unwrap());

    storage.delete_if_match(path, &etag_v2).await.unwrap();
    assert!(!storage.exists(path).await.unwrap());

    // Gone: a conditional delete of a missing path is a plain 404.
    let error = storage.delete_if_match(path, &etag_v2).await.unwrap_err();
    assert_server_status(error, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[pubky_testnet::test]
async fn verified_reads_check_the_body_against_its_etag() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let keypair = Keypair::random();
    let user = keypair.public_key();
    let session = pubky
        .signer(keypair)
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();
    let path = "/pub/example.com/verified.bin";
    let body = Bytes::from(vec![7; 4096]);

    session.storage().put(path, body.clone()).await.unwrap();

    let mine = session.storage().get_verified(path).await.unwrap();
    assert_eq!(mine.bytes, body);
    assert_eq!(mine.etag, content_etag(&body));

    let theirs = pubky
        .public_storage()
        .get_verified(format!("pubky://{}{path}", user.z32()))
        .await
        .unwrap();
    assert_eq!(theirs, mine);
}

#[tokio::test]
#[pubky_testnet::test]
async fn weak_entity_tags_are_rejected_before_any_request() {
    let testnet = build_full_testnet().await;
    let server = testnet.homeserver_app();
    let pubky = testnet.sdk().unwrap();
    let session = pubky
        .signer(Keypair::random())
        .signup_cookie(&server.public_key(), None)
        .await
        .unwrap();

    let error = session
        .storage()
        .put_if_match("/pub/example.com/x", "x", "W/\"abc\"")
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Request(RequestError::Validation { .. })
    ));
}
