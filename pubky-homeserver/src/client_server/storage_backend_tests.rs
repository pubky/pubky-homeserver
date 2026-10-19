//! The client API on each storage backend a homeserver is configured with in
//! production. The other tests run it on the in-memory backend.

use std::sync::Arc;

use axum::http::{header, StatusCode};
use axum_test::TestServer;
use pubky_common::{auth::AuthToken, capabilities::Capability, crypto::Keypair};

use crate::{
    app_context::AppContext, client_server::ClientServer, storage_config::StorageConfigToml,
};

/// Above the 5 MiB from which GCS uploads in parts.
const MULTIPART_SIZE: usize = 6 * 1024 * 1024;

#[tokio::test]
#[pubky_test_utils::test]
async fn file_system_serves_files_through_the_api() {
    let context = AppContext::test_with_config(|c| {
        c.storage.backend = StorageConfigToml::FileSystem;
    })
    .await;

    serves_files_through_the_api(context, &Keypair::random()).await;
}

/// Against the real bucket, see
/// [`gcs_test_bucket`](crate::persistence::files::gcs_test_bucket).
// Multi-threaded for the cleaner, which blocks on its async drop.
#[cfg(feature = "storage-gcs")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GCS_BUCKET and GOOGLE_APPLICATION_CREDENTIALS"]
#[pubky_test_utils::test]
async fn gcs_serves_files_through_the_api() {
    use crate::persistence::files::gcs_test_bucket::TestBucket;

    let bucket = TestBucket::from_env();
    let user = Keypair::random();
    // The homeserver stores in the bucket's root, under its users' keys.
    let _cleaner = bucket.cleaner_of_user(&user.public_key());
    let context = AppContext::test_with_config(|c| {
        c.storage.backend = StorageConfigToml::GoogleBucket(bucket.config());
    })
    .await;

    serves_files_through_the_api(context, &user).await;
}

/// Writes a small file and a multipart one, the second under a name that
/// URLs percent-encode, reads both back, overwrites one, and deletes both.
async fn serves_files_through_the_api(context: Arc<AppContext>, user: &Keypair) {
    let server = TestServer::new(ClientServer::create_router(context).unwrap());
    let cookie = signup_cookie(&server, user).await;
    let public_key = user.public_key().z32();
    let files = [
        ("/pub/smoke/small.txt", vec![1u8; 1024]),
        ("/pub/smoke/a%20b%20%C3%BC.bin", vec![2u8; MULTIPART_SIZE]),
    ];
    let url = |path: &str| format!("/storage/{public_key}{path}");

    for (path, body) in &files {
        server
            .put(&url(path))
            .add_header("pubky-host", public_key.clone())
            .add_header(header::COOKIE, cookie.clone())
            .bytes(body.clone().into())
            .expect_success()
            .await;
        let read = server.get(&url(path)).expect_success().await;
        assert_eq!(read.as_bytes().as_ref(), body.as_slice(), "{path}");
    }

    let (path, _) = &files[0];
    let overwrite = vec![3u8; 10];
    server
        .put(&url(path))
        .add_header("pubky-host", public_key.clone())
        .add_header(header::COOKIE, cookie.clone())
        .bytes(overwrite.clone().into())
        .expect_success()
        .await;
    let read = server.get(&url(path)).expect_success().await;
    assert_eq!(read.as_bytes().as_ref(), overwrite.as_slice());

    for (path, _) in &files {
        server
            .delete(&url(path))
            .add_header("pubky-host", public_key.clone())
            .add_header(header::COOKIE, cookie.clone())
            .expect_success()
            .await;
        server
            .get(&url(path))
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }
}

async fn signup_cookie(server: &TestServer, keypair: &Keypair) -> String {
    let auth_token = AuthToken::sign(keypair, vec![Capability::root()]);
    let response = server
        .post("/signup")
        .add_header("host", keypair.public_key().z32())
        .bytes(auth_token.serialize().into())
        .expect_success()
        .await;
    response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("signup returns a session cookie")
        .to_string()
}
