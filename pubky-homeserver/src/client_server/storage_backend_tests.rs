//! The client API on each storage backend a homeserver is configured with in
//! production. The other tests run it on the in-memory backend.

use std::sync::Arc;

use axum::http::{header, StatusCode};
use axum_test::{TestRequest, TestServer};
use pubky_common::{auth::AuthToken, capabilities::Capability, crypto::Keypair};

use crate::{app_context::AppContext, client_server::ClientServer};

/// Above the 5 MiB from which GCS uploads in parts.
const MULTIPART_SIZE: usize = 6 * 1024 * 1024;

mod file_system {
    use pubky_common::crypto::Keypair;

    use crate::{app_context::AppContext, storage_config::StorageConfigToml};

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn serves_files_through_the_api() {
        let context = AppContext::test_with_config(|c| {
            c.storage.backend = StorageConfigToml::FileSystem;
        })
        .await;

        super::serves_files_through_the_api(context, &Keypair::random()).await;
    }
}

/// Against the real bucket, see
/// [`gcs_test_bucket`](crate::persistence::files::test_support::gcs_test_bucket).
#[cfg(feature = "storage-gcs")]
mod gcs {
    use pubky_common::crypto::Keypair;

    use crate::persistence::files::test_support::TestBucket;
    use crate::{app_context::AppContext, storage_config::StorageConfigToml};

    // Multi-threaded for the cleaner, which blocks on its async drop.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs GCS_BUCKET and GOOGLE_APPLICATION_CREDENTIALS"]
    #[pubky_test_utils::test]
    async fn serves_files_through_the_api() {
        let bucket = TestBucket::from_env();
        let user = Keypair::random();
        // The homeserver stores in the bucket's root, under its users' keys.
        let _cleaner = bucket.user_cleaner(&user.public_key());
        let context = AppContext::test_with_config(|c| {
            c.storage.backend = StorageConfigToml::GoogleBucket(bucket.config());
        })
        .await;

        super::serves_files_through_the_api(context, &user).await;
    }
}

/// Writes a small file and a multipart one, the second under a name that
/// URLs percent-encode, reads both back, overwrites the small one, and
/// deletes both.
async fn serves_files_through_the_api(context: Arc<AppContext>, user: &Keypair) {
    let server = TestServer::new(ClientServer::create_router(context).unwrap());
    let user = SignedUpUser::sign_up(&server, user).await;
    let small_path = "/pub/smoke/small.txt";
    let small = vec![1u8; 1024];
    let multipart_path = "/pub/smoke/a%20b%20%C3%BC.bin";
    let multipart = vec![2u8; MULTIPART_SIZE];

    user.put(small_path, &small).await;
    user.put(multipart_path, &multipart).await;
    assert_eq!(user.get(small_path).await, small);
    assert_eq!(user.get(multipart_path).await, multipart);

    let overwrite = vec![3u8; 10];
    user.put(small_path, &overwrite).await;
    assert_eq!(user.get(small_path).await, overwrite);

    for path in [small_path, multipart_path] {
        user.delete(path).await;
        user.get_missing(path).await;
    }
}

/// A user signed up on the test server, sending its requests with its
/// session cookie.
struct SignedUpUser<'a> {
    server: &'a TestServer,
    public_key: String,
    cookie: String,
}

impl<'a> SignedUpUser<'a> {
    async fn sign_up(server: &'a TestServer, keypair: &Keypair) -> Self {
        let auth_token = AuthToken::sign(keypair, vec![Capability::root()]);
        let response = server
            .post("/signup")
            .add_header("host", keypair.public_key().z32())
            .bytes(auth_token.serialize().into())
            .expect_success()
            .await;
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .expect("signup returns a session cookie")
            .to_string();
        Self {
            server,
            public_key: keypair.public_key().z32(),
            cookie,
        }
    }

    async fn put(&self, path: &str, body: &[u8]) {
        self.authorized(self.server.put(&self.url(path)))
            .bytes(body.to_vec().into())
            .expect_success()
            .await;
    }

    async fn get(&self, path: &str) -> Vec<u8> {
        let response = self.server.get(&self.url(path)).expect_success().await;
        response.as_bytes().to_vec()
    }

    async fn get_missing(&self, path: &str) {
        self.server
            .get(&self.url(path))
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    async fn delete(&self, path: &str) {
        self.authorized(self.server.delete(&self.url(path)))
            .expect_success()
            .await;
    }

    fn url(&self, path: &str) -> String {
        format!("/storage/{}{path}", self.public_key)
    }

    fn authorized(&self, request: TestRequest) -> TestRequest {
        request
            .add_header("pubky-host", self.public_key.clone())
            .add_header(header::COOKIE, self.cookie.clone())
    }
}
