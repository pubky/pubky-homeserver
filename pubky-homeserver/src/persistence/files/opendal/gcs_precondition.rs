//! The HTTP client of the Google Cloud Storage backend, which puts the
//! generation condition on the requests that publish and delete.
//!
//! opendal tags each request with the service operation it is for. A copy
//! (`RewriteObject`) or delete (`DeleteObject`) sent while the task runs under
//! an expected generation, see
//! [`staged_publish_layer`](crate::persistence::files::staged_publish_layer),
//! gets `ifGenerationMatch` with that value, and GCS answers 412 when the
//! object's generation differs. Uploads are never conditional: they go to a
//! staging object, and the copy that publishes is what carries the condition.
//!
//! A copy sent under an expected source generation, see
//! [`under_expected_source_generation`], also gets `ifSourceGenerationMatch`,
//! so it copies only the version of the source that was seen. GCS answers 412
//! for either condition, so a refusal does not tell which object changed.

use axum::http::{Request, Response, Uri};
use opendal::raw::{HttpBody, HttpFetch, ServiceOperation};
use opendal::{Buffer, Error, ErrorKind, Result};

use crate::persistence::files::staged_publish_layer::{expected_generation, ExpectedGeneration};

/// Service operations whose request must carry the condition. A batch delete
/// (`BatchDeleteObjects`) cannot: its conditions would have to go into each
/// sub-request inside the body. The staged publish layer flushes deletes one
/// path at a time so that opendal never batches them, and its tests pin that.
const CONDITIONAL_OPERATIONS: [&str; 2] = ["RewriteObject", "DeleteObject"];

/// The service operation of a copy, the only one with a source.
const COPY_OPERATION: &str = "RewriteObject";

tokio::task_local! {
    static EXPECTED_SOURCE_GENERATION: u64;
}

/// Run `request`, a copy, so that GCS refuses it unless its source is at
/// `generation`.
pub(super) async fn under_expected_source_generation<T>(
    generation: u64,
    request: impl std::future::Future<Output = T>,
) -> T {
    EXPECTED_SOURCE_GENERATION.scope(generation, request).await
}

/// The generation the source of the current task's copy must be at, if it
/// runs under one.
fn expected_source_generation() -> Option<u64> {
    EXPECTED_SOURCE_GENERATION
        .try_with(|generation| *generation)
        .ok()
}

/// Wraps an HTTP client so that conditional requests carry their condition.
#[derive(Debug, Clone)]
pub(super) struct PreconditionFetcher<F> {
    inner: F,
}

impl<F: HttpFetch> PreconditionFetcher<F> {
    pub(super) fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F: HttpFetch> HttpFetch for PreconditionFetcher<F> {
    async fn fetch(&self, req: Request<Buffer>) -> Result<Response<HttpBody>> {
        let req = with_precondition(req, expected_generation(), expected_source_generation())?;
        self.inner.fetch(req).await
    }
}

/// Put `ifGenerationMatch` on `req` if it is a conditional operation and
/// `expected` asks for a condition, and `ifSourceGenerationMatch` if it is a
/// copy and `expected_source` asks for one.
fn with_precondition(
    mut req: Request<Buffer>,
    expected: Option<ExpectedGeneration>,
    expected_source: Option<u64>,
) -> Result<Request<Buffer>> {
    let operation = req
        .extensions()
        .get::<ServiceOperation>()
        .map(|operation| operation.0);
    let mut conditions = Vec::new();
    if let Some(generation) = expected.map(ExpectedGeneration::if_generation_match) {
        if operation.is_some_and(|operation| CONDITIONAL_OPERATIONS.contains(&operation)) {
            conditions.push(format!("ifGenerationMatch={generation}"));
        }
    }
    if let Some(generation) = expected_source {
        if operation == Some(COPY_OPERATION) {
            conditions.push(format!("ifSourceGenerationMatch={generation}"));
        }
    }
    if conditions.is_empty() {
        return Ok(req);
    }
    let uri = req.uri();
    let separator = if uri.query().is_some() { '&' } else { '?' };
    let conditional_uri: Uri = format!("{uri}{separator}{}", conditions.join("&"))
        .parse()
        .map_err(|error| {
            Error::new(
                ErrorKind::Unexpected,
                "Failed to add the generation condition",
            )
            .with_context("url", uri.to_string())
            .set_source(error)
        })?;
    *req.uri_mut() = conditional_uri;
    Ok(req)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::persistence::files::staged_publish_layer::under_expected_generation;

    fn request(operation: &'static str, url: &str) -> Request<Buffer> {
        Request::post(url)
            .extension(ServiceOperation(operation))
            .body(Buffer::new())
            .unwrap()
    }

    #[test]
    fn condition_goes_on_publish_and_delete_requests_only() {
        let absent = Some(ExpectedGeneration::Absent);
        let known = Some(ExpectedGeneration::Known(42));

        let copy = with_precondition(
            request("RewriteObject", "https://s/b/o/a/rewriteTo/b/o/b?x=1"),
            known,
            None,
        )
        .unwrap();
        assert_eq!(
            copy.uri().query(),
            Some("x=1&ifGenerationMatch=42"),
            "a copy under a known generation is conditional on it"
        );

        let delete =
            with_precondition(request("DeleteObject", "https://s/b/o/a"), absent, None).unwrap();
        assert_eq!(delete.uri().query(), Some("ifGenerationMatch=0"));

        let upload = with_precondition(
            request("InsertObject", "https://s/upload?uploadType=media"),
            known,
            None,
        )
        .unwrap();
        assert_eq!(upload.uri().query(), Some("uploadType=media"));

        let outside =
            with_precondition(request("RewriteObject", "https://s/b"), None, None).unwrap();
        assert_eq!(outside.uri().query(), None);
    }

    #[test]
    fn source_condition_goes_on_copy_requests_only() {
        let copy = with_precondition(
            request("RewriteObject", "https://s/b/o/a/rewriteTo/b/o/b"),
            Some(ExpectedGeneration::Absent),
            Some(42),
        )
        .unwrap();
        assert_eq!(
            copy.uri().query(),
            Some("ifGenerationMatch=0&ifSourceGenerationMatch=42"),
            "a copy carries both conditions"
        );

        let source_only = with_precondition(
            request("RewriteObject", "https://s/b/o/a/rewriteTo/b/o/b"),
            None,
            Some(42),
        )
        .unwrap();
        assert_eq!(
            source_only.uri().query(),
            Some("ifSourceGenerationMatch=42")
        );

        let delete =
            with_precondition(request("DeleteObject", "https://s/b/o/a"), None, Some(42)).unwrap();
        assert_eq!(delete.uri().query(), None, "a delete has no source");
    }

    /// A client that records the URL of every request it is given.
    #[derive(Clone, Default)]
    struct Recorder(Arc<Mutex<Vec<String>>>);

    impl HttpFetch for Recorder {
        async fn fetch(&self, req: Request<Buffer>) -> Result<Response<HttpBody>> {
            self.0.lock().unwrap().push(req.uri().to_string());
            Ok(Response::builder()
                .status(200)
                .body(HttpBody::new(futures_util::stream::empty(), Some(0)))
                .unwrap())
        }
    }

    /// Against a real bucket, when `GOOGLE_APPLICATION_CREDENTIALS` and
    /// `GCS_BUCKET` are set, the production stack end to end:
    ///
    /// 1. Writes land through staging, below and above the 5 MiB multipart
    ///    threshold, and leave no staging object behind.
    /// 2. A publish and a delete prepared against an object that a newer
    ///    write has since replaced are refused, and the newer data stays.
    /// 3. A read returns one version of the object or fails, never bytes of
    ///    two: an overwrite between two chunks ends the stream.
    // Multi-threaded for the cleaner, which deletes the test root on drop.
    #[tokio::test(flavor = "multi_thread")]
    async fn gcs_refuses_stale_changes_and_mixed_reads() {
        use futures_util::StreamExt;
        use pubky_common::crypto::Keypair;

        use async_dropper::AsyncDropper;

        use crate::persistence::files::opendal::opendal_service::{gcs_operator, OpendalService};
        use crate::persistence::files::opendal::opendal_test_operators::OpendalGcpCleaner;
        use crate::persistence::files::staged_publish_layer::live_generation;
        use crate::shared::webdav::{EntryPath, StoragePath};

        let (Ok(bucket), Ok(credentials)) = (
            std::env::var("GCS_BUCKET"),
            std::env::var("GOOGLE_APPLICATION_CREDENTIALS"),
        ) else {
            eprintln!("GCS_BUCKET or GOOGLE_APPLICATION_CREDENTIALS not set; skipping");
            return;
        };
        let root = format!("test_{}", uuid::Uuid::new_v4());
        let builder = || {
            opendal::services::Gcs::default()
                .bucket(&bucket)
                .credential_path(&credentials)
                .root(&root)
        };
        // The production stack, and the bare backend with only the condition
        // on it, through which the late requests below are sent.
        let operator = gcs_operator(builder()).unwrap();
        let backend = opendal::Operator::new(builder())
            .unwrap()
            .layer(opendal::layers::HttpClientLayer::new(
                opendal::raw::HttpClient::with(PreconditionFetcher::new(reqwest::Client::new())),
            ))
            .finish();
        // Removes the test root from the bucket on drop.
        let _cleaner = AsyncDropper::new(OpendalGcpCleaner::new(Some(backend.clone())));
        let entry_path = EntryPath::new(
            Keypair::random().public_key(),
            StoragePath::new("/pub/a.bin").unwrap(),
        );
        let path = entry_path.as_str();
        let small = 1024;
        let large = 6 * 1024 * 1024;

        // What the finalization does: read the generation, then change the
        // object under it.
        let generation = || {
            let backend = backend.clone().into_inner();
            async move {
                live_generation(&backend, path)
                    .await
                    .unwrap()
                    .expect("GCS reports a generation")
            }
        };
        let staging_objects = || async {
            operator
                .list(".staging/")
                .await
                .unwrap()
                .iter()
                .filter(|entry| entry.metadata().is_file())
                .count()
        };

        // 1. A single-request upload, then a multipart one.
        let g = generation().await;
        assert_eq!(g, ExpectedGeneration::Absent);
        under_expected_generation(g, operator.write(path, vec![1u8; small]))
            .await
            .unwrap();
        assert_eq!(
            operator.read(path).await.unwrap().to_vec(),
            vec![1u8; small]
        );
        let g = generation().await;
        under_expected_generation(g, operator.write(path, vec![2u8; large]))
            .await
            .unwrap();
        assert_eq!(
            operator.read(path).await.unwrap().to_vec(),
            vec![2u8; large]
        );
        assert_eq!(
            staging_objects().await,
            0,
            "every staging object was removed"
        );

        // 2. A publish and a delete are prepared against the object as it is
        // now, a newer write lands, and both are refused; the newer data,
        // itself a multipart upload, stays intact.
        let stale = generation().await;
        assert!(matches!(stale, ExpectedGeneration::Known(_)));
        under_expected_generation(stale, operator.write(path, vec![3u8; large]))
            .await
            .unwrap();
        backend.write("stale", vec![4u8; 10]).await.unwrap();
        let late_publish =
            under_expected_generation(stale, async { backend.copy("stale", path).await })
                .await
                .expect_err("a publish against a replaced object is refused");
        assert_eq!(late_publish.kind(), ErrorKind::ConditionNotMatch);
        let late_delete = under_expected_generation(stale, async { backend.delete(path).await })
            .await
            .expect_err("a delete against a replaced object is refused");
        assert_eq!(late_delete.kind(), ErrorKind::ConditionNotMatch);
        assert_eq!(
            operator.read(path).await.unwrap().to_vec(),
            vec![3u8; large]
        );

        // 3. A read through the server's read path, overwritten between two
        // of its chunks: what it delivered is the version it started on, and
        // it either completes that version or fails.
        let service = OpendalService::new_from_operator(operator.clone());
        let (length, mut stream) = service.get_sized_stream(&entry_path).await.unwrap();
        assert_eq!(length as usize, large);
        let first = stream.next().await.unwrap().unwrap();
        assert!(first.iter().all(|&byte| byte == 3));
        let g = generation().await;
        under_expected_generation(g, operator.write(path, vec![5u8; large]))
            .await
            .unwrap();
        let mut delivered = first.len();
        let mut ended_in = Ok(());
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(chunk) => {
                    assert!(
                        chunk.iter().all(|&byte| byte == 3),
                        "a chunk of the newer version was mixed in"
                    );
                    delivered += chunk.len();
                }
                Err(error) => {
                    ended_in = Err(error);
                    break;
                }
            }
        }
        assert!(
            ended_in.is_err() || delivered == large,
            "the read neither completed its version nor failed"
        );
        assert_eq!(
            operator.read(path).await.unwrap().to_vec(),
            vec![5u8; large]
        );

        let g = generation().await;
        under_expected_generation(g, operator.delete(path))
            .await
            .unwrap();
        assert!(!operator.exists(path).await.unwrap());
        assert_eq!(staging_objects().await, 0);
    }

    #[tokio::test]
    async fn fetcher_reads_the_condition_from_the_task() {
        let recorder = Recorder::default();
        let fetcher = PreconditionFetcher::new(recorder.clone());

        under_expected_generation(ExpectedGeneration::Known(9), async {
            fetcher
                .fetch(request("DeleteObject", "https://s/b/o/a"))
                .await
                .unwrap();
        })
        .await;
        fetcher
            .fetch(request("DeleteObject", "https://s/b/o/a"))
            .await
            .unwrap();

        under_expected_source_generation(5, async {
            fetcher
                .fetch(request("RewriteObject", "https://s/b/o/a/rewriteTo/b/o/b"))
                .await
                .unwrap();
        })
        .await;

        assert_eq!(
            *recorder.0.lock().unwrap(),
            vec![
                "https://s/b/o/a?ifGenerationMatch=9".to_string(),
                "https://s/b/o/a".to_string(),
                "https://s/b/o/a/rewriteTo/b/o/b?ifSourceGenerationMatch=5".to_string(),
            ]
        );
    }
}
