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

use axum::http::{Request, Response, Uri};
use opendal::raw::{HttpBody, HttpFetch, ServiceOperation};
use opendal::{Buffer, Error, ErrorKind, Result};

use crate::persistence::files::staged_publish_layer::{expected_generation, ExpectedGeneration};

/// Service operations whose request must carry the condition. A batch delete
/// (`BatchDeleteObjects`) cannot: its conditions would have to go into each
/// sub-request inside the body. The staged publish layer flushes deletes one
/// path at a time so that opendal never batches them, and its tests pin that.
const CONDITIONAL_OPERATIONS: [&str; 2] = ["RewriteObject", "DeleteObject"];

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
        let req = with_precondition(req, expected_generation())?;
        self.inner.fetch(req).await
    }
}

/// Put `ifGenerationMatch` on `req` if it is a conditional operation and
/// `expected` asks for a condition.
fn with_precondition(
    mut req: Request<Buffer>,
    expected: Option<ExpectedGeneration>,
) -> Result<Request<Buffer>> {
    let Some(generation) = expected.and_then(ExpectedGeneration::if_generation_match) else {
        return Ok(req);
    };
    let conditional = req
        .extensions()
        .get::<ServiceOperation>()
        .is_some_and(|operation| CONDITIONAL_OPERATIONS.contains(&operation.0));
    if !conditional {
        return Ok(req);
    }
    let uri = req.uri();
    let separator = if uri.query().is_some() { '&' } else { '?' };
    let conditional_uri: Uri = format!("{uri}{separator}ifGenerationMatch={generation}")
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
        )
        .unwrap();
        assert_eq!(
            copy.uri().query(),
            Some("x=1&ifGenerationMatch=42"),
            "a copy under a known generation is conditional on it"
        );

        let delete = with_precondition(request("DeleteObject", "https://s/b/o/a"), absent).unwrap();
        assert_eq!(delete.uri().query(), Some("ifGenerationMatch=0"));

        let upload = with_precondition(
            request("InsertObject", "https://s/upload?uploadType=media"),
            known,
        )
        .unwrap();
        assert_eq!(upload.uri().query(), Some("uploadType=media"));

        let unknown = with_precondition(
            request("RewriteObject", "https://s/b"),
            Some(ExpectedGeneration::Unknown),
        )
        .unwrap();
        assert_eq!(unknown.uri().query(), None);

        let outside = with_precondition(request("RewriteObject", "https://s/b"), None).unwrap();
        assert_eq!(outside.uri().query(), None);
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
    /// `GCS_BUCKET` are set: the staged publish lands files on both sides of
    /// the multipart threshold, and a publish or delete prepared against an
    /// object that has since changed is refused by GCS.
    // Multi-threaded for the cleaner, which deletes the test root on drop.
    #[tokio::test(flavor = "multi_thread")]
    async fn gcs_refuses_a_publish_or_delete_against_a_changed_object() {
        use crate::persistence::files::opendal::opendal_test_operators::OpendalGcpCleaner;
        use crate::persistence::files::staged_publish_layer::StagedPublishLayer;

        let (Ok(bucket), Ok(credentials)) = (
            std::env::var("GCS_BUCKET"),
            std::env::var("GOOGLE_APPLICATION_CREDENTIALS"),
        ) else {
            eprintln!("GCS_BUCKET or GOOGLE_APPLICATION_CREDENTIALS not set; skipping");
            return;
        };
        let builder = opendal::services::Gcs::default()
            .bucket(&bucket)
            .credential_path(&credentials)
            .root(&format!("test_{}", uuid::Uuid::new_v4()));
        let backend = opendal::Operator::new(builder)
            .unwrap()
            .layer(opendal::layers::HttpClientLayer::new(
                opendal::raw::HttpClient::with(PreconditionFetcher::new(reqwest::Client::new())),
            ))
            .finish();
        let _cleaner = OpendalGcpCleaner::new(Some(backend.clone()));
        let operator = backend.clone().layer(StagedPublishLayer);
        let path = "pk/pub/a.bin";

        // Below and above the 5 MiB single-request threshold.
        operator.write(path, vec![1u8; 1024]).await.unwrap();
        assert_eq!(operator.read(path).await.unwrap().len(), 1024);
        let large = 6 * 1024 * 1024;
        operator.write(path, vec![2u8; large]).await.unwrap();
        assert_eq!(operator.read(path).await.unwrap().len(), large);
        let stale: u64 = backend
            .stat(path)
            .await
            .unwrap()
            .version()
            .expect("GCS reports the generation")
            .parse()
            .unwrap();

        // The object changes after a publish and a delete were prepared
        // against it: both are refused and the object is left alone.
        operator.write(path, vec![3u8; 10]).await.unwrap();
        backend.write("pk/staged", vec![4u8; 10]).await.unwrap();
        let late_publish = under_expected_generation(ExpectedGeneration::Known(stale), async {
            backend.copy("pk/staged", path).await
        })
        .await
        .expect_err("a publish against a changed object is refused");
        assert_eq!(late_publish.kind(), ErrorKind::ConditionNotMatch);
        let late_delete = under_expected_generation(ExpectedGeneration::Known(stale), async {
            backend.delete(path).await
        })
        .await
        .expect_err("a delete against a changed object is refused");
        assert_eq!(late_delete.kind(), ErrorKind::ConditionNotMatch);
        assert_eq!(operator.read(path).await.unwrap().to_vec(), vec![3u8; 10]);

        operator.delete(path).await.unwrap();
        assert!(!operator.exists(path).await.unwrap());
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

        assert_eq!(
            *recorder.0.lock().unwrap(),
            vec![
                "https://s/b/o/a?ifGenerationMatch=9".to_string(),
                "https://s/b/o/a".to_string()
            ]
        );
    }
}
