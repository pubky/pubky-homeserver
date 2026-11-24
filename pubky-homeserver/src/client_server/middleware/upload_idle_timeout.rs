//! Limit how long a storage PUT waits for incoming body data.

use std::time::Duration;

use axum::{
    body::Body,
    extract::{MatchedPath, Request},
    http::Method,
};
use futures_util::TryStreamExt;
use tower_http::timeout::TimeoutBody;

use crate::client_server::routes::tenants::{LEGACY_STORAGE_ROUTE, STORAGE_ROUTE};

const UPLOAD_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) fn apply(request: Request) -> Request {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    if request.method() == Method::PUT
        && matches!(route, Some(STORAGE_ROUTE | LEGACY_STORAGE_ROUTE))
    {
        return request.map(timed_body);
    }
    request
}

fn timed_body(body: Body) -> Body {
    // TimeoutBody starts on demand and clears its timer after each frame.
    // Only yield data that counts as progress, or end the stream at EOF.
    let chunks = body.into_data_stream().try_filter_map(async |bytes| {
        if bytes.is_empty() {
            // Let the timer run even through a burst of ready empty frames.
            tokio::task::consume_budget().await;
            return Ok(None);
        }
        Ok(Some(bytes))
    });
    Body::new(TimeoutBody::new(
        UPLOAD_BODY_IDLE_TIMEOUT,
        Body::from_stream(chunks),
    ))
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use axum::body::{to_bytes, Bytes};
    use futures_util::StreamExt;
    use tokio::time::{advance, sleep, Instant};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn empty_frames_do_not_extend_the_deadline() {
        let body = Body::from_stream(async_stream::stream! {
            loop {
                sleep(Duration::from_secs(1)).await;
                yield Ok::<_, Infallible>(Bytes::new());
            }
        });
        let start = Instant::now();
        let result = tokio::time::timeout(
            UPLOAD_BODY_IDLE_TIMEOUT * 2,
            to_bytes(timed_body(body), usize::MAX),
        )
        .await
        .expect("empty frames must not keep the read alive");
        assert!(result.is_err());
        assert_eq!(start.elapsed(), Duration::from_secs(60));
    }

    #[tokio::test(start_paused = true)]
    async fn progress_resets_the_timeout_only_when_the_next_read_starts() {
        let body = Body::from_stream(async_stream::stream! {
            for value in 0..6 {
                sleep(Duration::from_secs(40)).await;
                yield Ok::<_, Infallible>(Bytes::from(vec![value]));
            }
        });
        let mut chunks = timed_body(body).into_data_stream();
        for value in 0..6 {
            // Time before the first read and time spent processing each chunk.
            advance(UPLOAD_BODY_IDLE_TIMEOUT * 2).await;
            assert_eq!(chunks.next().await.unwrap().unwrap()[..], [value]);
        }
        advance(UPLOAD_BODY_IDLE_TIMEOUT * 2).await;
        assert!(chunks.next().await.is_none());
    }
}
