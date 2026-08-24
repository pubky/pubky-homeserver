//! Body stream bandwidth throttling.
//!
//! Wraps request and response bodies in a throttled stream that uses
//! governor to enforce per-key bandwidth limits in kilobyte granularity.

use std::num::NonZero;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use futures_util::StreamExt;
use governor::Jitter;

use crate::shared::quota::LimitKey;

use super::limiter_pool::KeyedRateLimiter;

/// Wrap the request body in a bandwidth-throttled stream.
pub(super) fn throttle_request(
    req: Request<Body>,
    key: &LimitKey,
    limiter: &Arc<KeyedRateLimiter>,
) -> Request<Body> {
    let (parts, body) = req.into_parts();
    Request::from_parts(parts, throttle_body(body, key, limiter))
}

/// Wrap the response body in a bandwidth-throttled stream.
pub(super) fn throttle_response(
    res: Response<Body>,
    key: &LimitKey,
    limiter: &Arc<KeyedRateLimiter>,
) -> Response<Body> {
    let (parts, body) = res.into_parts();
    Response::from_parts(parts, throttle_body(body, key, limiter))
}

/// Throttle a body stream.
///
/// Important: The speed quotas are always in kilobytes, not bytes.
/// Counting bytes is not practical.
fn throttle_body(body: Body, key: &LimitKey, limiter: &Arc<KeyedRateLimiter>) -> Body {
    let body_stream = body.into_data_stream();
    let limiter = limiter.clone();
    let key = key.clone();
    let throttled = body_stream
        .map(move |chunk| {
            let limiter = limiter.clone();
            let key = key.clone();
            // When the rate limit is exceeded, we wait between 25ms and 500ms before retrying.
            // This is to avoid overwhelming the server with requests when the rate limit is exceeded.
            // Randomization is used to avoid thundering herd problem.
            let jitter = Jitter::new(Duration::from_millis(25), Duration::from_millis(500));
            async move {
                let bytes = match chunk {
                    Ok(actual_chunk) => actual_chunk,
                    Err(e) => return Err(e),
                };

                // --- Round up to the nearest kilobyte. ---
                // Important: If the chunk is < 1KB, it will be rounded up to 1 kb.
                // Many small uploads will be counted as more than they actually are.
                // I am not too concerned about this though because small random disk writes are stressing
                // the disk more anyway compared to larger writes.
                // Why are we doing this? governor::Quota is defined as a u32. u32 can only count up to 4GB.
                // To support 4GB/s+ limits we need to count in kilobytes.
                //
                // --- Chunk Size ---
                // The chunk size is determined by the client library.
                // Common chunk sizes: 16KB to 10MB.
                // HTTP based uploads are usually between 256KB and 1MB.
                // Asking the limiter for 1KB packets is tradeoff between
                // - Not calling the limiter too much
                // - Guaranteeing the call size (1kb) is low enough to not cause race condition issues.
                let chunk_kilobytes = bytes.len().div_ceil(1024);
                for _ in 0..chunk_kilobytes {
                    // Check each kilobyte
                    if limiter
                        .until_key_n_ready_with_jitter(
                            &key,
                            NonZero::new(1).expect("1 is always non zero"),
                            jitter,
                        )
                        .await
                        .is_err()
                    {
                        // Requested rate (1 KB) exceeds the configured limit.
                        // This should not happen in practice since limits are in KB.
                        tracing::error!(
                            "Rate limiter rejected a 1 KB cell — limit may be misconfigured"
                        );
                        return Err(axum::Error::new("Rate limit exceeded"));
                    };
                }
                Ok(bytes)
            }
        })
        .buffered(1);

    Body::from_stream(throttled)
}
