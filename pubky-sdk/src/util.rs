use std::fmt::Write;

use futures_util::StreamExt;
use reqwest::{Response, StatusCode};

use crate::{
    PubkyHttpClient,
    client::core::DEFAULT_MAX_ERROR_BODY_BYTES,
    errors::{Error, RequestError, Result},
};

impl PubkyHttpClient {
    pub(crate) async fn check_http_status(&self, response: Response) -> Result<Response> {
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status();
        let message = if self.max_error_body_bytes == 0 {
            // `bytes_stream()` acquires the browser body reader; dropping the unpolled
            // stream cancels the underlying `ReadableStream`.
            drop(response.bytes_stream());
            None
        } else {
            self.read_error_message(response).await.ok()
        }
        .unwrap_or_else(|| Self::status_reason(status));
        Err(Error::from(RequestError::Server { status, message }))
    }

    fn status_reason(status: StatusCode) -> String {
        status
            .canonical_reason()
            .unwrap_or("Unknown Error")
            .to_owned()
    }

    async fn read_error_message(&self, response: Response) -> reqwest::Result<String> {
        let limit = self.max_error_body_bytes;
        let mut body = Vec::with_capacity(limit.min(DEFAULT_MAX_ERROR_BODY_BYTES));
        let mut chunks = response.bytes_stream();
        let mut truncated = false;
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk?;
            let remaining = limit - body.len();
            body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            if chunk.len() > remaining {
                truncated = true;
                break;
            }
        }
        // Cancel the unread remainder before decoding the captured prefix.
        drop(chunks);

        let body = body.as_slice();
        // Strip a leading UTF-8 BOM on all targets, matching browser Response::text().
        let body = body.strip_prefix("\u{FEFF}".as_bytes()).unwrap_or(body);
        let mut message = String::from_utf8_lossy(body).into_owned();
        if truncated {
            write!(message, "\n[response body truncated at {limit} bytes]")
                .expect("writing to a String cannot fail");
        }
        Ok(message)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
