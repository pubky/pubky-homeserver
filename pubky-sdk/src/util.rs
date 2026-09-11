use std::fmt::Write;

use futures_util::StreamExt;
use reqwest::Response;

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
            // Dropping the stream also cancels the browser reader without polling it.
            drop(response.bytes_stream());
            None
        } else {
            self.read_error_message(response).await.ok()
        }
        .unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("Unknown Error")
                .to_owned()
        });
        Err(Error::from(RequestError::Server { status, message }))
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
        drop(chunks);

        // Native reqwest retains a UTF-8 BOM; browser Response.text() strips it.
        let body = body.as_slice();
        #[cfg(target_arch = "wasm32")]
        let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
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
