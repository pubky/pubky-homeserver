use reqwest::Response;

use crate::errors::{Error, RequestError, Result};

const MAX_ERROR_BODY_BYTES: usize = 4096;
const ERROR_BODY_TRUNCATION_SUFFIX: &str = "\n[response body truncated at 4096 bytes]";

/// Return successful responses untouched; capture bounded diagnostics for all
/// other statuses. Oversized error bodies are dropped without draining them.
pub async fn check_http_status(response: Response) -> Result<Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let message = read_error_message(response).await.unwrap_or_else(|_| {
        status
            .canonical_reason()
            .unwrap_or("Unknown Error")
            .to_string()
    });
    Err(Error::from(RequestError::Server { status, message }))
}

async fn read_error_message(response: Response) -> std::result::Result<String, reqwest::Error> {
    use futures_util::StreamExt;

    let mut body = Vec::with_capacity(MAX_ERROR_BODY_BYTES);
    let mut chunks = response.bytes_stream();
    let mut truncated = false;
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        let remaining = MAX_ERROR_BODY_BYTES - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() > remaining {
            truncated = true;
            break;
        }
    }
    // Release the transport (and the browser stream) before constructing the error.
    drop(chunks);

    // Native reqwest without `charset` retains a BOM; browser Response.text()
    // strips it. Preserve those existing target-specific decoding semantics.
    let body = body.as_slice();
    #[cfg(target_arch = "wasm32")]
    let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    let mut message = String::from_utf8_lossy(body).into_owned();
    if truncated {
        message.push_str(ERROR_BODY_TRUNCATION_SUFFIX);
    }
    Ok(message)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod test_server;
