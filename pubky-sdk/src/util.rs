use std::fmt::Write;

use futures_util::{StreamExt, TryStreamExt};
use reqwest::{Response, StatusCode};

use crate::{
    PubkyHttpClient,
    client::core::DEFAULT_MAX_ERROR_BODY_BYTES,
    errors::{Error, RequestError, Result},
};

/// Failure to receive a complete response within the caller's byte limit.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResponseBodyError {
    #[error("Response body exceeds the byte limit")]
    TooLarge,
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
}

impl ResponseBodyError {
    /// Convert into the crate error: `too_large` for the limit case, the
    /// transport error's usual conversion otherwise.
    pub(crate) fn into_error<E: Into<Error>>(self, too_large: impl FnOnce() -> E) -> Error {
        match self {
            Self::TooLarge => too_large().into(),
            Self::Transport(error) => error.into(),
        }
    }
}

/// Read a complete response within `max_bytes`, rejecting oversized declarations
/// and enforcing the limit incrementally. Dropping the stream on failure cancels
/// the unread browser `ReadableStream` as well as native response consumption.
pub(crate) async fn read_response_body(
    response: Response,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, ResponseBodyError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        drop(response.bytes_stream());
        return Err(ResponseBodyError::TooLarge);
    }

    let mut body = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.try_next().await? {
        if chunk.len() > max_bytes - body.len() {
            return Err(ResponseBodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Read a JSON response within `max_bytes` and decode it. Oversized and
/// undecodable bodies both report [`RequestError::DecodeJson`], naming `label`.
pub(crate) async fn read_json_body<T: serde::de::DeserializeOwned>(
    response: Response,
    max_bytes: usize,
    label: &str,
) -> Result<T> {
    let body = read_response_body(response, max_bytes)
        .await
        .map_err(|error| {
            error.into_error(|| RequestError::DecodeJson {
                message: format!("{label} exceeds the {max_bytes}-byte limit"),
            })
        })?;
    serde_json::from_slice(&body).map_err(|e| {
        RequestError::DecodeJson {
            message: format!("decoding {label}: {e}"),
        }
        .into()
    })
}

impl PubkyHttpClient {
    pub(crate) async fn check_http_status(
        &self,
        response: reqwest::Response,
    ) -> Result<reqwest::Response> {
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
pub(crate) mod tests;
