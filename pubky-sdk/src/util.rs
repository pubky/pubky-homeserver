use reqwest::Response;

use crate::errors::{Error, RequestError, Result};

/// Convert non-2xx responses into a structured error that includes the server body.
///
/// If the status is successful (2xx), the original response is returned.
/// If the status is an error (4xx or 5xx), the response body is consumed
/// to create a `PubkyError::Request(RequestError::Server)` and returned as an `Err`.
pub async fn check_http_status(response: Response) -> Result<Response> {
    if response.status().is_success() {
        return Ok(response);
    }

    let status = response.status();
    let message = response.text().await.unwrap_or_else(|_| {
        status
            .canonical_reason()
            .unwrap_or("Unknown Error")
            .to_string()
    });

    if status == reqwest::StatusCode::PRECONDITION_FAILED {
        return Err(Error::from(RequestError::PreconditionFailed { message }));
    }
    Err(Error::from(RequestError::Server { status, message }))
}
