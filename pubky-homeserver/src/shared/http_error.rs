//! Server error
use axum::{
    http::{header::RETRY_AFTER, StatusCode},
    response::IntoResponse,
};

use crate::persistence::files::FileIoError;

pub(crate) type HttpResult<T, E = HttpError> = core::result::Result<T, E>;

/// `Retry-After` of a request the storage backend throttled. The usual cause is
/// the mutation limit of object stores, about one write per second to one object.
const BACKEND_RATE_LIMIT_RETRY_AFTER_SECS: u64 = 1;

#[derive(Debug, Clone)]
pub(crate) struct HttpError {
    // #[serde(with = "serde_status_code")]
    status: StatusCode,
    detail: Option<String>,
    retry_after_secs: Option<u64>,
}

impl Default for HttpError {
    fn default() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            detail: None,
            retry_after_secs: None,
        }
    }
}

impl HttpError {
    /// Create a new [`Error`].
    pub fn new_with_message(status_code: StatusCode, message: impl ToString) -> HttpError {
        Self {
            status: status_code,
            detail: Some(message.to_string()),
            retry_after_secs: None,
        }
    }

    pub fn not_found() -> HttpError {
        Self::new_with_message(StatusCode::NOT_FOUND, "Not Found")
    }

    pub fn internal_server() -> HttpError {
        Self::new_with_message(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
    }

    /// Logs the message as a tracing::error! and returns an internal server error.
    pub fn internal_server_and_log(message: impl std::fmt::Display) -> HttpError {
        tracing::error!("Internal Server Error: {}", message);
        Self::internal_server()
    }

    pub fn bad_request(message: impl ToString) -> HttpError {
        Self::new_with_message(StatusCode::BAD_REQUEST, message)
    }

    pub fn insufficient_storage() -> HttpError {
        Self::new_with_message(
            StatusCode::INSUFFICIENT_STORAGE,
            "Disk space quota exceeded",
        )
    }

    pub fn forbidden_with_message(message: impl ToString) -> HttpError {
        Self::new_with_message(StatusCode::FORBIDDEN, message)
    }

    pub fn unauthorized() -> HttpError {
        Self::new_with_message(StatusCode::UNAUTHORIZED, "Unauthorized")
    }

    pub fn unauthorized_with_message(message: impl ToString) -> HttpError {
        Self::new_with_message(StatusCode::UNAUTHORIZED, message)
    }

    pub fn conflict(message: impl ToString) -> HttpError {
        Self::new_with_message(StatusCode::CONFLICT, message)
    }

    pub fn locked() -> HttpError {
        Self::new_with_message(StatusCode::LOCKED, "Resource is locked")
    }

    /// A change under the lock is still being published. The lock stays the
    /// caller's; the request can be repeated once the change has landed.
    pub fn lock_busy(retry_after_secs: u64) -> HttpError {
        Self {
            retry_after_secs: Some(retry_after_secs),
            ..Self::new_with_message(
                StatusCode::LOCKED,
                "A change under this lock is still being published; retry later",
            )
        }
    }

    pub fn lock_token_mismatch() -> HttpError {
        Self::new_with_message(
            StatusCode::PRECONDITION_FAILED,
            "The If header does not name the live lock on this path",
        )
    }

    pub fn too_many_requests(message: impl ToString, retry_after_secs: u64) -> HttpError {
        Self {
            retry_after_secs: Some(retry_after_secs),
            ..Self::new_with_message(StatusCode::TOO_MANY_REQUESTS, message)
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> axum::response::Response {
        let mut response = match self.detail {
            Some(detail) => (self.status, detail).into_response(),
            _ => (self.status,).into_response(),
        };
        if let Some(retry_after_secs) = self.retry_after_secs {
            response
                .headers_mut()
                .insert(RETRY_AFTER, retry_after_secs.into());
        }
        response
    }
}

// === INTERNAL_SERVER_ERROR ===
// Very common errors that we can just convert to a Internal Server Error.
// This way, we can use `?` to propagate errors without having to handle them.

impl From<std::io::Error> for HttpError {
    fn from(error: std::io::Error) -> Self {
        Self::internal_server_and_log(format!("IO error: {}", error))
    }
}

// SQLX errors
impl From<sqlx::Error> for HttpError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!("SQLX error: {}", error);
        Self::internal_server()
    }
}

// Anyhow errors
impl From<anyhow::Error> for HttpError {
    fn from(error: anyhow::Error) -> Self {
        Self::internal_server_and_log(format!("Anyhow error: {}", error))
    }
}

impl From<axum::Error> for HttpError {
    fn from(error: axum::Error) -> Self {
        Self::internal_server_and_log(format!("Axum error: {}", error))
    }
}

impl From<axum::http::Error> for HttpError {
    fn from(error: axum::http::Error) -> Self {
        Self::internal_server_and_log(format!("Axum HTTP error: {}", error))
    }
}

impl From<FileIoError> for HttpError {
    fn from(error: FileIoError) -> Self {
        match error {
            FileIoError::NotFound => Self::not_found(),
            FileIoError::DiskSpaceQuotaExceeded => Self::insufficient_storage(),
            FileIoError::WritePathForbidden => {
                Self::forbidden_with_message("Write to this path is not allowed")
            }
            FileIoError::PathCollision => {
                Self::new_with_message(StatusCode::CONFLICT, "File/folder path collision")
            }
            FileIoError::StreamBroken(_) => Self::bad_request("Stream broken"),
            FileIoError::BackendRateLimited(error) => {
                tracing::warn!(%error, "Storage backend rate limited");
                // Reads and deletes are throttled too, so the message names no operation.
                Self::too_many_requests(
                    "Storage backend is rate limited, retry later",
                    BACKEND_RATE_LIMIT_RETRY_AFTER_SECS,
                )
            }
            // The same answer a stale token gets up front: the client learns
            // its lock is gone rather than seeing its write silently land.
            FileIoError::LockLost => Self::lock_token_mismatch(),
            FileIoError::LockBusy { retry_after_secs } => Self::lock_busy(retry_after_secs),
            e => Self::internal_server_and_log(format!("FileIoError: {}", e)),
        }
    }
}

impl From<pubky_common::auth::Error> for HttpError {
    fn from(error: pubky_common::auth::Error) -> Self {
        Self::bad_request(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An object store throttles rapid mutations of one object, which is what
    /// concurrent writes to one path look like. The client must learn that it
    /// can retry, not that the server broke.
    #[test]
    fn backend_rate_limit_is_a_retryable_429() {
        let throttled = opendal::Error::new(
            opendal::ErrorKind::RateLimited,
            "object mutation rate limit exceeded",
        )
        .set_temporary();

        let response = HttpError::from(FileIoError::from(throttled)).into_response();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[RETRY_AFTER], "1");
    }
}
