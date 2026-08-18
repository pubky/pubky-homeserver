//! Server error
use axum::{http::StatusCode, response::IntoResponse};

use crate::persistence::files::FileIoError;

pub(crate) type HttpResult<T, E = HttpError> = core::result::Result<T, E>;

#[derive(Debug, Clone)]
pub(crate) struct HttpError {
    // #[serde(with = "serde_status_code")]
    status: StatusCode,
    detail: Option<String>,
}

impl Default for HttpError {
    fn default() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            detail: None,
        }
    }
}

impl HttpError {
    /// Create a new [`Error`].
    pub fn new_with_message(status_code: StatusCode, message: impl ToString) -> HttpError {
        Self {
            status: status_code,
            detail: Some(message.to_string()),
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

    pub fn method_not_allowed() -> HttpError {
        Self::new_with_message(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed")
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> axum::response::Response {
        match self.detail {
            Some(detail) => (self.status, detail).into_response(),
            _ => (self.status,).into_response(),
        }
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
            e => Self::internal_server_and_log(format!("FileIoError: {}", e)),
        }
    }
}

impl From<pubky_common::auth::Error> for HttpError {
    fn from(error: pubky_common::auth::Error) -> Self {
        Self::bad_request(error)
    }
}
