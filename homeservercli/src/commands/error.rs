use crate::helpers::errors::ApiError;
use crate::helpers::http_client::http_status;

pub fn map_http(e: anyhow::Error) -> anyhow::Error {
    match http_status(&e) {
        Some(401) => ApiError::InvalidToken.into(),
        _ => e,
    }
}
