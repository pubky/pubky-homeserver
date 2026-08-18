use crate::commands::admin::error as admin_error;
use crate::helpers::errors::ApiError;
use crate::helpers::http_client::http_status;

pub fn map_http(e: anyhow::Error) -> anyhow::Error {
    match http_status(&e) {
        Some(422) => ApiError::InvalidQuotaFormat.into(),
        _ => admin_error::map_http(e),
    }
}
