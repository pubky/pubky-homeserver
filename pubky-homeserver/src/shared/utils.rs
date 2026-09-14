use axum::{body::Body, http::StatusCode, response::Response};
use pubky_common::timestamp::Timestamp;
use sqlx::types::chrono::{DateTime, Utc};

use crate::constants::{DEFAULT_LIST_LIMIT, DEFAULT_MAX_LIST_LIMIT};

/// Apply the default list limit and cap it at the maximum, preserving explicit zero.
pub(crate) fn effective_list_limit(limit: Option<u16>) -> u16 {
    std::cmp::min(limit.unwrap_or(DEFAULT_LIST_LIMIT), DEFAULT_MAX_LIST_LIMIT)
}

/// Convert a pubky timestamp to a sqlx datetime.
pub fn timestamp_to_sqlx_datetime(timestamp: &Timestamp) -> DateTime<Utc> {
    let micros = timestamp.as_u64();
    let secs = micros / 1_000_000;
    let nanos = (micros % 1_000_000) * 1000;
    DateTime::from_timestamp(secs as i64, nanos as u32)
        .expect("Failed to convert timestamp to sqlx datetime")
}

/// Parse a boolean value from a string.
/// Returns an error if the value is not a valid boolean.
pub fn parse_bool(value: &str) -> Result<bool, Box<Response>> {
    match value.to_lowercase().as_str() {
        "true" => Ok(true),
        "yes" => Ok(true),
        "1" => Ok(true),
        "" => Ok(true),
        "false" => Ok(false),
        "no" => Ok(false),
        "0" => Ok(false),
        _ => Err(Box::new(
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Invalid boolean parameter"))
                .unwrap(),
        )),
    }
}
