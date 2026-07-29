use std::collections::HashMap;

use axum::{
    extract::{FromRequestParts, Query},
    http::request::Parts,
    response::{IntoResponse, Response},
    RequestPartsExt,
};

use crate::shared::parse_bool;

#[derive(Debug, Clone)]
pub struct ListQueryParams {
    pub limit: Option<u16>,
    pub cursor: Option<String>,
    pub shallow: bool,
    pub reverse: bool,
}

impl ListQueryParams {
    /// Extracts the cursor from the query parameters.
    /// If the cursor is not a valid EntryPath, returns None.
    /// If the cursor is empty, returns None.
    pub fn extract_cursor(params: &Query<HashMap<String, String>>) -> Option<String> {
        let value = params.get("cursor")?;
        if value.is_empty() {
            // Treat `cursor=` as None
            return None;
        }

        let mut value = value.as_str();
        if let Some(stripped_value) = value.strip_prefix("pubky://") {
            value = stripped_value;
        }
        Some(value.to_string())
    }
}

impl<S> FromRequestParts<S> for ListQueryParams
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let params: Query<HashMap<String, String>> =
            parts.extract().await.map_err(IntoResponse::into_response)?;

        let reverse = if let Some(reverse) = params.get("reverse") {
            parse_bool(reverse).map_err(|e| *e)?
        } else {
            false
        };

        let shallow = if let Some(shallow) = params.get("shallow") {
            parse_bool(shallow).map_err(|e| *e)?
        } else {
            false
        };

        let limit = params
            .get("limit")
            // Treat `limit=` as None
            .filter(|&l| !l.is_empty())
            .and_then(|l| l.parse::<u16>().ok());
        let cursor = Self::extract_cursor(&params);

        Ok(ListQueryParams {
            shallow,
            limit,
            cursor,
            reverse,
        })
    }
}
