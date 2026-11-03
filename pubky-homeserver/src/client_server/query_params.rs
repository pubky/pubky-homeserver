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

        let cursor = params
            .get("cursor")
            .filter(|value| !value.is_empty())
            .cloned();

        Ok(ListQueryParams {
            shallow,
            limit,
            cursor,
            reverse,
        })
    }
}
