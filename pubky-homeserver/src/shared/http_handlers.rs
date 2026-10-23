use std::future::{ready, Ready};

use axum::{
    http::{header::ALLOW, Method, StatusCode},
    response::{IntoResponse, Response},
};

/// Build a handler that rejects requests and advertises the allowed methods.
pub(crate) fn reject_allow<const N: usize>(
    methods: [Method; N],
) -> impl Fn() -> Ready<Response> + Clone {
    let allow = methods
        .iter()
        .map(Method::as_str)
        .collect::<Vec<_>>()
        .join(", ");

    move || ready((StatusCode::METHOD_NOT_ALLOWED, [(ALLOW, allow.clone())]).into_response())
}
