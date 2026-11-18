use std::{
    convert::Infallible,
    future::{ready, Ready},
    task::{Context, Poll},
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::IntoResponse,
};
use tower::Service;

/// Test service that rejects calls unless this instance was polled ready.
#[derive(Default)]
pub(crate) struct ReadinessRequiredService {
    ready: bool,
}

impl Clone for ReadinessRequiredService {
    fn clone(&self) -> Self {
        // Readiness belongs to the instance, not its clones.
        Self::default()
    }
}

impl Service<Request<Body>> for ReadinessRequiredService {
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.ready = true;
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        assert!(self.ready, "service called without polling readiness");
        self.ready = false;
        ready(Ok(StatusCode::OK.into_response()))
    }
}
