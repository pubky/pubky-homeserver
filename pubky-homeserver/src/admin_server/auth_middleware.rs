// src/core/layers/admin_auth.rs
use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use futures_util::future::BoxFuture;
use std::{convert::Infallible, task::Poll};
use tower::{Layer, Service};

/// A Tower Layer that checks the “X-Admin-Password” header against a configured password.
#[derive(Clone)]
pub struct AdminAuthLayer {
    password: String,
}

impl AdminAuthLayer {
    /// Create a new AdminAuthLayer with the given admin password.
    pub fn new(password: String) -> Self {
        Self { password }
    }
}

impl<S> Layer<S> for AdminAuthLayer {
    type Service = AdminAuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AdminAuthMiddleware {
            inner,
            password: self.password.clone(),
        }
    }
}

/// Middleware that performs the admin password check.
#[derive(Clone)]
pub struct AdminAuthMiddleware<S> {
    inner: S,
    password: String,
}

impl<S, ReqBody> Service<Request<ReqBody>> for AdminAuthMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let message = match req.headers().get("X-Admin-Password") {
            Some(header_value) if header_value.to_str().unwrap_or_default() == self.password => {
                // Call the same service instance that poll_ready checked.
                return Box::pin(self.inner.call(req));
            }
            Some(_) => "Invalid admin password",
            None => "Missing admin password",
        };
        let mut response = Response::new(Body::from(message));
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        Box::pin(async move { Ok(response) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::test_service::ReadinessRequiredService;
    use axum::body::to_bytes;
    use std::future::Ready;
    use tower::{service_fn, ServiceExt};

    #[tokio::test]
    async fn calls_the_service_instance_that_was_polled_ready() {
        let mut service =
            AdminAuthLayer::new("secret".into()).layer(ReadinessRequiredService::default());
        for _ in 0..2 {
            let request = Request::builder()
                .header("X-Admin-Password", "secret")
                .body(Body::empty())
                .unwrap();
            let response = service.ready().await.unwrap().call(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn rejects_missing_or_incorrect_password_before_calling_inner() {
        let inner = service_fn(|_: Request<Body>| -> Ready<Result<Response, Infallible>> {
            panic!("rejected requests must not reach the inner service");
        });
        let mut service = AdminAuthLayer::new("secret".into()).layer(inner);
        for (password, expected_message) in [
            (None, "Missing admin password"),
            (Some("incorrect"), "Invalid admin password"),
        ] {
            let mut request = Request::builder();
            if let Some(password) = password {
                request = request.header("X-Admin-Password", password);
            }
            let request = request.body(Body::empty()).unwrap();
            let response = service.ready().await.unwrap().call(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(body.as_ref(), expected_message.as_bytes());
        }
    }
}
