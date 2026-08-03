//! Cookie-based authentication middleware.
//!
//! The [`CookieAuthenticationLayer`] tries to authenticate via deprecated
//! session cookies. It only activates when no [`AuthSession`] has been set
//! by a prior middleware (e.g. grant).
//!
//! - **AuthSession already present** → skips (grant took priority).
//! - **Valid cookie** → inserts `AuthSession::Cookie`.
//! - **No cookies or invalid cookie** → forwards without an identity (never rejects).

use crate::client_server::auth::AuthSession;
use crate::client_server::auth::AuthState;
use crate::client_server::middleware::request_tenant::RequestTenant;
use axum::{body::Body, http::Request};
use futures_util::future::BoxFuture;
use pubky_common::crypto::PublicKey;
use std::{convert::Infallible, task::Poll};
use tower::{Layer, Service};
use tower_cookies::Cookies;

/// Extracts the session secret from the cookie and looks up the session in the database.
/// Returns `Some(AuthSession::Cookie)` on success, or `None` if the cookie is missing/invalid.
async fn extract_session_from_cookie(
    state: &AuthState,
    cookies: &Cookies,
    public_key: &PublicKey,
) -> Option<AuthSession> {
    let cookie_value = cookies
        .get(&public_key.z32())
        .map(|c| c.value().to_string());

    state
        .cookie_auth_service
        .resolve_session_from_cookie(cookie_value, public_key)
        .await
}

// ── Layer ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CookieAuthenticationLayer {
    state: AuthState,
}

impl CookieAuthenticationLayer {
    pub fn new(state: AuthState) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for CookieAuthenticationLayer {
    type Service = CookieAuthenticationMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CookieAuthenticationMiddleware {
            inner,
            state: self.state.clone(),
        }
    }
}

// ── Middleware ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CookieAuthenticationMiddleware<S> {
    inner: S,
    state: AuthState,
}

impl<S> Service<Request<Body>> for CookieAuthenticationMiddleware<S>
where
    S: Service<Request<Body>, Response = axum::response::Response, Error = Infallible>
        + Send
        + 'static
        + Clone,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(|e| match e {})
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let state = self.state.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            if req.extensions().get::<AuthSession>().is_some() {
                // Prior middleware already authenticated the request. No need to check cookies.
                return inner.call(req).await.map_err(|e| match e {});
            }

            let cookies = match req.extensions().get::<Cookies>().cloned() {
                Some(cookies) => cookies,
                None => {
                    tracing::trace!(
                        "No cookies found in request extensions. Skip cookie authentication."
                    );
                    return inner.call(req).await.map_err(|e| match e {});
                }
            };
            let tenant = match req.extensions().get::<RequestTenant>().cloned() {
                Some(tenant) => tenant,
                None => {
                    tracing::trace!(
                        "No request tenant found in request extensions. Skip cookie authentication."
                    );
                    return inner.call(req).await.map_err(|e| match e {});
                }
            };

            if let Some(session) =
                extract_session_from_cookie(&state, &cookies, tenant.public_key()).await
            {
                req.extensions_mut().insert(session);
            }

            inner.call(req).await.map_err(|e| match e {})
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_context::AppContext;
    use crate::client_server::auth::AuthSession;
    use crate::client_server::auth::AuthState;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use pubky_common::crypto::Keypair;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn create_auth_state() -> AuthState {
        let context = AppContext::test().await;
        AuthState::new(&context)
    }

    fn assert_handler(
        expect_auth: bool,
    ) -> impl Service<
        Request<Body>,
        Response = axum::response::Response,
        Error = Infallible,
        Future = impl Send,
    > + Clone {
        let expect_auth = Arc::new(expect_auth);
        tower::service_fn(move |req: Request<Body>| {
            let expect_auth = expect_auth.clone();
            async move {
                let has_auth = req.extensions().get::<AuthSession>().is_some();
                assert_eq!(
                    has_auth, *expect_auth,
                    "AuthSession presence mismatch: expected={}, actual={}",
                    *expect_auth, has_auth
                );
                Ok::<_, Infallible>(StatusCode::OK.into_response())
            }
        })
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn no_cookies_forwards_without_auth() {
        let state = create_auth_state().await;
        let svc = CookieAuthenticationLayer::new(state).layer(assert_handler(false));

        let req = Request::builder()
            .uri("/pub/file.txt")
            .body(Body::empty())
            .unwrap();

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn cookie_with_no_pubky_host_forwards_without_auth() {
        let state = create_auth_state().await;
        let svc = CookieAuthenticationLayer::new(state).layer(assert_handler(false));

        let req = Request::builder()
            .uri("/session")
            .header("Cookie", "somekey=somevalue")
            .body(Body::empty())
            .unwrap();

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn cookie_with_unknown_session_secret_forwards_without_auth() {
        let state = create_auth_state().await;
        let svc = CookieAuthenticationLayer::new(state).layer(assert_handler(false));

        let pk = Keypair::random().public_key();
        let mut req = Request::builder()
            .uri("/session")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(RequestTenant::legacy(pk.clone()));
        let cookies = tower_cookies::Cookies::default();
        cookies.add(tower_cookies::Cookie::new(
            pk.z32(),
            "nonexistent-secret-value",
        ));
        req.extensions_mut().insert(cookies);

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
