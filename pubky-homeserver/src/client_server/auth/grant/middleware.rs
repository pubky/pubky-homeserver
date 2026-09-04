//! Bearer token authentication middleware.
//!
//! The [`GrantAuthenticationLayer`] extracts the opaque Bearer token from the
//! `Authorization` header and asks the `AuthService` to resolve it into a
//! `GrantSession`. On success it inserts an [`AuthSession`] into request extensions.
//! The middleware never rejects — downstream handlers declare their auth
//! requirement via the extractor type (`AuthSession` for strict, `Option<AuthSession>`
//! for lenient).
//!
//! - **Bearer token present and valid** → inserts `AuthSession::Grant`.
//! - **Bearer token present but unknown/expired/revoked** → forwards without an
//!   identity; the downstream extractor emits 401 if the route requires auth.
//! - **No Authorization header** → forwards without an identity.
//! - **Non-Bearer / malformed Authorization header** → forwards without an identity.

use crate::client_server::auth::grant::bearer::{
    extract_bearer_token, BearerTokenExtraction, Scheme,
};
use crate::client_server::auth::{AuthSession, AuthState};
use crate::client_server::routes::dav::DAV_PREFIX;
use axum::{body::Body, http::Request};
use futures_util::future::BoxFuture;
use std::{convert::Infallible, task::Poll};
use tower::{Layer, Service};

// ── Layer ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GrantAuthenticationLayer {
    state: AuthState,
}

impl GrantAuthenticationLayer {
    pub fn new(state: AuthState) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for GrantAuthenticationLayer {
    type Service = GrantAuthenticationMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrantAuthenticationMiddleware {
            inner,
            state: self.state.clone(),
        }
    }
}

// ── Middleware ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GrantAuthenticationMiddleware<S> {
    inner: S,
    state: AuthState,
}

impl<S> Service<Request<Body>> for GrantAuthenticationMiddleware<S>
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

        // `Basic` exists for WebDAV clients, which can send nothing else, so it
        // is honoured only there. Everywhere else a Basic header is somebody
        // else's scheme and must not be read as a session token.
        let webdav = is_webdav_path(req.uri().path());

        Box::pin(async move {
            let bearer = match extract_bearer_token(req.headers()) {
                BearerTokenExtraction::Present(bearer, Scheme::Bearer) => bearer,
                BearerTokenExtraction::Present(bearer, Scheme::Basic) if webdav => bearer,
                BearerTokenExtraction::Present(_, Scheme::Basic) => {
                    tracing::debug!(
                        "Basic credentials outside the WebDAV endpoint; forwarding without auth"
                    );
                    return inner.call(req).await;
                }
                BearerTokenExtraction::Missing => {
                    return inner.call(req).await.map_err(|e| match e {});
                }
                BearerTokenExtraction::InvalidBearer | BearerTokenExtraction::NonBearer => {
                    tracing::debug!(
                        "Authorization header present but not a usable Bearer token; forwarding without auth"
                    );
                    return inner.call(req).await;
                }
            };

            match state
                .grant_auth_service
                .resolve_grant_session_by_bearer(&bearer)
                .await
            {
                Ok(session) => {
                    req.extensions_mut().insert(AuthSession::Grant(session));
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Bearer token did not resolve to a grant session; forwarding without auth"
                    );
                }
            }

            inner.call(req).await.map_err(|e| match e {})
        })
    }
}

/// Whether a request path is served by the WebDAV endpoint.
///
/// Matches the `/dav{*path}` route: `/dav` itself and anything beneath it, but
/// not a sibling like `/davos`.
fn is_webdav_path(path: &str) -> bool {
    path == DAV_PREFIX
        || path
            .strip_prefix(DAV_PREFIX)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webdav_paths_are_recognised_exactly() {
        for path in ["/dav", "/dav/", "/dav/abc/pub/x.txt"] {
            assert!(is_webdav_path(path), "{path} is the WebDAV endpoint");
        }
        // A sibling route must not inherit Basic auth by prefix accident.
        for path in [
            "/davos",
            "/dav-admin",
            "/storage/abc/pub/x",
            "/session",
            "/",
        ] {
            assert!(!is_webdav_path(path), "{path} is not the WebDAV endpoint");
        }
    }

    use crate::app_context::AppContext;
    use crate::client_server::auth::AuthSession;
    use crate::client_server::auth::AuthState;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use pubky_common::crypto::Keypair;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// A 43-char stand-in for a well-formed but unknown bearer (same shape as
    /// what the server mints but never issued → service-layer miss).
    const UNKNOWN_WELL_FORMED_BEARER: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

    /// Any length other than 43 — test wants to probe the parse-layer reject.
    const WRONG_LENGTH_BEARER_LEN: usize = 200;

    async fn test_state() -> (AuthState, Keypair) {
        let context = AppContext::test().await;
        let keypair = context.keypair.clone();
        (AuthState::new(&context), keypair)
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
    async fn no_auth_header_forwards_without_session() {
        let (state, _) = test_state().await;
        let svc = GrantAuthenticationLayer::new(state).layer(assert_handler(false));

        let req = Request::builder()
            .uri("/pub/file.txt")
            .body(Body::empty())
            .unwrap();

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn unknown_bearer_forwards_without_session() {
        let (state, _) = test_state().await;
        let svc = GrantAuthenticationLayer::new(state).layer(assert_handler(false));

        let req = Request::builder()
            .uri("/pub/file.txt")
            .header(
                "Authorization",
                format!("Bearer {UNKNOWN_WELL_FORMED_BEARER}"),
            )
            .body(Body::empty())
            .unwrap();

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn wrong_length_bearer_forwards_without_session() {
        let (state, _) = test_state().await;
        let svc = GrantAuthenticationLayer::new(state).layer(assert_handler(false));

        let huge = "a".repeat(WRONG_LENGTH_BEARER_LEN);
        let req = Request::builder()
            .uri("/pub/file.txt")
            .header("Authorization", format!("Bearer {huge}"))
            .body(Body::empty())
            .unwrap();

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn basic_auth_header_forwards_without_session() {
        let (state, _) = test_state().await;
        let svc = GrantAuthenticationLayer::new(state).layer(assert_handler(false));

        let req = Request::builder()
            .uri("/pub/file.txt")
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
