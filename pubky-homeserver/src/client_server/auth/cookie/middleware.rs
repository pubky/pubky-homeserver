//! Cookie-based authentication middleware.
//!
//! The [`CookieAuthenticationLayer`] tries to authenticate via deprecated
//! session cookies. It only activates when no [`AuthSession`] has been set
//! by a prior middleware (e.g. grant).
//!
//! - **AuthSession already present** → skips (grant took priority).
//! - **Bearer token presented, even an invalid one** → skips (no cookie fallback).
//! - **Browser request from an origin outside `drive.credentialed_origins`** → skips.
//! - **Valid cookie** → inserts `AuthSession::Cookie`.
//! - **No cookies or invalid cookie** → forwards without an identity (never rejects).

use crate::client_server::auth::grant::bearer::extract_bearer_token;
use crate::client_server::auth::AuthSession;
use crate::client_server::auth::AuthState;
use crate::client_server::middleware::request_tenant::RequestTenant;
use crate::shared::CredentialedOrigins;
use axum::{
    body::Body,
    http::{header, HeaderName, Request},
};
use futures_util::future::BoxFuture;
use pubky_common::crypto::PublicKey;
use std::{convert::Infallible, task::Poll};
use tower::{Layer, Service};
use tower_cookies::Cookies;

const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

/// Whether a cookie may authenticate this request.
///
/// A browser request from another origin must come from a configured
/// credentialed origin. That covers reads too: browsers attach `Origin` to
/// cross-origin `fetch` requests, whose responses scripts can read.
/// Requests without `Origin` are navigations, no-cors subresources, or
/// non-browser clients such as native apps; only their state-changing
/// browser requests (flagged by `Sec-Fetch-Site`) are refused.
fn cookie_allowed_for_request(req: &Request<Body>, origins: &CredentialedOrigins) -> bool {
    let headers = req.headers();
    let fetch_site = headers.get(SEC_FETCH_SITE).map(|value| value.as_bytes());
    if matches!(fetch_site, Some(b"same-origin" | b"none")) {
        return true;
    }
    match headers.get(header::ORIGIN) {
        Some(origin) => origins.allows(origin),
        None => req.method().is_safe() || fetch_site.is_none(),
    }
}

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

            if extract_bearer_token(req.headers()).has_bearer_scheme() {
                tracing::trace!("Bearer token presented. Skip cookie authentication.");
                return inner.call(req).await.map_err(|e| match e {});
            }

            if !cookie_allowed_for_request(&req, &state.credentialed_origins) {
                tracing::debug!(
                    method = %req.method(),
                    "Browser request from an origin not in drive.credentialed_origins. Skip cookie authentication."
                );
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

    #[test]
    fn cookie_requests_are_limited_to_trusted_origins() {
        use crate::shared::CredentialedOrigin;
        use std::str::FromStr;

        const TRUSTED: &str = "https://app.example";
        const OTHER: &str = "https://other.example";
        let trusted = CredentialedOrigins::new(&[CredentialedOrigin::from_str(TRUSTED).unwrap()]);
        let cases: &[(&str, Option<&str>, Option<&str>, bool)] = &[
            // Scripts on other origins could read these responses.
            ("GET", Some(OTHER), Some("cross-site"), false),
            ("HEAD", Some(OTHER), None, false),
            ("GET", Some(TRUSTED), Some("same-site"), true),
            // Navigations and no-cors subresources cannot be read cross-origin.
            ("GET", None, Some("cross-site"), true),
            // Native clients send no browser fetch metadata.
            ("GET", None, None, true),
            ("PUT", None, None, true),
            ("PUT", None, Some("same-origin"), true),
            // Pages served by the homeserver itself.
            (
                "DELETE",
                Some("https://hs.example"),
                Some("same-origin"),
                true,
            ),
            ("PUT", Some(TRUSTED), Some("same-site"), true),
            ("PUT", Some(TRUSTED), None, true),
            ("PUT", Some(OTHER), Some("cross-site"), false),
            ("DELETE", Some(OTHER), None, false),
            ("POST", Some("null"), Some("cross-site"), false),
            ("PUT", None, Some("cross-site"), false),
            ("LOCK", Some(OTHER), Some("same-site"), false),
        ];
        for (method, origin, fetch_site, expected) in cases {
            let mut builder = Request::builder().method(*method).uri("/pub/file.txt");
            if let Some(origin) = origin {
                builder = builder.header(header::ORIGIN, *origin);
            }
            if let Some(fetch_site) = fetch_site {
                builder = builder.header(SEC_FETCH_SITE, *fetch_site);
            }
            let req = builder.body(Body::empty()).unwrap();
            assert_eq!(
                cookie_allowed_for_request(&req, &trusted),
                *expected,
                "{method} origin={origin:?} sec-fetch-site={fetch_site:?}"
            );
        }
    }
}
