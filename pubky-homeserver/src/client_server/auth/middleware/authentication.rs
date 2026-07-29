//! Composed authentication middleware.
//!
//! The [`AuthenticationLayer`] composes grant and cookie authentication into a
//! single layer. Grant runs first; cookie only activates when no `AuthSession`
//! was inserted by the grant layer. Neither layer rejects — handlers declare
//! their auth requirement via the extractor type (`AuthSession` for strict,
//! `Option<AuthSession>` for lenient).
//!
//! - **Bearer token present and valid** → `AuthSession::Grant` (cookie skipped).
//! - **Bearer token present but invalid** → forwards without identity; cookie
//!   fallback still runs downstream.
//! - **No Bearer, valid cookie** → `AuthSession::Cookie`.
//! - **No credentials** → forwards without an identity.

use crate::client_server::auth::cookie::middleware::{
    CookieAuthenticationLayer, CookieAuthenticationMiddleware,
};
use crate::client_server::auth::grant::middleware::{
    GrantAuthenticationLayer, GrantAuthenticationMiddleware,
};
use crate::client_server::auth::AuthState;
use tower::Layer;

// ── Layer ───────────────────────────────────────────────────────────────────

/// Tower layer that resolves credentials into an [`AuthSession`].
///
/// Composes grant (outer) and cookie (inner) authentication middlewares.
/// Grant runs first on the request path; the cookie middleware only activates
/// when no `AuthSession` was set by the grant layer.
#[derive(Debug, Clone)]
pub struct AuthenticationLayer {
    grant: GrantAuthenticationLayer,
    cookie: CookieAuthenticationLayer,
}

impl AuthenticationLayer {
    pub fn new(state: AuthState) -> Self {
        Self {
            grant: GrantAuthenticationLayer::new(state.clone()),
            cookie: CookieAuthenticationLayer::new(state),
        }
    }
}

impl<S> Layer<S> for AuthenticationLayer {
    type Service = GrantAuthenticationMiddleware<CookieAuthenticationMiddleware<S>>;

    fn layer(&self, inner: S) -> Self::Service {
        // grant wraps cookie wraps inner → Grant runs first on the request path.
        self.grant.layer(self.cookie.layer(inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_context::AppContext;
    use crate::client_server::auth::cookie::persistence::SessionRepository;
    use crate::client_server::auth::AuthSession;
    use crate::client_server::middleware::pubky_host::PubkyHost;
    use crate::persistence::sql::user::UserRepository;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use pubky_common::capabilities::{Capabilities, Capability};
    use pubky_common::crypto::Keypair;
    use std::convert::Infallible;
    use std::sync::Arc;
    use tower::{Service, ServiceExt};
    use tower_cookies::{Cookie, Cookies};

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

    async fn cookie_for_user(context: &AppContext, keypair: &Keypair) -> Cookie<'static> {
        let user = UserRepository::create(&keypair.public_key(), &mut context.sql_db.pool().into())
            .await
            .unwrap();
        let secret = SessionRepository::create(
            user.id,
            &Capabilities::from(vec![Capability::root()]),
            &mut context.sql_db.pool().into(),
        )
        .await
        .unwrap();
        Cookie::new(keypair.public_key().z32(), secret.to_string())
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn no_credentials_forwards_without_auth_session() {
        let (state, _) = test_state().await;
        let svc = AuthenticationLayer::new(state).layer(assert_handler(false));

        let req = Request::builder()
            .uri("/pub/file.txt")
            .body(Body::empty())
            .unwrap();

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn invalid_bearer_falls_through_without_auth() {
        let (state, _) = test_state().await;
        let svc = AuthenticationLayer::new(state).layer(assert_handler(false));

        let pk = Keypair::random().public_key();
        let mut req = Request::builder()
            .uri("/pub/file.txt")
            .header("Authorization", "Bearer not-a-valid-jws")
            .header("Cookie", format!("{}=fakesecret", pk.z32()))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(PubkyHost(pk));

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn invalid_bearer_falls_through_to_user_addressed_cookie() {
        let context = AppContext::test().await;
        let keypair = Keypair::random();
        let state = AuthState::new(&context);
        let svc = AuthenticationLayer::new(state).layer(assert_handler(true));

        let mut req = Request::builder()
            .uri("/pub/file.txt")
            .header("Authorization", "Bearer not-a-valid-jws")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(PubkyHost(keypair.public_key()));
        let cookies = Cookies::default();
        cookies.add(cookie_for_user(&context, &keypair).await);
        req.extensions_mut().insert(cookies);

        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
