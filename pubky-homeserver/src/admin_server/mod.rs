//! Admin control server.
//!
//! Separate HTTP server for operator-only actions: generating
//! signup tokens, enabling/disabling users, and a WebDAV interface for file
//! management. Protected routes require the `X-Admin-Password` header.

mod app;
mod app_state;
mod auth_middleware;
mod routes;
mod trace;

pub use app::{AdminServer, AdminServerBuildError};

/// Extension trait to add the default admin password header to test requests.
#[cfg(test)]
pub(crate) trait AdminAuthExt {
    fn admin_auth(self) -> Self;
}

#[cfg(test)]
impl AdminAuthExt for axum_test::TestRequest {
    fn admin_auth(self) -> Self {
        self.add_header("X-Admin-Password", "admin")
    }
}
