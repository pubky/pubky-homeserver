//! Self-contained authentication module.
//!
//! Organized into two sub-modules by auth method:
//! - **cookie**: Deprecated cookie-based authentication (session persistence, routes, auth logic)
//! - **grant**: Grant-based authentication (crypto, persistence, service, routes, auth logic)
//!
//! Shared types:
//! - **session**: [`AuthSession`] enum bridging both auth methods
//! - **middleware**: Authentication layer (Bearer/Cookie) and `AuthSession` extractor
//! - **authorization**: [`has_write_permission`] / [`has_read_permission`] predicates for handlers
//! - **router**: Pre-configured axum routers for base and tenant routes
//! - **state**: Auth-specific sub-state extracted via `FromRef`

pub mod authorization;
pub mod cookie;
pub mod grant;
pub mod middleware;
pub(crate) mod revocation;
mod router;
mod session;
mod signup_service;
mod state;
mod stream_auth;
mod user_error_mapping;

pub use authorization::{has_read_permission, has_write_permission};
pub use middleware::authentication::AuthenticationLayer;

pub use grant::service::GrantAuthService;
pub(crate) use revocation::{AuthRevocation, RevocationListener};
pub use router::{base_router, tenant_router};
pub use session::AuthSession;
pub use signup_service::{SignupService, SignupServiceError};
pub use state::AuthState;
pub(crate) use stream_auth::PendingStreamAuth;
