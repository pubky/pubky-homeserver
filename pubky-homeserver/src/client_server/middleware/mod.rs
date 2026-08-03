//! Request middleware for the client server.
//!
//! - [`request_tenant`]: Resolves path-addressed and legacy request tenants.
//! - [`pubky_host`]: Compatibility resolver for legacy tenant addressing.
//! - [`rate_limiter`]: Configurable per-path request rate limiting, keyed by IP or user,
//!   with optional per-user speed overrides resolved from DB.
//! - [`trace`]: Request/response logging via `tracing`.
//!
//! Authentication and authorization middleware live in [`crate::client_server::auth::middleware`].

pub mod pubky_host;
pub mod rate_limiter;
pub mod request_tenant;
pub mod trace;
