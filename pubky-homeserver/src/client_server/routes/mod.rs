//! HTTP route handlers for the client server.
//!
//! - [`dav`]: Per-user WebDAV endpoint.
//! - [`drive`]: Browser file explorer for a user's drive.
//! - [`events`]: Historical event feed and live SSE stream for file change notifications.
//! - [`info`]: Homeserver feature discovery.
//! - [`root`]: Server info endpoint.
//! - [`signup_tokens`]: Signup token validation.
//! - [`tenants`]: Per-user data routes (read, write).
//!
//! Auth routes (signup, signin, session management) live in [`crate::client_server::auth::routes`].

pub(crate) mod dav;
pub(crate) mod drive;
pub(crate) mod events;
pub(crate) mod info;
pub(crate) mod root;
pub(crate) mod signup_tokens;
pub(crate) mod tenants;
