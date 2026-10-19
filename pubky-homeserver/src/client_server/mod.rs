//! Main data-serving HTTP server.
//!
//! Listens on two sockets: plain HTTP (ICANN) and
//! TLS using the server's Ed25519 keypair.
//! Routes are organized into server-level endpoints and per-tenant endpoints.

mod app;
pub(crate) mod app_state;
pub(crate) mod auth;
pub(crate) mod cache_policy;
mod middleware;
mod query_params;
pub(crate) mod routes;

pub use app::create_app;
pub use app::{ClientServer, ClientServerBuildError};
pub(crate) use app_state::AppState;
