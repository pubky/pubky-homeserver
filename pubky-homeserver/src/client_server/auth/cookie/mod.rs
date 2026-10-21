//! Deprecated cookie-based session authentication.
//!
//! This is the legacy authentication flow, superseded by grant bearer auth (see [`super::grant`]).
//! It authenticates requests by matching a session cookie against the `sessions` database table.
//!
//! # How it works
//!
//! ## Signup / Signin
//!
//! 1. The client sends a signed [`AuthToken`](pubky_common::auth::AuthToken) in the request body.
//! 2. The server verifies the token signature and extracts the client's public key.
//! 3. For signup: a new user row is created (rejected with 409 if the user already exists).
//!    For signin: the user must already exist.
//! 4. A session secret is generated — 16 random bytes encoded as a 26-character
//!    base32 (Crockford) string — and stored in the `sessions` table.
//! 5. A cookie is set on the response:
//!    - **Name**: the user's public key in z32 format (`pubkey.z32()`).
//!    - **Value**: the session secret.
//!    - **Max-Age**: 365 days, `HttpOnly`.
//!    - **SameSite**: `drive.session_cookie_same_site` (default `Lax`).
//!    - **Secure**: enabled when the host is a pkarr key or FQDN;
//!      disabled for localhost / plain IP (development).
//!
//! ## Authenticating subsequent requests
//!
//! The [`CookieAuthenticationMiddleware`](middleware::CookieAuthenticationMiddleware) runs
//! as a Tower layer on every request. It:
//!
//! 1. Skips if an [`AuthSession`](super::session::AuthSession) was already set by the
//!    grant middleware, or if the request presents any Bearer token (Bearer tokens
//!    take priority and never fall back to cookies).
//! 2. Skips browser requests from an origin that is neither the homeserver itself
//!    nor listed in `drive.credentialed_origins`.
//! 3. Reads the cookie whose name matches the request's public key.
//! 4. Looks up the secret in the `sessions` table and verifies the owning user matches.
//! 5. On success, inserts `AuthSession::Cookie` into the request extensions so downstream
//!    handlers can access the authenticated session.
//!
//! ## Signout
//!
//! Deletes the session row from the database and sends a removal cookie.

pub mod middleware;
pub mod persistence;
pub mod routes;
pub(crate) mod service;
pub(crate) mod verifier;
