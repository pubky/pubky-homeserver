//! The session credential port.
//!
//! A credential is the per-identity material that authenticates one user
//! against one homeserver. The SDK supports two credential types:
//!
//! - **Grant** ([`crate::actors::auth::grant::GrantCredential`]) — the default.
//!   Long-lived user-signed grant + short-lived homeserver-minted access
//!   opaque bearer, refreshed transparently.
//! - **Cookie** ([`crate::actors::auth::cookie::CookieCredential`]) —
//!   legacy flow. A single opaque secret returned by `POST /session` and
//!   replayed via the `Cookie` header.
//!
//! [`SessionCredential`] is the port (Clean Architecture sense). All
//! session-aware code (`PubkySession`, `SessionStorage`) talks to the
//! trait and never matches on a credential variant. The concrete adapters
//! live alongside their respective auth flows under `actors/auth/`.
//!
//! ## Why a trait, not an enum
//!
//! The previous design held a `Credential` enum and had `match` arms in
//! every method on `PubkySession` and `SessionStorage`. Adding a third
//! credential shape (or — more importantly — *removing* the cookie one)
//! meant editing every match. With a trait, those call sites become single
//! virtual dispatches and removing cookies becomes a one-folder deletion.

use std::any::Any;
use std::fmt::Debug;

use async_trait::async_trait;
use pubky_common::crypto::PublicKey;

use super::SessionInfo;
use reqwest::{RequestBuilder, Response, StatusCode};

use crate::{PubkyHttpClient, errors::Result};

/// Shared `revalidate` helper: a `404` or `401` from the homeserver means
/// the credential is gone (revoked / expired), not a transport failure.
pub(crate) fn credential_session_missing(response: &Response) -> bool {
    matches!(
        response.status(),
        StatusCode::NOT_FOUND | StatusCode::UNAUTHORIZED
    )
}

/// Behavior shared by every session credential type.
///
/// Implementations live alongside their auth protocol:
/// - [`crate::actors::auth::grant::GrantCredential`] — grant (default)
/// - [`crate::actors::auth::cookie::CookieCredential`] — legacy cookie flow
///
/// On native targets the boxed futures are `Send` so the trait is usable
/// behind `Arc<dyn SessionCredential>` from multi-threaded async runtimes.
/// On WASM (`wasm32`) the `?Send` variant is used because the browser event
/// loop is single-threaded and the underlying types contain `Rc`/`RefCell`.
///
// `async-trait` defaults to boxing futures as `Pin<Box<dyn Future + Send>>`,
// which doesn't compile on `wasm32-unknown-unknown` because the JS/WASM
// futures from `wasm-bindgen-futures` hold `Rc<RefCell<…>>` and aren't
// `Send`. The `?Send` variant drops that bound for WASM only; native keeps
// the `Send` bound so tokio's multi-threaded runtime stays happy.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub(crate) trait SessionCredential: Debug + Send + Sync {
    /// Session metadata. Cheap clone; never blocks on network or refresh state.
    fn info(&self) -> SessionInfo;

    /// Sign out and invalidate this credential server-side.
    ///
    /// Each implementation knows its own session resource on the homeserver
    /// (cookie: `/session`; grant: `/auth/grant/session`) and the exact wire
    /// shape needed to delete it. Mirrors [`Self::revalidate`] in being a
    /// full operation rather than exposing a fragment of one.
    async fn signout(&self, client: &PubkyHttpClient) -> Result<()>;

    /// Attach this credential's authentication to an in-flight request.
    ///
    /// grant implementations may proactively refresh the bearer token here.
    /// Cookie implementations attach a `Cookie` header (or rely on the
    /// browser jar on WASM).
    async fn attach(&self, rb: RequestBuilder, client: &PubkyHttpClient) -> Result<RequestBuilder>;

    /// Whether this credential may be attached to a request targeting
    /// `homeserver`.
    async fn can_attach_to(&self, homeserver: &PublicKey) -> bool;

    /// Round-trip the homeserver to verify this credential is still valid.
    ///
    /// Returns:
    /// - `Ok(Some(info))` — server recognised the credential.
    /// - `Ok(None)` — credential is gone (revoked / expired).
    /// - `Err(_)` — transport / server error unrelated to validity.
    async fn revalidate(
        &self,
        client: &PubkyHttpClient,
        user: &PublicKey,
    ) -> Result<Option<SessionInfo>>;

    /// Type-erased accessor for downcasting to a concrete credential. Each
    /// impl returns `self`; callers use [`Any::downcast_ref`] to recover the
    /// concrete type. This keeps the trait ignorant of concrete credential
    /// types, so new adapters can be added without editing the port.
    fn as_any(&self) -> &dyn Any;
}
