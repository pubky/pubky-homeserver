//! Legacy **cookie** authentication flow.
//!
//! Deprecated — prefer [`crate::PubkyGrantAuthFlow`] for new applications.
//! Cookie-backed sessions lack the self-refreshing, mirror-friendly properties
//! of grant-backed sessions.

#![allow(
    deprecated,
    reason = "This module implements the deprecated cookie compatibility API"
)]

pub(crate) mod approval;
pub(crate) mod builder;
pub(crate) mod credential;
pub(crate) mod flow;
mod legacy_api;
pub(crate) mod secret;
pub mod view;

pub use credential::CookieCredential;
#[allow(deprecated, reason = "Re-exporting deprecated public API")]
pub use flow::PubkyCookieAuthFlow;
pub use view::CookieSessionView;
