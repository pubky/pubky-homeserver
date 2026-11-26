//! Compatibility with existing cookie sessions.

#![allow(
    deprecated,
    reason = "This module implements the deprecated cookie compatibility API"
)]

pub(crate) mod credential;
mod legacy_api;
pub(crate) mod secret;
pub mod view;

pub use credential::CookieCredential;
pub use view::CookieSessionView;
