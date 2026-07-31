#![doc = include_str!("../README.md")]
#![warn(unused_crate_dependencies)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "workspace dependencies still require distinct versions"
)]
#![cfg_attr(
    target_arch = "wasm32",
    allow(clippy::future_not_send, reason = "WASM futures are single-threaded")
)]

mod pubky;

mod actors;
mod client;
pub mod errors;
mod macros;

mod util;

pub mod prelude;

// --- PUBLIC API EXPORTS ---
// SDK facade
#[doc(inline)]
pub use pubky::Pubky;
// Transport
#[doc(inline)]
pub use client::core::{PubkyHttpClient, PubkyHttpClientBuilder};
// High level actors
#[doc(inline)]
pub use actors::AuthFlowKind;
#[doc(inline)]
pub use actors::Pkdns;
#[doc(inline)]
#[allow(deprecated, reason = "Re-exporting deprecated public API")]
pub use actors::PubkyCookieAuthFlow;
#[doc(inline)]
pub use actors::PubkySession;
#[doc(inline)]
pub use actors::PubkySigner;
#[doc(inline)]
pub use actors::SessionInfo;
#[doc(inline)]
pub use actors::deep_links;
#[doc(inline)]
pub use actors::{
    CookieCredential, CookieSessionView, DelegatedGrantCredentialState, GrantCredential,
    GrantManager, GrantSessionView,
};
#[doc(inline)]
pub use actors::{DelegatedGrantAuthFlowState, GrantAuthFlowState, PubkyGrantAuthFlow};
#[doc(inline)]
pub use actors::{Event, EventCursor, EventStreamBuilder, EventType};
#[doc(inline)]
pub use actors::{PublicStorage, SessionStorage};

// Error and global client
#[doc(inline)]
pub use errors::{BuildError, Error, Result};

// Export common types and constants
#[doc(inline)]
pub use crate::actors::storage::{
    list::ListBuilder,
    resource::{IntoPubkyResource, IntoResourcePath, resolve_pubky},
    resource::{PubkyResource, ResourcePath},
    stats::ResourceStats,
};
#[doc(inline)]
#[allow(
    deprecated,
    reason = "Re-exporting deprecated public API for backwards compat"
)]
pub use actors::DEFAULT_HTTP_RELAY;
pub use actors::pkdns::DEFAULT_STALE_AFTER;
#[doc(inline)]
pub use actors::{DEFAULT_HTTP_RELAY_INBOX, EncryptedHttpRelayInboxChannel, HttpRelayInboxChannel};
#[doc(hidden)]
pub use actors::{DelegatedSignFn, delegated_sign_callback};
#[doc(inline)]
pub use pkarr;

// Re-exports
#[doc(inline)]
pub use pubky_common::{
    StoragePath, StoragePathError,
    auth::{
        AuthToken,
        grant::GrantClaims,
        grant_session_responses::{GrantInfo, GrantSessionInfo, GrantSessionResponse},
        jws::{ClientId, GRANT_JWS_TYP, GrantId, POP_JWS_TYP, PopNonce},
        pop::PopProofClaims,
    },
    capabilities::{Capabilities, Capability},
    crypto::{Keypair, PublicKey},
    recovery_file,
    session::CookieSessionRecord,
};
pub use reqwest::{Method, StatusCode};

#[cfg(test)]
use pubky_testnet as _; // Used in docstring tests.
