//! Same-site session agent: one grant session shared across first-party origins.
//!
//! The *agent* is a page on a dedicated origin (for example `auth.example.app`)
//! that owns a grant session through `browserSessionStore`. Apps embed it in a
//! hidden iframe and connect over `postMessage`; the agent answers only origins
//! on its allowlist and hands out the current bearer, never the grant or the
//! `PoP` key. Browsers do not partition storage for a same-site frame, so every
//! first-party origin sees the agent's one stored session.
//!
//! The Rust core owns the credential logic ([`pubky::RemoteBearerCredential`]
//! and [`pubky::GrantSessionView::bearer_for_remote`]). This module is the
//! browser transport for it:
//!
//! - [`transport`]: the `postMessage` handshake and request channel (JS).
//! - [`client`]: the app side, a [`pubky::RemoteBearerProvider`] over that channel.
//! - [`server`]: the agent side, answering requests from a served session.

mod client;
mod server;
mod transport;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tsify::Tsify;
use wasm_bindgen::JsValue;

use crate::js_error::js_error_message;

pub(crate) use client::connect;
pub use server::SessionAgent;
pub(crate) use server::serve;

/// Options for connecting to a session agent.
#[derive(Tsify, Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct SessionAgentOptions {
    /// How long to wait for the agent frame to answer, in milliseconds.
    /// Defaults to 5000.
    #[tsify(optional, type = "number | null")]
    pub(crate) timeout_ms: Option<f64>,
}

/// Requests an app may send once the handshake succeeded.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum AgentMethod {
    /// Current bearer and session metadata, or `null` without a session.
    Session,
    /// A bearer valid now; see [`BearerParams`].
    Bearer,
    /// Sign the served session out, revoking the grant.
    Signout,
}

/// Parameters of [`AgentMethod::Bearer`].
#[derive(Serialize, Deserialize, Debug, Default)]
struct BearerParams {
    /// Bearer the homeserver refused, so the agent exchanges only if it still
    /// holds that one.
    rejected: Option<String>,
}

/// Failure on the agent channel, as the credential layer reports it.
fn agent_failure(message: impl Into<String>) -> pubky::Error {
    pubky::errors::AuthError::Validation(message.into()).into()
}

fn agent_error(value: JsValue) -> pubky::Error {
    agent_failure(js_error_message(&value, "Session agent request failed."))
}

fn encode<T: Serialize>(value: &T) -> pubky::Result<JsValue> {
    serde_wasm_bindgen::to_value(value)
        .map_err(|error| agent_failure(format!("Invalid session agent message: {error}")))
}

fn decode<T: DeserializeOwned>(value: JsValue) -> pubky::Result<T> {
    serde_wasm_bindgen::from_value(value)
        .map_err(|error| agent_failure(format!("Invalid session agent message: {error}")))
}
