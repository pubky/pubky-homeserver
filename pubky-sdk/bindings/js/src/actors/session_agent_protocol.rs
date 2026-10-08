//! Types shared by the session agent host and client.
//!
//! The wire protocol itself is documented in `docs/sso-agent.md`.

use serde::{Deserialize, Serialize};
use tsify::Tsify;

use crate::js_error::{JsResult, PubkyError, PubkyErrorName};

/// Protocol version both sides must agree on.
pub(crate) const PROTOCOL_VERSION: u32 = 1;

/// What the agent tells a connected app about its session.
#[derive(Tsify, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AgentState {
    /// A session covering the app's capabilities is available.
    SignedIn,
    /// Nobody is signed in on the agent; the app should show the frame.
    SignedOut,
    /// The session does not cover the capabilities the app asked for.
    InsufficientScope,
    /// The agent cannot persist a session in this browser context.
    Unavailable,
}

/// Public session metadata the agent shares with apps.
#[derive(Tsify, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentSessionInfo {
    /// User public key, z-base-32.
    pub pubky: String,
    /// Capabilities the session holds.
    pub capabilities: Vec<String>,
    /// Homeserver public key, z-base-32.
    pub homeserver: String,
}

/// A status message from the agent.
#[derive(Tsify, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatus {
    /// Current state.
    pub state: AgentState,
    /// Session metadata, present while `signed-in`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub info: Option<AgentSessionInfo>,
}

/// Origins must match `event.origin` exactly, so accept nothing but the
/// serialized origin form (no path, no trailing slash, no default port).
pub(crate) fn validate_origin(origin: &str) -> JsResult<()> {
    let serialized = url::Url::parse(origin)
        .map(|url| url.origin().ascii_serialization())
        .map_err(|error| {
            PubkyError::new(
                PubkyErrorName::InvalidInput,
                format!("Invalid origin `{origin}`: {error}"),
            )
        })?;
    if serialized != origin {
        return Err(PubkyError::new(
            PubkyErrorName::InvalidInput,
            format!("Origin `{origin}` must be written as `{serialized}`."),
        ));
    }
    Ok(())
}
