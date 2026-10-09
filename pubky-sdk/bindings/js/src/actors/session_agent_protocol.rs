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
    // The URL parser accepts `*` in a host, but no browser origin contains one.
    if origin.contains('*') {
        return Err(PubkyError::new(
            PubkyErrorName::InvalidInput,
            format!("Origin `{origin}` must not contain `*`."),
        ));
    }
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

/// An agent allowlist entry: an exact origin, or a wildcard pattern such as
/// `https://*.example.com` that matches every host under `example.com` on
/// that scheme and port, at any depth, but not `example.com` itself. The
/// pattern is checked by validating it with a stand-in label.
pub(crate) fn validate_allowed_origin(entry: &str) -> JsResult<()> {
    let Some((scheme, rest)) = entry.split_once("://*.") else {
        return validate_origin(entry);
    };
    let host = rest.split(':').next().unwrap_or_default();
    if host.is_empty()
        || rest.contains('*')
        || validate_origin(&format!("{scheme}://x.{rest}")).is_err()
    {
        return Err(PubkyError::new(
            PubkyErrorName::InvalidInput,
            format!(
                "Invalid origin pattern `{entry}`: write it as `https://*.example.com`, with a port only if the apps use one."
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_origins_only() {
        for origin in ["https://example.app", "http://localhost:8080"] {
            assert!(validate_origin(origin).is_ok(), "{origin}");
        }
        for origin in [
            "not an origin",
            "https://example.app/",
            "https://example.app/agent",
            "https://example.app:443",
            "HTTPS://example.app",
            "null",
            // No browser origin carries a wildcard; the client's agent origin is exact.
            "https://*.example.app",
        ] {
            assert!(validate_origin(origin).is_err(), "{origin}");
        }
    }

    #[test]
    fn allowlist_entries_may_be_wildcards_in_csp_form() {
        for entry in [
            "https://example.app",
            "https://*.example.app",
            "http://*.localhost:8080",
        ] {
            assert!(validate_allowed_origin(entry).is_ok(), "{entry}");
        }
        for entry in [
            "*.example.app",
            "https://*",
            "https://*.",
            "https://*example.app",
            "https://*.*.example.app",
            "https://a.*.example.app",
            "https://*.example.app/",
            "https://*.example.app:443",
            "https://example.app/",
        ] {
            assert!(validate_allowed_origin(entry).is_err(), "{entry}");
        }
    }
}
