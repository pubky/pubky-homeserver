//! Grant-based session response types.
//!
//! These types represent the response from `POST /auth/grant/session` and grant management
//! endpoints when using grant-based authentication. Shared between homeserver
//! (serializes) and SDK (deserializes).

use serde::{Deserialize, Serialize};

use crate::{
    auth::jws::{ClientId, GrantId},
    capabilities::Capability,
    crypto::PublicKey,
};

/// Response from `POST /session` for grant-based authentication.
///
/// # JSON representation
/// ```json
/// {
///   "token": "base64url-encoded-random-bearer",
///   "session": { ... }
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantSessionResponse {
    /// The opaque bearer token.
    pub token: String,
    /// Session metadata.
    pub session: GrantSessionInfo,
}

/// How a grant was authorized.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    /// Signed by the user and exchanged for storage sessions.
    #[default]
    Direct,
    /// Signed by the user to authorize child grants. It has no storage sessions.
    Parent,
    /// Signed by a parent grant's key and exchanged for storage sessions.
    Child,
}

impl GrantKind {
    /// The wire and database name of this kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Parent => "parent",
            Self::Child => "child",
        }
    }
}

/// Summary of an active grant returned by `GET /auth/grant/sessions`.
///
/// Used by Ring's session management UI to show all authorized apps for a user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantInfo {
    /// Grant identifier (revocation target).
    pub grant_id: GrantId,
    /// Application identifier: a domain string, or a child grant's exact callback URL.
    pub client_id: String,
    /// Capabilities this grant authorizes, formatted as a comma-separated string.
    pub capabilities: String,
    /// Issued-at timestamp (Unix seconds).
    pub issued_at: u64,
    /// Expiry timestamp (Unix seconds).
    pub expires_at: u64,
    /// How the grant was authorized. Older homeservers omit it for direct grants.
    #[serde(default)]
    pub kind: GrantKind,
    /// The parent grant of a child grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<GrantId>,
}

/// Session metadata returned alongside the bearer.
///
/// Timestamps are Unix seconds (not microseconds).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantSessionInfo {
    /// Homeserver that issued this session.
    pub homeserver: PublicKey,
    /// User this session belongs to.
    pub pubky: PublicKey,
    /// Application identifier.
    pub client_id: ClientId,
    /// Authorized capabilities for this session.
    pub capabilities: Vec<Capability>,
    /// Grant ID this session was minted from.
    pub grant_id: GrantId,
    /// When the bearer token expires (Unix seconds).
    pub token_expires_at: u64,
    /// When the underlying Grant expires (Unix seconds).
    pub grant_expires_at: u64,
    /// When this session was created (Unix seconds).
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use crate::crypto::Keypair;

    use super::*;

    #[test]
    fn grant_session_response_serde_roundtrip() {
        let hs_kp = Keypair::random();
        let user_kp = Keypair::random();

        let response = GrantSessionResponse {
            token: "eyJhbGciOiJFZERTQSIs.payload.signature".to_string(),
            session: GrantSessionInfo {
                homeserver: hs_kp.public_key(),
                pubky: user_kp.public_key(),
                client_id: ClientId::new("franky.pubky.app").unwrap(),
                capabilities: vec![Capability::root()],
                grant_id: GrantId::generate(),
                token_expires_at: 1700003600,
                grant_expires_at: 1763136000,
                created_at: 1700000000,
            },
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: GrantSessionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(response, parsed);
    }

    #[test]
    fn grant_info_without_kind_is_direct() {
        let info: GrantInfo = serde_json::from_value(serde_json::json!({
            "grant_id": "grant",
            "client_id": "franky.pubky.app",
            "capabilities": "/:rw",
            "issued_at": 1,
            "expires_at": 2,
        }))
        .unwrap();

        assert_eq!(info.kind, GrantKind::Direct);
        assert_eq!(info.parent_id, None);
    }
}
