//! JWS Compact Serialization parsing.

use std::fmt;

use serde::{Deserialize, Deserializer};

// ── JWS Compact Serialization ────────────────────────────────────────────────

/// A JWS Compact Serialization string (RFC 7515 §7.1).
///
/// Three base64url-encoded segments separated by dots: `header.payload.signature`.
/// Validated on construction to contain exactly three dot-separated parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JwsCompact(String);

impl JwsCompact {
    /// Parse a string into a [`JwsCompact`], validating the three-part structure.
    pub fn parse(s: &str) -> Result<Self, JwsCompactError> {
        if s.splitn(4, '.').count() != 3 {
            return Err(JwsCompactError);
        }
        Ok(Self(s.to_string()))
    }

    /// Returns the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JwsCompact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for JwsCompact {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Error returned when a string is not a valid JWS Compact Serialization.
#[derive(Debug)]
pub struct JwsCompactError;

impl fmt::Display for JwsCompactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JWS Compact Serialization must have exactly 3 dot-separated parts")
    }
}

impl std::error::Error for JwsCompactError {}
