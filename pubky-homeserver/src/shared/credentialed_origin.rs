use std::fmt::{self, Display};
use std::str::FromStr;
use std::sync::Arc;

use axum::http::HeaderValue;
use serde::{Deserialize, Serialize};
use url::Url;

/// A browser origin trusted to use cookie sessions, configured in
/// `[drive].credentialed_origins`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialedOrigin {
    /// `"*"`: every origin. Development only; never use it on a public homeserver.
    Any,
    /// A serialized `scheme://host[:port]` origin, as browsers send it in `Origin`.
    Origin(String),
}

impl FromStr for CredentialedOrigin {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "*" {
            return Ok(Self::Any);
        }
        let url = Url::parse(s).map_err(|e| anyhow::anyhow!("Invalid origin '{s}': {e}"))?;
        // A `*` inside a host parses as a literal label, so reject it rather
        // than let a wildcard pattern silently match nothing.
        let is_bare_origin = matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some_and(|host| !host.contains('*'))
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none();
        if !is_bare_origin {
            return Err(anyhow::anyhow!(
                "Invalid origin '{s}': expected `http(s)://host[:port]` without a path, query, or credentials"
            ));
        }
        Ok(Self::Origin(url.origin().ascii_serialization()))
    }
}

impl Display for CredentialedOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => write!(f, "*"),
            Self::Origin(origin) => write!(f, "{origin}"),
        }
    }
}

impl Serialize for CredentialedOrigin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CredentialedOrigin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// The configured [`CredentialedOrigin`]s, matched against request `Origin` headers.
#[derive(Debug, Clone, Default)]
pub struct CredentialedOrigins(Arc<[CredentialedOrigin]>);

impl CredentialedOrigins {
    pub fn new(origins: &[CredentialedOrigin]) -> Self {
        Self(origins.into())
    }

    /// Whether a request with this `Origin` header may use cookie credentials.
    pub fn allows(&self, origin: &HeaderValue) -> bool {
        self.0.iter().any(|allowed| match allowed {
            CredentialedOrigin::Any => true,
            CredentialedOrigin::Origin(allowed) => origin.as_bytes() == allowed.as_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes_origins() {
        let cases = [
            ("*", CredentialedOrigin::Any),
            (
                "https://pubky.app",
                CredentialedOrigin::Origin("https://pubky.app".into()),
            ),
            (
                "https://Pubky.App/",
                CredentialedOrigin::Origin("https://pubky.app".into()),
            ),
            (
                "https://pubky.app:443",
                CredentialedOrigin::Origin("https://pubky.app".into()),
            ),
            (
                "http://localhost:3000",
                CredentialedOrigin::Origin("http://localhost:3000".into()),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                CredentialedOrigin::from_str(input).unwrap(),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_values_that_are_not_bare_origins() {
        for input in [
            "",
            "pubky.app",
            "https://*.pubky.app",
            "https://pubky.app/path",
            "https://pubky.app?x=1",
            "https://pubky.app#x",
            "https://user@pubky.app",
            "ftp://pubky.app",
            "null",
        ] {
            assert!(CredentialedOrigin::from_str(input).is_err(), "{input}");
        }
    }

    #[test]
    fn matches_request_origins_exactly() {
        let origins =
            CredentialedOrigins::new(&[CredentialedOrigin::from_str("https://pubky.app").unwrap()]);
        assert!(origins.allows(&HeaderValue::from_static("https://pubky.app")));
        assert!(!origins.allows(&HeaderValue::from_static("http://pubky.app")));
        assert!(!origins.allows(&HeaderValue::from_static("https://pubky.app:8443")));
        assert!(!origins.allows(&HeaderValue::from_static("https://evil.pubky.app")));
        assert!(!origins.allows(&HeaderValue::from_static("null")));

        assert!(
            !CredentialedOrigins::default().allows(&HeaderValue::from_static("https://pubky.app"))
        );

        let any = CredentialedOrigins::new(&[CredentialedOrigin::Any]);
        assert!(any.allows(&HeaderValue::from_static("https://example.com")));
        assert!(any.allows(&HeaderValue::from_static("null")));
    }
}
