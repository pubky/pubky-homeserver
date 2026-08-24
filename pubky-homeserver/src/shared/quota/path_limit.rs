use super::{GlobPattern, HttpMethod, LimitKey, LimitKeyType, RequestCountQuota};
use serde::{Deserialize, Serialize};
use serde_valid::Validate;
use std::num::NonZeroU32;

/// Make sure all whitelist keys are of the same type as the limit key type.
fn serde_validate_path_limit(limit: &PathLimit) -> Result<(), serde_valid::validation::Error> {
    limit
        .validate()
        .map_err(|e| serde_valid::validation::Error::Custom(e.to_string()))?;
    Ok(())
}

/// A limit on a path for a specific method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Validate)]
#[validate(custom = serde_validate_path_limit)]
pub struct PathLimit {
    /// The path glob pattern to match against.
    pub path: GlobPattern,
    /// The method to limit.
    pub method: HttpMethod,
    /// The request-count quota to apply (e.g. "10r/m").
    pub quota: RequestCountQuota,
    /// The key to limit.
    pub key: LimitKeyType,
    /// The burst to apply.
    pub burst: Option<NonZeroU32>,
    /// The whitelist of keys to limit.
    #[serde(default)]
    pub whitelist: Vec<LimitKey>,
}

impl PathLimit {
    /// Check if the key is whitelisted.
    pub fn is_whitelisted(&self, key: &LimitKey) -> bool {
        self.whitelist.contains(key)
    }

    /// Validate the path limit.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(k) = self.whitelist.iter().find(|k| k.get_type() != self.key) {
            let should_type = self.key.to_string();
            let is_type = k.get_type().to_string();
            anyhow::bail!("Whitelist key type mismatch for '{k}'. Expected type '{should_type}' but got '{is_type}'. Full path limit: {self}");
        }
        Ok(())
    }
}

impl std::fmt::Display for PathLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let burst_str = self
            .burst
            .map(|b| format!(" burst {b}"))
            .unwrap_or_default();
        write!(
            f,
            "{} {}: {}{burst_str} by {}.whitelist: {:?}",
            self.method, self.path, self.quota, self.key, self.whitelist
        )
    }
}

impl TryFrom<PathLimit> for governor::Quota {
    type Error = String;

    fn try_from(value: PathLimit) -> Result<Self, Self::Error> {
        let quota = Self::try_from(value.quota)?;
        let quota = match value.burst {
            Some(burst) => quota.allow_burst(burst),
            None => quota,
        };
        Ok(quota)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
    };

    use axum::http::Method;
    use pubky_common::crypto::Keypair;

    use super::*;

    #[test]
    fn test_validate_path_limit() {
        let mut limit = PathLimit {
            path: GlobPattern::new("*"),
            method: HttpMethod(Method::GET),
            quota: RequestCountQuota::from_str("10r/s").unwrap(),
            key: LimitKeyType::Ip,
            burst: None,
            whitelist: Vec::new(),
        };
        assert!(limit.validate().is_ok());
        limit
            .whitelist
            .push(LimitKey::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(limit.validate().is_ok());
        limit
            .whitelist
            .push(LimitKey::User(Keypair::random().public_key()));
        assert!(limit.validate().is_err());
    }

    #[test]
    fn test_converts_to_governor_quota_with_burst_override() {
        let burst = NonZeroU32::new(3).unwrap();
        let limit = PathLimit {
            path: GlobPattern::new("/session"),
            method: HttpMethod(Method::POST),
            quota: RequestCountQuota::from_str("10r/s").unwrap(),
            key: LimitKeyType::Ip,
            burst: Some(burst),
            whitelist: Vec::new(),
        };

        assert_eq!(
            governor::Quota::try_from(limit).unwrap(),
            governor::Quota::per_second(NonZeroU32::new(10).unwrap()).allow_burst(burst)
        );
    }
}
