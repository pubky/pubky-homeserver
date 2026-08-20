use std::fmt::{self, Display};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Validated domain name according to RFC 1123.
#[derive(Debug, Clone, PartialEq)]
pub struct Domain(pub String);

impl Domain {
    /// Create a new domain from a string.
    pub fn new(domain: String) -> Result<Self, anyhow::Error> {
        Self::is_valid_domain(&domain)?;
        Ok(Self(domain))
    }

    /// Validate a domain name according to RFC 1123
    pub fn is_valid_domain(domain: &str) -> anyhow::Result<()> {
        // Check if it's a valid hostname according to RFC 1123
        if !hostname_validator::is_valid(domain) {
            return Err(anyhow::anyhow!(
                "Invalid domain '{}': is not a valid RFC 1123 hostname",
                domain
            ));
        }
        Ok(())
    }
}

impl Default for Domain {
    fn default() -> Self {
        Self("localhost".to_string())
    }
}

impl FromStr for Domain {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::is_valid_domain(s)?;
        Ok(Self(s.to_string()))
    }
}

impl Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Domain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Domain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_validation() {
        // Test valid domains
        let valid_domains = [
            "example.com",
            "sub.example.com",
            "a.b.c.d",
            "valid-domain.com",
            "valid.domain-name.com",
            "localhost",
            "test.local",
        ];

        for domain in valid_domains {
            let result: anyhow::Result<Domain> = domain.parse();
            assert!(result.is_ok(), "Domain '{}' should be valid", domain);
        }

        // Test invalid domains
        let invalid_domains = [
            ("invalid@domain.com", "contains invalid characters"),
            ("domain..com", "contains consecutive dots"),
            (".domain.com", "starts with a dot"),
            ("domain.com.", "ends with a dot"),
            ("-domain.com", "starts with a hyphen"),
            ("domain.com-", "ends with a hyphen"),
        ];

        for (domain, reason) in invalid_domains {
            let result: anyhow::Result<Domain> = domain.parse();
            assert!(
                result.is_err(),
                "Domain '{}' should be invalid: {}",
                domain,
                reason
            );
        }
    }
}
