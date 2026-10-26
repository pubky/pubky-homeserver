//! Account response types.
//!
//! The shape returned by the client `GET /account` route and by the admin
//! `GET /users` routes. The homeserver serializes it from its own quota types;
//! the SDK deserializes it. Both are pinned to this definition by tests.

use serde::{Deserialize, Serialize};

use crate::{crypto::PublicKey, StoragePath};

/// A user's account as the homeserver reports it.
///
/// # JSON representation
/// ```json
/// {
///   "pubky": "o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo",
///   "created_at": "2026-10-22T11:03:41.120394",
///   "disabled": false,
///   "used_bytes": 134217728,
///   "quota": {
///     "effective": { "storage_quota_mb": 500, "rate_read": "100mb/m", "rate_write": "unlimited" },
///     "overrides": { "storage_quota_mb": 500, "rate_read": "100mb/m" }
///   }
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountInfo {
    /// The user this account belongs to.
    pub pubky: PublicKey,
    /// When the user signed up, as an ISO 8601 date and time without a UTC
    /// offset (e.g. `2026-10-22T10:11:12.123456`).
    pub created_at: String,
    /// Whether the account is disabled. Disabled accounts can read and delete
    /// but not write.
    pub disabled: bool,
    /// Bytes of storage currently used.
    pub used_bytes: u64,
    /// The quota that applies and the per-user overrides behind it.
    pub quota: AccountQuota,
}

/// A user's quota, both as it applies and as it was customised.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AccountQuota {
    /// Overrides merged with the homeserver's defaults. `storage_quota_mb`,
    /// `rate_read` and `rate_write` are always present, as unlimited when the
    /// homeserver has no default either. The burst fields and
    /// `allowed_write_paths` have no system default and stay absent unless
    /// set for the user.
    pub effective: QuotaLimits,
    /// Only the per-user overrides. Limits using the system default are absent.
    pub overrides: QuotaLimits,
}

/// The individual limits of a quota. In `overrides`, an absent limit means
/// "system default". In `effective`, the three rate and storage limits are
/// always present; the rest are absent when nothing applies.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct QuotaLimits {
    /// Storage quota in megabytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_quota_mb: Option<QuotaLimit<u64>>,
    /// Read bandwidth limit, e.g. `"100mb/m"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_read: Option<QuotaLimit<String>>,
    /// Write bandwidth limit, e.g. `"50mb/s"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_write: Option<QuotaLimit<String>>,
    /// Burst allowance for reads, in the rate's unit. Absent means burst equals rate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_read_burst: Option<u32>,
    /// Burst allowance for writes, in the rate's unit. Absent means burst equals rate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_write_burst: Option<u32>,
    /// Path prefixes the user may write to. Absent means unrestricted; an
    /// empty list means read-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_write_paths: Option<Vec<StoragePath>>,
}

/// An explicitly set limit: either no limit at all, or a value.
///
/// Serializes as the string `"unlimited"` or as the bare value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuotaLimit<T> {
    /// No limit.
    Unlimited,
    /// An explicit limit.
    Value(T),
}

impl<T: Serialize> Serialize for QuotaLimit<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            QuotaLimit::Unlimited => serializer.serialize_str("unlimited"),
            QuotaLimit::Value(value) => value.serialize(serializer),
        }
    }
}

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for QuotaLimit<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::String(s) if s == "unlimited" => Ok(QuotaLimit::Unlimited),
            other => serde_json::from_value(other)
                .map(QuotaLimit::Value)
                .map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn account_info_json_roundtrip() {
        let info = AccountInfo {
            pubky: Keypair::random().public_key(),
            created_at: "2026-10-22T11:03:41.120394".to_string(),
            disabled: false,
            used_bytes: 134_217_728,
            quota: AccountQuota {
                effective: QuotaLimits {
                    storage_quota_mb: Some(QuotaLimit::Value(500)),
                    rate_read: Some(QuotaLimit::Value("100mb/m".to_string())),
                    rate_write: Some(QuotaLimit::Unlimited),
                    rate_read_burst: Some(50),
                    rate_write_burst: None,
                    allowed_write_paths: Some(vec![StoragePath::new("/pub/tokens/").unwrap()]),
                },
                overrides: QuotaLimits {
                    storage_quota_mb: Some(QuotaLimit::Value(500)),
                    ..Default::default()
                },
            },
        };

        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["quota"]["effective"]["rate_write"], "unlimited");
        assert_eq!(json["quota"]["effective"]["storage_quota_mb"], 500);
        assert!(json["quota"]["overrides"].get("rate_read").is_none());
        assert_eq!(
            json["quota"]["effective"]["allowed_write_paths"][0],
            "/pub/tokens/"
        );

        let parsed: AccountInfo = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, info);
    }

    #[test]
    fn quota_limit_rejects_other_strings() {
        assert!(serde_json::from_str::<QuotaLimit<u64>>("\"lots\"").is_err());
        assert_eq!(
            serde_json::from_str::<QuotaLimit<u64>>("\"unlimited\"").unwrap(),
            QuotaLimit::Unlimited
        );
        assert_eq!(
            serde_json::from_str::<QuotaLimit<u64>>("7").unwrap(),
            QuotaLimit::Value(7)
        );
    }
}
