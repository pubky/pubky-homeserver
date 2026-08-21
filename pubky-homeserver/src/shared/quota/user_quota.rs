//! Per-user quota domain types.
//!
//! These types model the per-user overrides for storage and bandwidth limits.
//! They are shared across the codebase: persistence entities use them to
//! convert raw DB columns into typed values, the service layer uses them for
//! enforcement and caching, and route handlers use them for API serialization.
//!
//! Key types:
//! - [`QuotaOverride<T>`] — three-state enum: Default / Unlimited / Value(T).
//! - [`UserQuota`] — the full set of per-user quota fields.
//! - [`UserQuotaPatch`] — partial update for PATCH semantics (absent = keep).

use std::num::NonZeroU32;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{BandwidthQuota, DefaultQuotasToml};
use crate::shared::webdav::StoragePath;

/// Maximum length of the VARCHAR column used for rate strings in the DB.
/// Matches the `VARCHAR(32)` used in the `m20260327_add_quota_columns` migration.
pub const MAX_RATE_COLUMN_LEN: usize = 32;

/// Sentinel value stored in BIGINT columns to represent "Unlimited".
const DB_UNLIMITED_SENTINEL: i32 = -1;

/// A three-state override for per-user quota fields.
///
/// Semantics:
/// - `Default`   — no override; the system-wide default applies.
/// - `Unlimited` — explicitly bypass the limit for this user.
/// - `Value(T)`  — a custom limit for this user.
///
/// ## JSON encoding
///
/// | JSON | Variant |
/// |---|---|
/// | field absent | `Default` (use system default) |
/// | `null` | `Default` (use system default) |
/// | `"unlimited"` | `Unlimited` (no limit) |
/// | value | `Value(T)` (custom limit) |
///
/// ## DB encoding
///
/// | Variant | Integer columns | VARCHAR columns |
/// |---|---|---|
/// | `Default` | `NULL` | `NULL` |
/// | `Unlimited` | `-1` | `"unlimited"` |
/// | `Value(T)` | positive value | rate string |
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum QuotaOverride<T> {
    /// No override — the system-wide default applies.
    #[default]
    Default,
    /// Explicitly bypass the limit for this user.
    Unlimited,
    /// A custom limit for this user.
    Value(T),
}

impl<T> QuotaOverride<T> {
    /// Returns `true` if the field is `Default`.
    pub fn is_default(&self) -> bool {
        matches!(self, QuotaOverride::Default)
    }

    /// Returns `true` if the field is `Unlimited`.
    #[cfg(test)]
    pub fn is_unlimited(&self) -> bool {
        matches!(self, QuotaOverride::Unlimited)
    }

    /// Returns the inner value if `Value(t)`, else `None`.
    #[cfg(test)]
    pub fn as_value(&self) -> Option<&T> {
        match self {
            QuotaOverride::Value(v) => Some(v),
            _ => None,
        }
    }
}

/// Serialize: Default → null, Unlimited → "unlimited", Value → T.
///
/// In the context of `UserQuota`, `Default` fields are skipped entirely
/// (via `skip_serializing_if`), so the null serialization of `Default`
/// only appears if `QuotaOverride` is serialized standalone.
impl<T: Serialize> Serialize for QuotaOverride<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            QuotaOverride::Default => serializer.serialize_none(),
            QuotaOverride::Unlimited => serializer.serialize_str("unlimited"),
            QuotaOverride::Value(v) => v.serialize(serializer),
        }
    }
}

/// Deserialize: null → Default, "unlimited" → Unlimited, value → Value(T).
///
/// Uses `serde_json::Value` as an intermediate to distinguish between
/// null, the string "unlimited", and other values.
impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for QuotaOverride<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        match &value {
            serde_json::Value::Null => Ok(QuotaOverride::Default),
            serde_json::Value::String(s) if s == "unlimited" => Ok(QuotaOverride::Unlimited),
            _ => serde_json::from_value(value)
                .map(QuotaOverride::Value)
                .map_err(serde::de::Error::custom),
        }
    }
}

impl QuotaOverride<u64> {
    /// Encode to DB INTEGER column: Default → NULL, Unlimited → -1, Value → positive.
    pub fn to_db_int(&self) -> Option<i32> {
        match self {
            QuotaOverride::Default => None,
            QuotaOverride::Unlimited => Some(DB_UNLIMITED_SENTINEL),
            QuotaOverride::Value(v) => Some(i32::try_from(*v).unwrap_or(i32::MAX)),
        }
    }

    /// Decode from DB INTEGER column: NULL → Default, -1 → Unlimited, positive → Value.
    pub fn from_db_int(column: &str, val: Option<i32>) -> Self {
        match val {
            None => QuotaOverride::Default,
            Some(DB_UNLIMITED_SENTINEL) => QuotaOverride::Unlimited,
            Some(v) if v >= 0 => QuotaOverride::Value(v as u64),
            Some(v) => {
                tracing::warn!("Unexpected {column} ({v}) in DB; treating as Default");
                QuotaOverride::Default
            }
        }
    }

    /// Resolve to an effective `Option<u64>` using a system default.
    ///
    /// - `Default` → `system_default`
    /// - `Unlimited` → `None`
    /// - `Value(v)` → `Some(v)`
    pub fn resolve_with_default(&self, system_default: Option<u64>) -> Option<u64> {
        match self {
            QuotaOverride::Default => system_default,
            QuotaOverride::Unlimited => None,
            QuotaOverride::Value(v) => Some(*v),
        }
    }
}

impl QuotaOverride<BandwidthQuota> {
    /// Resolve to an effective `Option<BandwidthQuota>` using a system default.
    ///
    /// - `Default`   → `system_default`
    /// - `Unlimited` → `None`
    /// - `Value(v)`  → `Some(v)`
    pub fn resolve_with_default(
        &self,
        system_default: Option<&BandwidthQuota>,
    ) -> Option<BandwidthQuota> {
        match self {
            QuotaOverride::Default => system_default.cloned(),
            QuotaOverride::Unlimited => None,
            QuotaOverride::Value(v) => Some(v.clone()),
        }
    }

    /// Encode to DB VARCHAR column: Default → NULL, Unlimited → "unlimited", Value → rate string.
    pub fn to_db_varchar(&self) -> Option<String> {
        match self {
            QuotaOverride::Default => None,
            QuotaOverride::Unlimited => Some("unlimited".to_string()),
            QuotaOverride::Value(v) => Some(v.to_string()),
        }
    }

    /// Decode from DB VARCHAR column: NULL → Default, "unlimited" → Unlimited, value → Value.
    pub fn from_db_varchar(column: &str, val: Option<String>) -> Self {
        match val {
            None => QuotaOverride::Default,
            Some(s) if s == "unlimited" => QuotaOverride::Unlimited,
            Some(s) => match s.parse() {
                Ok(rate) => QuotaOverride::Value(rate),
                Err(e) => {
                    tracing::warn!("Invalid {column} \"{s}\" in DB: {e}; treating as Default");
                    QuotaOverride::Default
                }
            },
        }
    }
}

/// Convert an `Option<NonZeroU32>` burst value to the DB column type (`INTEGER`),
/// truncating to `i32::MAX` with a warning if the value overflows.
fn burst_to_i32(label: &str, value: Option<NonZeroU32>) -> Option<i32> {
    value.map(|v| {
        let v = v.get();
        i32::try_from(v).unwrap_or_else(|_| {
            tracing::warn!("{label} {v} exceeds i32::MAX, truncating to {}", i32::MAX);
            i32::MAX
        })
    })
}

/// Validate that a `BandwidthQuota` value can be persisted: its string form
/// must fit the DB column and parse back to the same rate.
fn validate_rate_value(label: &str, field: &QuotaOverride<BandwidthQuota>) -> Result<(), String> {
    if let QuotaOverride::Value(ref b) = field {
        let s = b.to_string();
        if s.len() > MAX_RATE_COLUMN_LEN {
            return Err(format!(
                "{label} string \"{s}\" exceeds DB column limit of {MAX_RATE_COLUMN_LEN} characters"
            ));
        }
        s.parse::<BandwidthQuota>()
            .map_err(|e| format!("{label} roundtrip validation failed for \"{s}\": {e}"))?;
    }
    Ok(())
}

/// Validate that a burst value (if present) fits in the DB column (i32).
fn validate_burst_value(label: &str, burst: Option<NonZeroU32>) -> Result<(), String> {
    if let Some(b) = burst {
        if b.get() > i32::MAX as u32 {
            return Err(format!("{label} value {b} exceeds maximum ({})", i32::MAX));
        }
    }
    Ok(())
}

/// Validate a burst field that also requires a corresponding rate `Value`.
fn validate_burst(
    label: &str,
    burst: Option<NonZeroU32>,
    rate: &QuotaOverride<BandwidthQuota>,
) -> Result<(), String> {
    if burst.is_some() && !matches!(rate, QuotaOverride::Value(_)) {
        return Err(format!(
            "{label} requires the corresponding rate to be set to a value"
        ));
    }
    validate_burst_value(label, burst)
}

/// Validate that allowed_write_paths entries are well-formed path restrictions.
///
/// Each `StoragePath` is already normalized and validated by serde deserialization.
/// This checks the remaining domain constraints: not root, no duplicates.
///
/// Entries can be either directories (ending with `/`) for prefix matching,
/// or specific files for exact-path matching.
fn validate_allowed_write_paths(paths: &Option<Vec<StoragePath>>) -> Result<(), String> {
    if let Some(ref entries) = paths {
        let mut seen = std::collections::HashSet::new();
        for (i, p) in entries.iter().enumerate() {
            if p.as_str() == "/" {
                return Err(format!(
                    "allowed_write_paths[{i}] must not be '/'; use null for unrestricted access"
                ));
            }
            if !seen.insert(p) {
                return Err(format!("allowed_write_paths[{i}] is a duplicate: \"{p}\""));
            }
        }
    }
    Ok(())
}

/// Per-user quotas. Most fields use the three-state `QuotaOverride<T>`.
///
/// | Field | Default means | Example Value |
/// |---|---|---|
/// | `storage_quota_mb` | use `storage.default_quota_mb` from config | `Value(500)` = 500 MB |
/// | `rate_read` | use `default_quotas.rate_read` from config | `Value(BandwidthQuota)` |
/// | `rate_write` | use `default_quotas.rate_write` from config | `Value(BandwidthQuota)` |
/// | `rate_read_burst` | burst = rate | `Some(50)` = 50 in rate's unit |
/// | `rate_write_burst` | burst = rate | `Some(50)` = 50 in rate's unit |
/// | `allowed_write_paths` | unrestricted | `Some(vec!["/pub/tokens/"])` |
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UserQuota {
    /// Storage quota in MB.
    #[serde(default, skip_serializing_if = "QuotaOverride::is_default")]
    pub storage_quota_mb: QuotaOverride<u64>,
    /// Per-user read speed limit override (e.g. "10mb/s").
    #[serde(default, skip_serializing_if = "QuotaOverride::is_default")]
    pub rate_read: QuotaOverride<BandwidthQuota>,
    /// Per-user write speed limit override (e.g. "5mb/s").
    #[serde(default, skip_serializing_if = "QuotaOverride::is_default")]
    pub rate_write: QuotaOverride<BandwidthQuota>,
    /// Burst override for read speed limit, in the rate's natural unit
    /// (MB for "…mb/s", KB for "…kb/s"). `None` = burst equals rate (default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_read_burst: Option<NonZeroU32>,
    /// Burst override for write speed limit, in the rate's natural unit
    /// (MB for "…mb/s", KB for "…kb/s"). `None` = burst equals rate (default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_write_burst: Option<NonZeroU32>,
    /// Restrict which paths a user can write to.
    /// - `None` = unrestricted (all paths allowed) — default
    /// - `Some([])` = read-only (no writes allowed)
    /// - `Some(["/pub/tokens/", "/pub/paykit/"])` = only these prefix paths
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_write_paths: Option<Vec<StoragePath>>,
}

impl UserQuota {
    /// Construct from nullable DB columns.
    ///
    /// - Integer columns: NULL → Default, -1 → Unlimited, positive → Value.
    /// - VARCHAR columns: NULL → Default, "unlimited" → Unlimited, value → Value.
    /// - `allowed_write_paths`: NULL → `None` (unrestricted), valid JSON array → `Some(vec)`,
    ///   malformed JSON → `Some(vec![])` (read-only, fail-closed).
    pub fn from_nullable_columns(
        storage_quota_mb: Option<i32>,
        rate_read: Option<String>,
        rate_write: Option<String>,
        rate_read_burst: Option<i32>,
        rate_write_burst: Option<i32>,
        allowed_write_paths: Option<String>,
    ) -> Self {
        let allowed_write_paths = allowed_write_paths.map(|s| {
            serde_json::from_str::<Vec<StoragePath>>(&s).unwrap_or_else(|e| {
                tracing::error!(
                    "Invalid allowed_write_paths JSON in DB: {e}; falling back to read-only"
                );
                vec![]
            })
        });
        Self {
            storage_quota_mb: QuotaOverride::<u64>::from_db_int(
                "quota_storage_mb",
                storage_quota_mb,
            ),
            rate_read: QuotaOverride::<BandwidthQuota>::from_db_varchar("rate_read", rate_read),
            rate_write: QuotaOverride::<BandwidthQuota>::from_db_varchar("rate_write", rate_write),
            rate_read_burst: rate_read_burst.and_then(|v| u32::try_from(v).ok()?.try_into().ok()),
            rate_write_burst: rate_write_burst.and_then(|v| u32::try_from(v).ok()?.try_into().ok()),
            allowed_write_paths,
        }
    }

    /// Storage quota as the DB-column type (`INTEGER`).
    pub fn storage_quota_mb_i32(&self) -> Option<i32> {
        self.storage_quota_mb.to_db_int()
    }

    /// Rate-read as the DB-column type (`VARCHAR`).
    pub fn rate_read_str(&self) -> Option<String> {
        self.rate_read.to_db_varchar()
    }

    /// Rate-write as the DB-column type (`VARCHAR`).
    pub fn rate_write_str(&self) -> Option<String> {
        self.rate_write.to_db_varchar()
    }

    /// Rate-read burst as DB-column type (`INTEGER`).
    pub fn rate_read_burst_i32(&self) -> Option<i32> {
        burst_to_i32("rate_read_burst", self.rate_read_burst)
    }

    /// Rate-write burst as DB-column type (`INTEGER`).
    pub fn rate_write_burst_i32(&self) -> Option<i32> {
        burst_to_i32("rate_write_burst", self.rate_write_burst)
    }

    /// Allowed write paths as DB-column type (`TEXT`): JSON array string or NULL.
    pub fn allowed_write_paths_db(&self) -> Result<Option<String>, serde_json::Error> {
        self.allowed_write_paths
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
    }

    /// Check whether a write to `path` is allowed under the current restrictions.
    pub fn is_write_path_allowed(&self, path: &str) -> bool {
        match &self.allowed_write_paths {
            None => true,
            Some(entries) => entries.iter().any(|entry| {
                if entry.is_directory() {
                    // Directory entries use prefix matching.
                    path.starts_with(entry.as_str())
                } else {
                    // File entries use exact matching.
                    path == entry.as_str()
                }
            }),
        }
    }

    /// Resolve all `Default` fields against system-wide defaults.
    ///
    /// After resolution every field is either `Value(…)` or `Unlimited`,
    /// so `skip_serializing_if = "is_default"` will *not* omit any field —
    /// the caller gets the full effective quota in the JSON response.
    pub fn resolve_with_defaults(
        &self,
        default_storage_mb: Option<u64>,
        default_quotas: &DefaultQuotasToml,
    ) -> Self {
        fn resolve_u64(field: &QuotaOverride<u64>, default: Option<u64>) -> QuotaOverride<u64> {
            match field {
                QuotaOverride::Default => match default {
                    Some(v) => QuotaOverride::Value(v),
                    None => QuotaOverride::Unlimited,
                },
                other => other.clone(),
            }
        }
        fn resolve_bw(
            field: &QuotaOverride<BandwidthQuota>,
            default: Option<&BandwidthQuota>,
        ) -> QuotaOverride<BandwidthQuota> {
            match field {
                QuotaOverride::Default => match default {
                    Some(v) => QuotaOverride::Value(v.clone()),
                    None => QuotaOverride::Unlimited,
                },
                other => other.clone(),
            }
        }

        Self {
            storage_quota_mb: resolve_u64(&self.storage_quota_mb, default_storage_mb),
            rate_read: resolve_bw(&self.rate_read, default_quotas.rate_read.as_ref()),
            rate_write: resolve_bw(&self.rate_write, default_quotas.rate_write.as_ref()),
            rate_read_burst: self.rate_read_burst.or(if self.rate_read.is_default() {
                default_quotas.rate_read_burst
            } else {
                None
            }),
            rate_write_burst: self.rate_write_burst.or(if self.rate_write.is_default() {
                default_quotas.rate_write_burst
            } else {
                None
            }),
            allowed_write_paths: self.allowed_write_paths.clone(),
        }
    }

    /// Check that the quota fields are internally consistent:
    /// - Rate values can be persisted (fit in the DB column).
    /// - Burst overrides have a corresponding rate `Value`.
    /// - Burst values are > 0.
    pub fn validate(&self) -> Result<(), String> {
        validate_rate_value("rate_read", &self.rate_read)?;
        validate_rate_value("rate_write", &self.rate_write)?;
        validate_burst("rate_read_burst", self.rate_read_burst, &self.rate_read)?;
        validate_burst("rate_write_burst", self.rate_write_burst, &self.rate_write)?;
        validate_allowed_write_paths(&self.allowed_write_paths)?;
        Ok(())
    }

    /// Merge a patch into this quota: only `Some` fields are updated; `None` means keep.
    pub fn merge(&mut self, patch: &UserQuotaPatch) {
        if let Some(ref v) = patch.storage_quota_mb {
            self.storage_quota_mb = v.clone();
        }
        if let Some(ref v) = patch.rate_read {
            self.rate_read = v.clone();
        }
        if let Some(ref v) = patch.rate_write {
            self.rate_write = v.clone();
        }
        if let Some(v) = patch.rate_read_burst {
            self.rate_read_burst = v;
        }
        if let Some(v) = patch.rate_write_burst {
            self.rate_write_burst = v;
        }
        if let Some(ref v) = patch.allowed_write_paths {
            self.allowed_write_paths = v.clone();
        }
    }
}

/// Serde helper: when the field is present, delegates to `QuotaOverride::deserialize`
/// which maps null → `Default`, "unlimited" → `Unlimited`, value → `Value(T)`.
/// When absent, `#[serde(default)]` gives `None` (keep unchanged).
fn deserialize_patch_override<'de, T, D>(d: D) -> Result<Option<QuotaOverride<T>>, D::Error>
where
    T: serde::de::DeserializeOwned,
    D: Deserializer<'de>,
{
    QuotaOverride::<T>::deserialize(d).map(Some)
}

/// Serde helper for patch `Option<Option<Vec<String>>>`:
/// - field absent → `None` (keep existing)
/// - field `null` → `Some(None)` (reset to unrestricted)
/// - field `[...]` → `Some(Some(vec))` (set paths)
fn deserialize_patch_allowed_write_paths<'de, D>(
    d: D,
) -> Result<Option<Option<Vec<StoragePath>>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<StoragePath>>::deserialize(d).map(Some)
}

/// Serde helper for patch `Option<Option<NonZeroU32>>`:
/// - field absent → `None` (keep existing)
/// - field `null` → `Some(None)` (reset to default)
/// - field `N` → `Some(Some(N))` (set value)
fn deserialize_patch_option_non_zero_u32<'de, D>(
    d: D,
) -> Result<Option<Option<NonZeroU32>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<NonZeroU32>::deserialize(d).map(Some)
}

/// Partial update for `UserQuota`.
///
/// Used by the PATCH endpoint: only fields present in the JSON body are
/// applied to the existing quota. Absent fields are left unchanged.
///
/// | JSON | Effect |
/// |---|---|
/// | field absent | keep existing value |
/// | `null` | reset to `Default` (use system default) |
/// | `"unlimited"` | set to `Unlimited` (no limit) |
/// | value | set to `Value(v)` (custom limit) |
///
/// For `allowed_write_paths` specifically: absent = keep, `null` = reset
/// to unrestricted, `[...]` = set allowed path prefixes.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UserQuotaPatch {
    /// Storage quota in MB.
    #[serde(default, deserialize_with = "deserialize_patch_override")]
    pub storage_quota_mb: Option<QuotaOverride<u64>>,
    /// Per-user read rate limit.
    #[serde(default, deserialize_with = "deserialize_patch_override")]
    pub rate_read: Option<QuotaOverride<BandwidthQuota>>,
    /// Per-user write rate limit.
    #[serde(default, deserialize_with = "deserialize_patch_override")]
    pub rate_write: Option<QuotaOverride<BandwidthQuota>>,
    /// Burst for read speed limit (in the rate's natural unit). null = reset to default.
    #[serde(default, deserialize_with = "deserialize_patch_option_non_zero_u32")]
    pub rate_read_burst: Option<Option<NonZeroU32>>,
    /// Burst for write speed limit (in the rate's natural unit). null = reset to default.
    #[serde(default, deserialize_with = "deserialize_patch_option_non_zero_u32")]
    pub rate_write_burst: Option<Option<NonZeroU32>>,
    /// Allowed write paths. absent = keep, null = reset to unrestricted, array = set paths.
    #[serde(default, deserialize_with = "deserialize_patch_allowed_write_paths")]
    pub allowed_write_paths: Option<Option<Vec<StoragePath>>>,
}

impl UserQuotaPatch {
    /// Check that the patch fields are individually valid:
    /// - Rate values can be persisted (fit in the DB column).
    /// - Burst values are > 0.
    ///
    /// Note: does not check cross-field constraints (e.g. burst requires a
    /// corresponding rate). Use [`UserQuota::validate`] on the merged config.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref field) = self.rate_read {
            validate_rate_value("rate_read", field)?;
        }
        if let Some(ref field) = self.rate_write {
            validate_rate_value("rate_write", field)?;
        }
        validate_burst_value("rate_read_burst", self.rate_read_burst.flatten())?;
        validate_burst_value("rate_write_burst", self.rate_write_burst.flatten())?;
        if let Some(ref inner) = self.allowed_write_paths {
            validate_allowed_write_paths(inner)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn nz(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).unwrap()
    }

    #[test]
    fn test_quota_field_default() {
        let field: QuotaOverride<BandwidthQuota> = QuotaOverride::default();
        assert!(field.is_default());
        assert!(!field.is_unlimited());
        assert_eq!(field.as_value(), None);
    }

    #[test]
    fn test_quota_field_unlimited() {
        let field: QuotaOverride<BandwidthQuota> = QuotaOverride::Unlimited;
        assert!(!field.is_default());
        assert!(field.is_unlimited());
        assert_eq!(field.as_value(), None);
    }

    #[test]
    fn test_quota_field_value() {
        let rate = BandwidthQuota::from_str("100mb/m").unwrap();
        let field = QuotaOverride::Value(rate.clone());
        assert!(!field.is_default());
        assert!(!field.is_unlimited());
        assert_eq!(field.as_value(), Some(&rate));
    }

    #[test]
    fn test_varchar_roundtrip() {
        assert_eq!(
            QuotaOverride::<BandwidthQuota>::from_db_varchar("rate_read", None),
            QuotaOverride::Default
        );
        assert_eq!(
            QuotaOverride::<BandwidthQuota>::from_db_varchar(
                "rate_read",
                Some("unlimited".to_string())
            ),
            QuotaOverride::Unlimited
        );
        assert_eq!(
            QuotaOverride::<BandwidthQuota>::from_db_varchar(
                "rate_read",
                Some("100mb/m".to_string())
            ),
            QuotaOverride::Value(BandwidthQuota::from_str("100mb/m").unwrap())
        );
        assert_eq!(
            QuotaOverride::<BandwidthQuota>::from_db_varchar(
                "rate_read",
                Some("rubbish".to_string())
            ),
            QuotaOverride::Default
        );

        assert_eq!(
            QuotaOverride::<BandwidthQuota>::Default.to_db_varchar(),
            None
        );
        assert_eq!(
            QuotaOverride::<BandwidthQuota>::Unlimited.to_db_varchar(),
            Some("unlimited".to_string())
        );
        assert_eq!(
            QuotaOverride::Value(BandwidthQuota::from_str("100mb/m").unwrap()).to_db_varchar(),
            Some("100mb/m".to_string())
        );
    }

    #[test]
    fn test_bigint_roundtrip() {
        assert_eq!(
            QuotaOverride::<u64>::from_db_int("quota_storage_mb", None),
            QuotaOverride::Default
        );
        assert_eq!(
            QuotaOverride::<u64>::from_db_int("quota_storage_mb", Some(-1)),
            QuotaOverride::Unlimited
        );
        assert_eq!(
            QuotaOverride::<u64>::from_db_int("quota_storage_mb", Some(500)),
            QuotaOverride::Value(500)
        );
        assert_eq!(
            QuotaOverride::<u64>::from_db_int("quota_storage_mb", Some(0)),
            QuotaOverride::Value(0)
        );
        assert_eq!(
            QuotaOverride::<u64>::from_db_int("quota_storage_mb", Some(-5)),
            QuotaOverride::Default
        );

        assert_eq!(QuotaOverride::<u64>::Default.to_db_int(), None);
        assert_eq!(QuotaOverride::<u64>::Unlimited.to_db_int(), Some(-1));
        assert_eq!(QuotaOverride::Value(500u64).to_db_int(), Some(500));
    }

    #[test]
    fn test_resolve_with_default() {
        assert_eq!(
            QuotaOverride::<u64>::Default.resolve_with_default(Some(500)),
            Some(500)
        );
        assert_eq!(
            QuotaOverride::<u64>::Default.resolve_with_default(None),
            None
        );
        assert_eq!(
            QuotaOverride::<u64>::Unlimited.resolve_with_default(Some(500)),
            None
        );
        assert_eq!(
            QuotaOverride::Value(200u64).resolve_with_default(Some(500)),
            Some(200)
        );
    }

    #[test]
    fn test_from_nullable_columns_all_null() {
        let q = UserQuota::from_nullable_columns(None, None, None, None, None, None);
        assert_eq!(q, UserQuota::default());
    }

    #[test]
    fn test_from_nullable_columns_with_values() {
        let q = UserQuota::from_nullable_columns(
            Some(500),
            Some("100mb/m".to_string()),
            None,
            None,
            None,
            None,
        );
        assert_eq!(q.storage_quota_mb, QuotaOverride::Value(500));
        assert_eq!(
            q.rate_read,
            QuotaOverride::Value(BandwidthQuota::from_str("100mb/m").unwrap())
        );
        assert_eq!(q.rate_write, QuotaOverride::Default);
    }

    #[test]
    fn test_from_nullable_columns_unlimited_values() {
        let q = UserQuota::from_nullable_columns(
            Some(-1),
            Some("unlimited".to_string()),
            Some("unlimited".to_string()),
            None,
            None,
            None,
        );
        assert_eq!(q.storage_quota_mb, QuotaOverride::Unlimited);
        assert_eq!(q.rate_read, QuotaOverride::Unlimited);
        assert_eq!(q.rate_write, QuotaOverride::Unlimited);
    }

    #[test]
    fn test_from_nullable_columns_mixed() {
        let q = UserQuota::from_nullable_columns(
            None,
            Some("10mb/s".to_string()),
            None,
            None,
            None,
            None,
        );
        assert_eq!(q.storage_quota_mb, QuotaOverride::Default);
        assert_eq!(
            q.rate_read,
            QuotaOverride::Value(BandwidthQuota::from_str("10mb/s").unwrap())
        );
        assert_eq!(q.rate_write, QuotaOverride::Default);
    }

    #[test]
    fn test_from_nullable_columns_invalid_rate_string() {
        let q = UserQuota::from_nullable_columns(
            None,
            Some("rubbish".to_string()),
            Some("100mb/m".to_string()),
            None,
            None,
            None,
        );
        assert_eq!(q.rate_read, QuotaOverride::Default);
        assert_eq!(
            q.rate_write,
            QuotaOverride::Value(BandwidthQuota::from_str("100mb/m").unwrap())
        );
    }

    #[test]
    fn test_from_nullable_columns_legacy_request_units() {
        let q = UserQuota::from_nullable_columns(
            None,
            Some("100r/m".to_string()),
            Some("50r/s".to_string()),
            None,
            None,
            None,
        );
        assert_eq!(q.rate_read, QuotaOverride::Default);
        assert_eq!(q.rate_write, QuotaOverride::Default);
    }

    #[test]
    fn test_serde_roundtrip() {
        let q = UserQuota {
            storage_quota_mb: QuotaOverride::Value(500),
            rate_read: QuotaOverride::Value(BandwidthQuota::from_str("100mb/m").unwrap()),
            rate_write: QuotaOverride::Unlimited,
            ..Default::default()
        };
        let json = serde_json::to_string(&q).unwrap();
        let deserialized: UserQuota = serde_json::from_str(&json).unwrap();
        assert_eq!(q, deserialized);
    }

    #[test]
    fn test_serde_default_fields_omitted() {
        let q = UserQuota {
            storage_quota_mb: QuotaOverride::Value(500),
            ..Default::default()
        };
        let json = serde_json::to_string(&q).unwrap();
        assert!(json.contains("storage_quota_mb"));
        assert!(!json.contains("rate_read"));
        assert!(!json.contains("rate_write"));
    }

    #[test]
    fn test_serde_empty_json_is_all_default() {
        let q: UserQuota = serde_json::from_str("{}").unwrap();
        assert_eq!(q, UserQuota::default());
    }

    #[test]
    fn test_serde_null_is_default_for_all() {
        let json = r#"{"storage_quota_mb": null, "rate_read": null, "rate_write": null}"#;
        let q: UserQuota = serde_json::from_str(json).unwrap();
        assert_eq!(q, UserQuota::default());
    }

    #[test]
    fn test_serde_unlimited_string() {
        let json = r#"{"storage_quota_mb": "unlimited", "rate_read": "unlimited", "rate_write": "unlimited"}"#;
        let q: UserQuota = serde_json::from_str(json).unwrap();
        assert_eq!(q.storage_quota_mb, QuotaOverride::Unlimited);
        assert_eq!(q.rate_read, QuotaOverride::Unlimited);
        assert_eq!(q.rate_write, QuotaOverride::Unlimited);
    }

    #[test]
    fn test_serde_unlimited_serializes_as_string() {
        let q = UserQuota {
            storage_quota_mb: QuotaOverride::Unlimited,
            rate_read: QuotaOverride::Unlimited,
            ..Default::default()
        };
        let json = serde_json::to_string(&q).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["storage_quota_mb"], "unlimited");
        assert_eq!(v["rate_read"], "unlimited");
    }

    #[test]
    fn test_serde_absent_is_default() {
        let json = r#"{"storage_quota_mb": 500}"#;
        let q: UserQuota = serde_json::from_str(json).unwrap();
        assert_eq!(q.storage_quota_mb, QuotaOverride::Value(500));
        assert_eq!(q.rate_read, QuotaOverride::Default);
    }

    #[test]
    fn test_serde_none_fields_omitted() {
        let q = UserQuota::default();
        let json = serde_json::to_string(&q).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_serde_rejects_invalid_rate_string() {
        let json = r#"{"rate_read": "rubbish"}"#;
        let result: Result<UserQuota, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "Invalid rate string should fail deserialization"
        );
    }

    #[test]
    fn test_validate_valid_rates() {
        let budgets = ["100mb/m", "1gb/d", "500kb/s", "10mb/h", "999gb/d", "1kb/s"];
        for s in budgets {
            let q = UserQuota {
                rate_read: QuotaOverride::Value(BandwidthQuota::from_str(s).unwrap()),
                rate_write: QuotaOverride::Value(BandwidthQuota::from_str(s).unwrap()),
                ..Default::default()
            };
            q.validate().unwrap_or_else(|e| {
                panic!("Budget \"{s}\" should pass validation but got: {e}");
            });
        }
    }

    #[test]
    fn test_validate_skips_non_value() {
        let q = UserQuota {
            rate_read: QuotaOverride::Default,
            rate_write: QuotaOverride::Unlimited,
            ..Default::default()
        };
        assert!(q.validate().is_ok());
    }

    // ── Patch tests ──

    #[test]
    fn test_patch_empty_body_changes_nothing() {
        let patch: UserQuotaPatch = serde_json::from_str("{}").unwrap();
        assert!(patch.storage_quota_mb.is_none());
        assert!(patch.rate_read.is_none());
        assert!(patch.rate_write.is_none());
    }

    #[test]
    fn test_patch_null_resets_to_default() {
        let json = r#"{"rate_read": null, "storage_quota_mb": null}"#;
        let patch: UserQuotaPatch = serde_json::from_str(json).unwrap();
        assert_eq!(patch.storage_quota_mb, Some(QuotaOverride::Default));
        assert_eq!(patch.rate_read, Some(QuotaOverride::Default));
        // absent → None (keep)
        assert!(patch.rate_write.is_none());
    }

    #[test]
    fn test_patch_unlimited_string() {
        let json = r#"{"storage_quota_mb": "unlimited", "rate_write": "unlimited"}"#;
        let patch: UserQuotaPatch = serde_json::from_str(json).unwrap();
        assert_eq!(patch.storage_quota_mb, Some(QuotaOverride::Unlimited));
        assert_eq!(patch.rate_write, Some(QuotaOverride::Unlimited));
    }

    #[test]
    fn test_patch_value_sets_value() {
        let json = r#"{"storage_quota_mb": 500, "rate_write": "10mb/s"}"#;
        let patch: UserQuotaPatch = serde_json::from_str(json).unwrap();
        assert_eq!(patch.storage_quota_mb, Some(QuotaOverride::Value(500)));
        assert_eq!(
            patch.rate_write,
            Some(QuotaOverride::Value(
                BandwidthQuota::from_str("10mb/s").unwrap()
            ))
        );
        assert!(patch.rate_read.is_none());
    }

    #[test]
    fn test_merge_applies_only_present_fields() {
        let mut base = UserQuota {
            storage_quota_mb: QuotaOverride::Value(500),
            rate_read: QuotaOverride::Value(BandwidthQuota::from_str("100mb/m").unwrap()),
            rate_write: QuotaOverride::Value(BandwidthQuota::from_str("50mb/s").unwrap()),
            ..Default::default()
        };

        // Patch only storage_quota_mb and rate_write; others should be unchanged
        let patch: UserQuotaPatch =
            serde_json::from_str(r#"{"storage_quota_mb": 200, "rate_write": "unlimited"}"#)
                .unwrap();
        base.merge(&patch);

        assert_eq!(base.storage_quota_mb, QuotaOverride::Value(200));
        assert_eq!(
            base.rate_read,
            QuotaOverride::Value(BandwidthQuota::from_str("100mb/m").unwrap())
        ); // unchanged
        assert_eq!(base.rate_write, QuotaOverride::Unlimited); // patched
    }

    #[test]
    fn test_merge_null_resets_to_default() {
        let mut base = UserQuota {
            storage_quota_mb: QuotaOverride::Value(500),
            rate_read: QuotaOverride::Value(BandwidthQuota::from_str("100mb/m").unwrap()),
            ..Default::default()
        };

        let patch: UserQuotaPatch =
            serde_json::from_str(r#"{"storage_quota_mb": null, "rate_read": null}"#).unwrap();
        base.merge(&patch);

        assert_eq!(base.storage_quota_mb, QuotaOverride::Default);
        assert_eq!(base.rate_read, QuotaOverride::Default);
    }

    #[test]
    fn test_merge_empty_patch_is_noop() {
        let original = UserQuota {
            storage_quota_mb: QuotaOverride::Value(500),
            rate_read: QuotaOverride::Value(BandwidthQuota::from_str("100mb/m").unwrap()),
            rate_write: QuotaOverride::Unlimited,
            ..Default::default()
        };
        let mut patched = original.clone();
        let patch: UserQuotaPatch = serde_json::from_str("{}").unwrap();
        patched.merge(&patch);
        assert_eq!(patched, original);
    }

    #[test]
    fn test_burst_valid_with_rate() {
        let q = UserQuota {
            rate_read: QuotaOverride::Value(BandwidthQuota::from_str("10mb/s").unwrap()),
            rate_read_burst: Some(nz(50)),
            ..Default::default()
        };
        assert!(q.validate().is_ok());
    }

    #[test]
    fn test_burst_zero_rejected_by_serde() {
        let err =
            serde_json::from_str::<UserQuota>(r#"{"rate_read":"10mb/s","rate_read_burst":0}"#)
                .unwrap_err();
        assert!(err.to_string().contains("zero"), "error: {err}");
    }

    #[test]
    fn test_burst_exceeds_i32_max_rejected() {
        let q = UserQuota {
            rate_read: QuotaOverride::Value(BandwidthQuota::from_str("10mb/s").unwrap()),
            rate_read_burst: Some(nz(i32::MAX as u32 + 1)),
            ..Default::default()
        };
        let err = q.validate().unwrap_err();
        assert!(err.contains("rate_read_burst"), "error: {err}");
        assert!(err.contains("exceeds maximum"), "error: {err}");
    }

    #[test]
    fn test_burst_at_i32_max_accepted() {
        let q = UserQuota {
            rate_read: QuotaOverride::Value(BandwidthQuota::from_str("10mb/s").unwrap()),
            rate_read_burst: Some(nz(i32::MAX as u32)),
            ..Default::default()
        };
        assert!(q.validate().is_ok());
    }

    #[test]
    fn test_burst_without_rate_rejected() {
        let q = UserQuota {
            rate_read: QuotaOverride::Default,
            rate_read_burst: Some(nz(50)),
            ..Default::default()
        };
        let err = q.validate().unwrap_err();
        assert!(err.contains("rate_read_burst"), "error: {err}");
    }

    #[test]
    fn test_burst_with_unlimited_rate_rejected() {
        let q = UserQuota {
            rate_write: QuotaOverride::Unlimited,
            rate_write_burst: Some(nz(50)),
            ..Default::default()
        };
        let err = q.validate().unwrap_err();
        assert!(err.contains("rate_write_burst"), "error: {err}");
    }

    #[test]
    fn test_burst_none_always_valid() {
        // No burst set — valid regardless of rate state
        for rate in [
            QuotaOverride::Default,
            QuotaOverride::Unlimited,
            QuotaOverride::Value(BandwidthQuota::from_str("10mb/s").unwrap()),
        ] {
            let q = UserQuota {
                rate_read: rate,
                rate_read_burst: None,
                ..Default::default()
            };
            assert!(q.validate().is_ok());
        }
    }

    #[test]
    fn test_patch_burst_zero_rejected_by_serde() {
        let err = serde_json::from_str::<UserQuotaPatch>(r#"{"rate_read_burst": 0}"#).unwrap_err();
        assert!(err.to_string().contains("zero"), "error: {err}");
    }

    #[test]
    fn test_patch_burst_null_valid() {
        // null → Some(None) → reset to default, always valid
        let patch: UserQuotaPatch = serde_json::from_str(r#"{"rate_read_burst": null}"#).unwrap();
        assert!(patch.validate().is_ok());
    }

    #[test]
    fn test_patch_burst_positive_valid() {
        let patch: UserQuotaPatch = serde_json::from_str(r#"{"rate_read_burst": 50}"#).unwrap();
        assert!(patch.validate().is_ok());
    }

    #[test]
    fn test_burst_serde_roundtrip() {
        let q = UserQuota {
            rate_read: QuotaOverride::Value(BandwidthQuota::from_str("10mb/s").unwrap()),
            rate_read_burst: Some(nz(50)),
            rate_write: QuotaOverride::Value(BandwidthQuota::from_str("5mb/s").unwrap()),
            rate_write_burst: Some(nz(25)),
            ..Default::default()
        };
        let json = serde_json::to_string(&q).unwrap();
        let deserialized: UserQuota = serde_json::from_str(&json).unwrap();
        assert_eq!(q, deserialized);
        assert_eq!(deserialized.rate_read_burst, Some(nz(50)));
        assert_eq!(deserialized.rate_write_burst, Some(nz(25)));
    }

    #[test]
    fn test_burst_db_roundtrip() {
        let q = UserQuota {
            rate_read: QuotaOverride::Value(BandwidthQuota::from_str("10mb/s").unwrap()),
            rate_read_burst: Some(nz(50)),
            rate_write: QuotaOverride::Default,
            rate_write_burst: None,
            ..Default::default()
        };
        // Simulate DB write/read cycle
        let reconstructed = UserQuota::from_nullable_columns(
            q.storage_quota_mb_i32(),
            q.rate_read_str(),
            q.rate_write_str(),
            q.rate_read_burst_i32(),
            q.rate_write_burst_i32(),
            q.allowed_write_paths_db().unwrap(),
        );
        assert_eq!(q, reconstructed);
    }

    #[test]
    fn test_burst_absent_from_json_when_none() {
        let q = UserQuota {
            rate_read: QuotaOverride::Value(BandwidthQuota::from_str("10mb/s").unwrap()),
            rate_read_burst: None,
            ..Default::default()
        };
        let json = serde_json::to_string(&q).unwrap();
        assert!(!json.contains("rate_read_burst"));
    }

    #[test]
    fn test_burst_present_in_json_when_set() {
        let q = UserQuota {
            rate_read: QuotaOverride::Value(BandwidthQuota::from_str("10mb/s").unwrap()),
            rate_read_burst: Some(nz(50)),
            ..Default::default()
        };
        let json = serde_json::to_string(&q).unwrap();
        assert!(json.contains(r#""rate_read_burst":50"#));
    }

    /// Helper to create a `StoragePath` in tests.
    fn wdp(s: &str) -> StoragePath {
        StoragePath::from_str(s).unwrap()
    }

    #[test]
    fn test_is_write_path_allowed_none_means_unrestricted() {
        let q = UserQuota::default();
        assert!(q.is_write_path_allowed("/pub/anything"));
        assert!(q.is_write_path_allowed("/"));
    }

    #[test]
    fn test_is_write_path_allowed_empty_means_readonly() {
        let q = UserQuota {
            allowed_write_paths: Some(vec![]),
            ..Default::default()
        };
        assert!(!q.is_write_path_allowed("/pub/anything"));
    }

    #[test]
    fn test_is_write_path_allowed_prefix_match() {
        let q = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/tokens/"), wdp("/pub/paykit/")]),
            ..Default::default()
        };
        assert!(q.is_write_path_allowed("/pub/tokens/foo.json"));
        assert!(q.is_write_path_allowed("/pub/paykit/bar"));
        assert!(!q.is_write_path_allowed("/pub/other/file"));
        assert!(!q.is_write_path_allowed("/pub/token")); // no trailing slash match
    }

    #[test]
    fn test_is_write_path_allowed_exact_file_match() {
        let q = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/profile.json")]),
            ..Default::default()
        };
        assert!(q.is_write_path_allowed("/pub/profile.json"));
        assert!(!q.is_write_path_allowed("/pub/profile.json/sub"));
        assert!(!q.is_write_path_allowed("/pub/profile.jsonx"));
        assert!(!q.is_write_path_allowed("/pub/other.json"));
    }

    #[test]
    fn test_is_write_path_allowed_mixed_dirs_and_files() {
        let q = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/tokens/"), wdp("/pub/profile.json")]),
            ..Default::default()
        };
        assert!(q.is_write_path_allowed("/pub/tokens/foo.json"));
        assert!(q.is_write_path_allowed("/pub/profile.json"));
        assert!(!q.is_write_path_allowed("/pub/other/file"));
    }

    #[test]
    fn test_is_write_path_allowed_prefix_not_child_rejected() {
        // "/pub/tokenstore/" shares a prefix with "/pub/tokens/" but is NOT a child.
        let q = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/tokens/")]),
            ..Default::default()
        };
        assert!(
            !q.is_write_path_allowed("/pub/tokenstore/foo.json"),
            "Path sharing a prefix but not under the allowed dir must be rejected"
        );
        assert!(
            !q.is_write_path_allowed("/pub/tokens"),
            "Allowed dir '/pub/tokens/' should not match file path '/pub/tokens' (no trailing slash)"
        );
    }

    #[test]
    fn test_is_write_path_allowed_nested_subdir() {
        let q = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/tokens/")]),
            ..Default::default()
        };
        assert!(q.is_write_path_allowed("/pub/tokens/sub/deep/file.json"));
        assert!(q.is_write_path_allowed("/pub/tokens/a"));
    }

    #[test]
    fn test_is_write_path_allowed_exact_file_no_children() {
        // An exact file entry should not allow writes to "children" paths.
        let q = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/config.json")]),
            ..Default::default()
        };
        assert!(q.is_write_path_allowed("/pub/config.json"));
        assert!(
            !q.is_write_path_allowed("/pub/config.json/extra"),
            "Exact file match must not allow sub-paths"
        );
        assert!(
            !q.is_write_path_allowed("/pub/config.jsonx"),
            "Exact file match must not allow suffix extensions"
        );
    }

    #[test]
    fn test_allowed_write_paths_serde_roundtrip() {
        let q = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/tokens/")]),
            ..Default::default()
        };
        let json = serde_json::to_string(&q).unwrap();
        assert!(json.contains("allowed_write_paths"));
        let deserialized: UserQuota = serde_json::from_str(&json).unwrap();
        assert_eq!(q, deserialized);
    }

    #[test]
    fn test_allowed_write_paths_none_omitted_from_json() {
        let q = UserQuota::default();
        let json = serde_json::to_string(&q).unwrap();
        assert!(!json.contains("allowed_write_paths"));
    }

    #[test]
    fn test_allowed_write_paths_db_roundtrip() {
        let q = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/a/"), wdp("/pub/b/")]),
            ..Default::default()
        };
        let db_val = q.allowed_write_paths_db().unwrap();
        let reconstructed = UserQuota::from_nullable_columns(None, None, None, None, None, db_val);
        assert_eq!(q.allowed_write_paths, reconstructed.allowed_write_paths);
    }

    #[test]
    fn test_allowed_write_paths_db_none() {
        let q = UserQuota::default();
        assert_eq!(q.allowed_write_paths_db().unwrap(), None);
    }

    #[test]
    fn test_validate_allowed_write_paths_valid() {
        let q = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/tokens/")]),
            ..Default::default()
        };
        assert!(q.validate().is_ok());
    }

    #[test]
    fn test_validate_allowed_write_paths_empty_is_valid() {
        let q = UserQuota {
            allowed_write_paths: Some(vec![]),
            ..Default::default()
        };
        assert!(q.validate().is_ok());
    }

    #[test]
    fn test_serde_rejects_invalid_path_no_leading_slash() {
        let result =
            serde_json::from_str::<UserQuota>(r#"{"allowed_write_paths": ["pub/tokens/"]}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_allowed_write_paths_file_path_accepted() {
        let q = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/tokens")]),
            ..Default::default()
        };
        assert!(q.validate().is_ok(), "File paths should be accepted");
    }

    #[test]
    fn test_serde_rejects_dotdot_path() {
        let result =
            serde_json::from_str::<UserQuota>(r#"{"allowed_write_paths": ["/pub/../etc/"]}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_serde_rejects_double_slash() {
        let result =
            serde_json::from_str::<UserQuota>(r#"{"allowed_write_paths": ["/pub//tokens/"]}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_patch_allowed_write_paths_absent_keeps() {
        let patch: UserQuotaPatch = serde_json::from_str("{}").unwrap();
        assert!(patch.allowed_write_paths.is_none());
    }

    #[test]
    fn test_patch_allowed_write_paths_null_resets() {
        let patch: UserQuotaPatch =
            serde_json::from_str(r#"{"allowed_write_paths": null}"#).unwrap();
        assert_eq!(patch.allowed_write_paths, Some(None));
    }

    #[test]
    fn test_patch_allowed_write_paths_array_sets() {
        let patch: UserQuotaPatch =
            serde_json::from_str(r#"{"allowed_write_paths": ["/pub/a/"]}"#).unwrap();
        assert_eq!(patch.allowed_write_paths, Some(Some(vec![wdp("/pub/a/")])));
    }

    #[test]
    fn test_validate_allowed_write_paths_root_slash_rejected() {
        let q = UserQuota {
            allowed_write_paths: Some(vec![wdp("/")]),
            ..Default::default()
        };
        assert!(q.validate().unwrap_err().contains("must not be '/'"));
    }

    #[test]
    fn test_validate_allowed_write_paths_duplicate_rejected() {
        let q = UserQuota {
            allowed_write_paths: Some(vec![wdp("/pub/tokens/"), wdp("/pub/tokens/")]),
            ..Default::default()
        };
        assert!(q.validate().unwrap_err().contains("duplicate"));
    }

    #[test]
    fn test_from_nullable_columns_malformed_json_falls_back_to_readonly() {
        let q = UserQuota::from_nullable_columns(
            None,
            None,
            None,
            None,
            None,
            Some("not valid json".to_string()),
        );
        assert_eq!(
            q.allowed_write_paths,
            Some(vec![]),
            "Malformed JSON should fall back to read-only (fail-closed)"
        );
    }

    #[test]
    fn test_from_nullable_columns_wrong_json_type_falls_back_to_readonly() {
        // Valid JSON but wrong type (object instead of array).
        let q = UserQuota::from_nullable_columns(
            None,
            None,
            None,
            None,
            None,
            Some(r#"{"not": "an array"}"#.to_string()),
        );
        assert_eq!(
            q.allowed_write_paths,
            Some(vec![]),
            "Wrong JSON type should fall back to read-only (fail-closed)"
        );
    }

    #[test]
    fn test_patch_serde_rejects_bad_write_paths() {
        let result = serde_json::from_str::<UserQuotaPatch>(
            r#"{"allowed_write_paths": ["no-leading-slash/"]}"#,
        );
        assert!(
            result.is_err(),
            "Invalid paths should be rejected at deserialization"
        );
    }

    #[test]
    fn test_merge_allowed_write_paths() {
        let mut base = UserQuota::default();
        let patch: UserQuotaPatch =
            serde_json::from_str(r#"{"allowed_write_paths": ["/pub/x/"]}"#).unwrap();
        base.merge(&patch);
        assert_eq!(base.allowed_write_paths, Some(vec![wdp("/pub/x/")]));

        // Reset to unrestricted
        let patch: UserQuotaPatch =
            serde_json::from_str(r#"{"allowed_write_paths": null}"#).unwrap();
        base.merge(&patch);
        assert_eq!(base.allowed_write_paths, None);
    }
}
