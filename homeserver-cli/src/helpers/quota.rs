use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(untagged)]
pub enum Quota {
    Limit(u64),
    Unlimited(UnlimitedTag),
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum UnlimitedTag {
    Unlimited,
}

impl fmt::Display for Quota {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Quota::Limit(v) => write!(f, "{v}"),
            Quota::Unlimited(_) => write!(f, "unlimited"),
        }
    }
}

impl FromStr for Quota {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("unlimited") {
            Ok(Quota::Unlimited(UnlimitedTag::Unlimited))
        } else {
            s.parse::<u64>()
                .map(Quota::Limit)
                .map_err(|_| format!("expected a number or 'unlimited', got '{s}'"))
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RateLimit(String);

impl fmt::Display for RateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for RateLimit {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim().to_ascii_lowercase();

        if normalized == "unlimited" {
            return Ok(RateLimit(normalized));
        }

        let (amount_part, period) = normalized.split_once('/').ok_or_else(|| err_msg(s))?;

        let unit_start = amount_part
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| err_msg(s))?;
        let (number, unit) = amount_part.split_at(unit_start);

        if number.is_empty() || !matches!(number.parse::<u32>(), Ok(n) if n > 0) {
            return Err(err_msg(s));
        }
        if !matches!(unit, "kb" | "mb" | "gb") {
            return Err(err_msg(s));
        }
        if !matches!(period, "s" | "m" | "h" | "d") {
            return Err(err_msg(s));
        }

        Ok(RateLimit(normalized))
    }
}

fn err_msg(s: &str) -> String {
    format!(
        "invalid rate '{s}': expected <number><kb|mb|gb>/<s|m|h|d> (e.g. 100mb/s) or 'unlimited'"
    )
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct QuotaUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_quota_mb: Option<Quota>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_read: Option<RateLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_write: Option<RateLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_read_burst: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_write_burst: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_write_paths: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct UserQuota {
    pub effective: UserQuotaFields,
}

#[derive(Deserialize, Debug, Default)]
pub struct UserQuotaFields {
    #[serde(default)]
    pub storage_quota_mb: Option<Quota>,
    #[serde(default)]
    pub rate_read: Option<RateLimit>,
    #[serde(default)]
    pub rate_write: Option<RateLimit>,
    #[serde(default)]
    pub rate_read_burst: Option<u32>,
    #[serde(default)]
    pub rate_write_burst: Option<u32>,
    #[serde(default)]
    pub allowed_write_paths: Option<Vec<String>>,
}

impl UserQuotaFields {
    pub fn display_storage(&self) -> String {
        self.storage_quota_mb
            .as_ref()
            .map(|q| q.to_string())
            .unwrap_or_else(|| "(system default)".to_string())
    }

    pub fn display_rate_read(&self) -> String {
        self.rate_read
            .as_ref()
            .map(|r| r.to_string())
            .unwrap_or_else(|| "(system default)".to_string())
    }

    pub fn display_rate_write(&self) -> String {
        self.rate_write
            .as_ref()
            .map(|r| r.to_string())
            .unwrap_or_else(|| "(system default)".to_string())
    }

    pub fn display_rate_read_burst(&self) -> String {
        self.rate_read_burst
            .map(|b| b.to_string())
            .unwrap_or_else(|| "(same as rate)".to_string())
    }

    pub fn display_rate_write_burst(&self) -> String {
        self.rate_write_burst
            .map(|b| b.to_string())
            .unwrap_or_else(|| "(same as rate)".to_string())
    }

    pub fn display_allowed_write_paths(&self) -> String {
        match &self.allowed_write_paths {
            None => "unrestricted".to_string(),
            Some(paths) if paths.is_empty() => "(read-only)".to_string(),
            Some(paths) => paths.join(", "),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quota(s: &str) -> Result<Quota, String> {
        s.parse()
    }

    fn rate(s: &str) -> Result<RateLimit, String> {
        s.parse()
    }

    // --- Quota::from_str ---

    #[test]
    fn quota_parses_number() {
        assert!(matches!(quota("500"), Ok(Quota::Limit(500))));
    }

    #[test]
    fn quota_parses_zero() {
        assert!(matches!(quota("0"), Ok(Quota::Limit(0))));
    }

    #[test]
    fn quota_parses_unlimited_lowercase() {
        assert!(matches!(quota("unlimited"), Ok(Quota::Unlimited(_))));
    }

    #[test]
    fn quota_parses_unlimited_uppercase() {
        assert!(matches!(quota("UNLIMITED"), Ok(Quota::Unlimited(_))));
    }

    #[test]
    fn quota_rejects_negative() {
        assert!(quota("-1").is_err());
    }

    #[test]
    fn quota_rejects_float() {
        assert!(quota("1.5").is_err());
    }

    #[test]
    fn quota_rejects_empty() {
        assert!(quota("").is_err());
    }

    #[test]
    fn quota_display_number() {
        assert_eq!(Quota::Limit(1024).to_string(), "1024");
    }

    #[test]
    fn quota_display_unlimited() {
        assert_eq!(
            Quota::Unlimited(UnlimitedTag::Unlimited).to_string(),
            "unlimited"
        );
    }

    #[test]
    fn rate_parses_all_unit_period_combinations() {
        for unit in ["kb", "mb", "gb"] {
            for period in ["s", "m", "h", "d"] {
                let s = format!("100{unit}/{period}");
                assert!(rate(&s).is_ok(), "{s} should parse");
                assert_eq!(rate(&s).unwrap().to_string(), s);
            }
        }
    }

    #[test]
    fn rate_parses_unlimited() {
        assert!(rate("unlimited").is_ok());
    }

    #[test]
    fn rate_is_case_insensitive() {
        assert!(rate("100MB/S").is_ok());
    }

    #[test]
    fn rate_trims_whitespace() {
        assert!(rate("  100mb/s  ").is_ok());
    }

    #[test]
    fn rate_rejects_bare_b_unit() {
        assert!(rate("500b/s").is_err());
    }

    #[test]
    fn rate_rejects_invalid_period() {
        assert!(rate("100mb/w").is_err());
    }

    #[test]
    fn rate_rejects_missing_slash() {
        assert!(rate("100mbs").is_err());
    }

    #[test]
    fn rate_rejects_missing_number() {
        assert!(rate("mb/s").is_err());
    }

    #[test]
    fn rate_rejects_missing_unit() {
        assert!(rate("100/s").is_err());
    }

    #[test]
    fn rate_rejects_empty() {
        assert!(rate("").is_err());
    }

    #[test]
    fn rate_rejects_zero_rate() {
        assert!(rate("0mb/s").is_err());
        assert!(rate("0kb/d").is_err());
    }

    #[test]
    fn rate_normalizes_to_lowercase() {
        let r = rate("100MB/S").unwrap();
        assert_eq!(r.to_string(), "100mb/s");
    }

    // --- QuotaUpdate serialization ---

    #[test]
    fn quota_update_empty_serializes_to_empty_object() {
        let json = serde_json::to_string(&QuotaUpdate::default()).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn quota_update_omits_none_and_empty_fields() {
        let body = QuotaUpdate {
            storage_quota_mb: Some(Quota::Limit(500)),
            ..Default::default()
        };
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(json, r#"{"storage_quota_mb":500}"#);
    }

    #[test]
    fn quota_update_empty_paths_are_omitted() {
        let body = QuotaUpdate {
            rate_read_burst: Some(50),
            allowed_write_paths: vec![],
            ..Default::default()
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(!json.contains("allowed_write_paths"));
        assert!(json.contains(r#""rate_read_burst":50"#));
    }

    #[test]
    fn quota_update_serializes_all_fields() {
        let body = QuotaUpdate {
            storage_quota_mb: Some(Quota::Unlimited(UnlimitedTag::Unlimited)),
            rate_read: Some("100mb/s".parse().unwrap()),
            rate_write: Some("unlimited".parse().unwrap()),
            rate_read_burst: Some(50),
            rate_write_burst: Some(25),
            allowed_write_paths: vec!["/pub/tokens/".to_string()],
        };
        let v: serde_json::Value = serde_json::to_value(&body).unwrap();
        assert_eq!(v["storage_quota_mb"], "unlimited");
        assert_eq!(v["rate_read"], "100mb/s");
        assert_eq!(v["rate_write"], "unlimited");
        assert_eq!(v["rate_read_burst"], 50);
        assert_eq!(v["rate_write_burst"], 25);
        assert_eq!(
            v["allowed_write_paths"],
            serde_json::json!(["/pub/tokens/"])
        );
    }

    // --- UserQuota deserialization ---

    #[test]
    fn user_quota_parses_effective_and_ignores_overrides() {
        let json = r#"{
            "effective": {
                "storage_quota_mb": 500,
                "rate_read": "100mb/s",
                "rate_write": "unlimited",
                "rate_read_burst": 50,
                "allowed_write_paths": ["/pub/tokens/"]
            },
            "overrides": { "storage_quota_mb": 500 }
        }"#;
        let quota: UserQuota = serde_json::from_str(json).unwrap();
        assert!(matches!(
            quota.effective.storage_quota_mb,
            Some(Quota::Limit(500))
        ));
        assert_eq!(quota.effective.rate_read.unwrap().to_string(), "100mb/s");
        assert_eq!(quota.effective.rate_read_burst, Some(50));
    }

    #[test]
    fn user_quota_fields_default_when_absent() {
        let json = r#"{"effective": {}}"#;
        let quota: UserQuota = serde_json::from_str(json).unwrap();
        assert!(quota.effective.storage_quota_mb.is_none());
        assert!(quota.effective.rate_read.is_none());
        assert!(quota.effective.allowed_write_paths.is_none());
    }

    // --- UserQuotaFields display ---

    #[test]
    fn display_falls_back_when_fields_absent() {
        let f = UserQuotaFields::default();
        assert_eq!(f.display_storage(), "(system default)");
        assert_eq!(f.display_rate_read(), "(system default)");
        assert_eq!(f.display_rate_write(), "(system default)");
        assert_eq!(f.display_rate_read_burst(), "(same as rate)");
        assert_eq!(f.display_rate_write_burst(), "(same as rate)");
        assert_eq!(f.display_allowed_write_paths(), "unrestricted");
    }

    #[test]
    fn display_shows_values_when_present() {
        let f = UserQuotaFields {
            storage_quota_mb: Some(Quota::Limit(500)),
            rate_read: Some("100mb/s".parse().unwrap()),
            rate_read_burst: Some(50),
            ..Default::default()
        };
        assert_eq!(f.display_storage(), "500");
        assert_eq!(f.display_rate_read(), "100mb/s");
        assert_eq!(f.display_rate_read_burst(), "50");
    }

    #[test]
    fn display_allowed_write_paths_read_only_when_empty() {
        let f = UserQuotaFields {
            allowed_write_paths: Some(vec![]),
            ..Default::default()
        };
        assert_eq!(f.display_allowed_write_paths(), "(read-only)");
    }

    #[test]
    fn display_allowed_write_paths_joins_list() {
        let f = UserQuotaFields {
            allowed_write_paths: Some(vec!["/pub/tokens/".to_string(), "/pub/paykit/".to_string()]),
            ..Default::default()
        };
        assert_eq!(
            f.display_allowed_write_paths(),
            "/pub/tokens/, /pub/paykit/"
        );
    }
}
