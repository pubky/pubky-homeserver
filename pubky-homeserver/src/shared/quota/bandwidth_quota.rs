use std::fmt;
use std::num::NonZeroU32;
use std::str::FromStr;
use std::time::Duration;

use super::rate_unit::SpeedRateUnit;
use super::TimeUnit;

/// Per-user bandwidth rate — a speed limit for governor throttling.
///
/// Only accepts bandwidth units (`kb`, `mb`, `gb`).
///
/// Used as per-user speed limit overrides in `BandwidthQuotaLimitLayer`.
/// When a user has a custom `BandwidthQuota`, their traffic is throttled at
/// that speed instead of the default path limit.
///
/// Examples: `"10mb/s"`, `"1gb/s"`, `"500kb/s"`
/// Invalid:  `"100r/m"` (request units not accepted)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BandwidthQuota {
    /// The numeric rate value (e.g. 10 in "10mb/s").
    pub rate: NonZeroU32,
    /// The speed unit (kb, mb, gb).
    pub unit: SpeedRateUnit,
    /// The time window.
    pub time_unit: TimeUnit,
}

impl BandwidthQuota {
    /// Convert to a `governor::Quota`, optionally overriding the burst.
    ///
    /// - `burst_override = None` → default behaviour (burst = rate).
    /// - `burst_override = Some(n)` → burst is `n` in the rate's natural unit
    ///   (MB for `"…mb/s"`, KB for `"…kb/s"`, etc.).
    pub fn to_governor_quota(&self, burst_override: Option<NonZeroU32>) -> governor::Quota {
        let rate_unit_mult = self.unit.multiplier().get();
        let rate_cells = NonZeroU32::new(self.rate.get() * rate_unit_mult)
            .expect("always non-zero: rate and multiplier are non-zero");
        let replenish_1_per = Duration::from(self.time_unit) / rate_cells.get();
        let base = governor::Quota::with_period(replenish_1_per)
            .expect("always non-zero: replenish_1_per is non-zero");

        match burst_override {
            Some(b) => {
                let burst_cells =
                    NonZeroU32::new(b.get().saturating_mul(rate_unit_mult)).unwrap_or(rate_cells);
                base.allow_burst(burst_cells)
            }
            None => base.allow_burst(rate_cells),
        }
    }
}

impl From<BandwidthQuota> for governor::Quota {
    fn from(value: BandwidthQuota) -> Self {
        value.to_governor_quota(None)
    }
}

impl fmt::Display for BandwidthQuota {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}/{}", self.rate, self.unit, self.time_unit)
    }
}

impl FromStr for BandwidthQuota {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(format!(
                "Invalid bandwidth rate format: '{s}', expected {{rate}}{{unit}}/{{time}}"
            ));
        }

        let rate_with_unit = parts[0];
        let time_unit = TimeUnit::from_str(parts[1])?;

        // Find boundary between digits and unit suffix.
        let digit_end = rate_with_unit
            .chars()
            .position(|c| !c.is_ascii_digit())
            .unwrap_or(rate_with_unit.len());

        if digit_end == 0 {
            return Err(format!("Missing rate value in '{rate_with_unit}'"));
        }

        let rate_str = &rate_with_unit[..digit_end];
        let unit_str = &rate_with_unit[digit_end..];

        let rate = rate_str
            .parse::<NonZeroU32>()
            .map_err(|_| format!("Failed to parse rate from '{rate_str}'"))?;

        let unit = SpeedRateUnit::from_str(unit_str).map_err(|_| {
            format!(
                "BandwidthQuota does not accept '{unit_str}' as a unit. \
                 Use a bandwidth unit (kb, mb, gb), e.g. \"10mb/s\"."
            )
        })?;

        Ok(BandwidthQuota {
            rate,
            unit,
            time_unit,
        })
    }
}

impl serde::Serialize for BandwidthQuota {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for BandwidthQuota {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BandwidthQuota::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_bandwidth_rates() {
        let b = BandwidthQuota::from_str("10mb/s").unwrap();
        assert_eq!(b.to_string(), "10mb/s");

        let b = BandwidthQuota::from_str("1gb/s").unwrap();
        assert_eq!(b.to_string(), "1gb/s");

        let b = BandwidthQuota::from_str("500kb/s").unwrap();
        assert_eq!(b.to_string(), "500kb/s");

        let b = BandwidthQuota::from_str("500mb/d").unwrap();
        assert_eq!(b.to_string(), "500mb/d");
    }

    #[test]
    fn test_request_units_rejected() {
        let err = BandwidthQuota::from_str("100r/m").unwrap_err();
        assert!(err.contains("does not accept"), "error: {err}");
    }

    #[test]
    fn test_display_roundtrip() {
        let b = BandwidthQuota::from_str("10mb/s").unwrap();
        assert_eq!(b.to_string(), "10mb/s");

        let b2: BandwidthQuota = b.to_string().parse().unwrap();
        assert_eq!(b, b2);
    }

    #[test]
    fn test_serde_roundtrip() {
        let b = BandwidthQuota::from_str("10mb/s").unwrap();
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(json, "\"10mb/s\"");
        let b2: BandwidthQuota = serde_json::from_str(&json).unwrap();
        assert_eq!(b, b2);
    }

    #[test]
    fn test_serde_rejects_request_units() {
        let result: Result<BandwidthQuota, _> = serde_json::from_str("\"100r/m\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_converts_to_governor_quota() {
        let b = BandwidthQuota::from_str("10mb/s").unwrap();
        let _quota: governor::Quota = b.into();
    }
}
