use std::fmt;
use std::num::NonZeroU32;
use std::str::FromStr;
use std::time::Duration;

use super::TimeUnit;

/// A request-count quota — limits how many requests are allowed per time window.
///
/// Examples: `"5r/s"`, `"10r/m"`, `"100r/h"`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestCountQuota {
    /// Number of requests allowed per time window.
    pub rate: NonZeroU32,
    /// The time window.
    pub time_unit: TimeUnit,
}

impl TryFrom<RequestCountQuota> for governor::Quota {
    type Error = String;

    fn try_from(value: RequestCountQuota) -> Result<Self, Self::Error> {
        let replenish_1_per = Duration::from(value.time_unit) / value.rate.get();
        let quota = governor::Quota::with_period(replenish_1_per)
            .ok_or_else(|| {
                format!(
                    "Request-count quota rate '{}' is too high",
                    value.rate.get()
                )
            })?
            .allow_burst(value.rate);
        Ok(quota)
    }
}

impl fmt::Display for RequestCountQuota {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}r/{}", self.rate, self.time_unit)
    }
}

impl FromStr for RequestCountQuota {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (rate_with_unit, time_unit) = s.split_once('/').ok_or_else(|| {
            format!("Invalid request-count quota format: '{s}', expected {{count}}r/{{time}}")
        })?;
        let rate = rate_with_unit
            .strip_suffix('r')
            .ok_or_else(|| format!("Request-count quota must end with 'r': '{rate_with_unit}'"))?
            .parse::<NonZeroU32>()
            .map_err(|_| format!("Failed to parse rate from '{s}'"))?;

        let time_unit = TimeUnit::from_str(time_unit)?;

        Ok(RequestCountQuota { rate, time_unit })
    }
}

impl serde::Serialize for RequestCountQuota {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for RequestCountQuota {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RequestCountQuota::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_display() {
        let q: RequestCountQuota = "5r/s".parse().unwrap();
        assert_eq!(q.rate, NonZeroU32::new(5).unwrap());
        assert_eq!(q.time_unit, TimeUnit::Second);
        assert_eq!(q.to_string(), "5r/s");

        let q: RequestCountQuota = "100r/m".parse().unwrap();
        assert_eq!(q.rate, NonZeroU32::new(100).unwrap());
        assert_eq!(q.time_unit, TimeUnit::Minute);
        assert_eq!(q.to_string(), "100r/m");
    }

    #[test]
    fn test_converts_to_governor_quota() {
        let q: RequestCountQuota = "5r/s".parse().unwrap();
        assert_eq!(
            governor::Quota::try_from(q).unwrap(),
            governor::Quota::per_second(NonZeroU32::new(5).unwrap())
        );

        let q: RequestCountQuota = "5r/m".parse().unwrap();
        assert_eq!(
            governor::Quota::try_from(q).unwrap(),
            governor::Quota::per_minute(NonZeroU32::new(5).unwrap())
        );
    }

    #[test]
    fn test_rejects_rate_that_would_create_zero_replenish_period() {
        let q = RequestCountQuota::from_str("4294967295r/s").unwrap();
        let err = governor::Quota::try_from(q).unwrap_err();
        assert!(err.contains("too high"), "error: {err}");
    }

    #[test]
    fn test_rejects_bandwidth_units() {
        assert!(RequestCountQuota::from_str("5mb/s").is_err());
        assert!(RequestCountQuota::from_str("5kb/m").is_err());
    }

    #[test]
    fn test_rejects_invalid_formats() {
        assert!(RequestCountQuota::from_str("5rs").is_err()); // missing /
        assert!(RequestCountQuota::from_str("r/s").is_err()); // missing count
        assert!(RequestCountQuota::from_str("5r/x").is_err()); // invalid time unit
        assert!(RequestCountQuota::from_str("0r/s").is_err()); // zero rate
    }

    #[test]
    fn test_serde_roundtrip() {
        let q: RequestCountQuota = "10r/m".parse().unwrap();
        let json = serde_json::to_string(&q).unwrap();
        assert_eq!(json, "\"10r/m\"");
        let q2: RequestCountQuota = serde_json::from_str(&json).unwrap();
        assert_eq!(q, q2);
    }
}
