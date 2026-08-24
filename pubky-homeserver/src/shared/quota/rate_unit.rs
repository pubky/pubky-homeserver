use std::{num::NonZeroU32, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SpeedRateUnit {
    /// Kilobyte
    Kilobyte,
    /// Megabyte
    Megabyte,
    /// Gigabyte
    Gigabyte,
}

impl SpeedRateUnit {
    /// Returns the multiplier in kilobytes for this unit.
    ///
    /// Speed quotas are always counted in kilobytes because governor::Quota
    /// uses u32, which maxes at ~4GB. Counting in KB extends the range to ~4TB.
    pub const fn multiplier(&self) -> NonZeroU32 {
        match self {
            SpeedRateUnit::Kilobyte => NonZeroU32::new(1).expect("non-zero"),
            SpeedRateUnit::Megabyte => NonZeroU32::new(1024).expect("non-zero"),
            SpeedRateUnit::Gigabyte => NonZeroU32::new(1024 * 1024).expect("non-zero"),
        }
    }
}

impl std::fmt::Display for SpeedRateUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SpeedRateUnit::Kilobyte => "kb",
                SpeedRateUnit::Megabyte => "mb",
                SpeedRateUnit::Gigabyte => "gb",
            }
        )
    }
}

impl FromStr for SpeedRateUnit {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "kb" => Ok(SpeedRateUnit::Kilobyte),
            "mb" => Ok(SpeedRateUnit::Megabyte),
            "gb" => Ok(SpeedRateUnit::Gigabyte),
            _ => Err(format!("Invalid speed rate unit: {}", s)),
        }
    }
}
