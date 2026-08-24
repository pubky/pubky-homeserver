use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::BandwidthQuota;

/// Default bandwidth limits for the rate limiter.
///
/// Per-user defaults (`rate_read`, `rate_write`) are the system-wide
/// fallback values used when a user's quota is "Default" (NULL in DB).
/// Per-user overrides are managed via the admin API:
///   `PATCH /users/{pubkey}/quota`
///
/// `unauthenticated_ip_rate_read` is a fixed server-level limit for
/// anonymous requests (not overridable per-user).
///
/// Consumed by `BandwidthQuotaLimitLayer`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct DefaultQuotasToml {
    /// Default bandwidth limit for user reads / downloads (e.g. "10mb/s").
    /// Per-user DB overrides take precedence. `None` means no read throttling.
    pub rate_read: Option<BandwidthQuota>,
    /// Default bandwidth limit for user writes / uploads (e.g. "5mb/s").
    /// Per-user DB overrides take precedence. `None` means no write throttling.
    pub rate_write: Option<BandwidthQuota>,
    /// Default burst for read rate, in the rate's natural unit (e.g. MB for "…mb/s").
    /// Per-user DB overrides take precedence. `None` means burst equals rate.
    pub rate_read_burst: Option<NonZeroU32>,
    /// Default burst for write rate, in the rate's natural unit (e.g. MB for "…mb/s").
    /// Per-user DB overrides take precedence. `None` means burst equals rate.
    pub rate_write_burst: Option<NonZeroU32>,
    /// Server-level bandwidth limit for unauthenticated IP reads (e.g. "1mb/s").
    /// `None` means no read throttling for unauthenticated requests.
    pub unauthenticated_ip_rate_read: Option<BandwidthQuota>,
}
