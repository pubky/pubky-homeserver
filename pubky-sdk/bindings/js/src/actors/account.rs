use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::js_error::{JsResult, PubkyError, PubkyErrorName};
use crate::wrappers::keys::PublicKey;

#[wasm_bindgen(typescript_custom_section)]
const ACCOUNT_QUOTA_TYPES: &str = r#"
/** The individual limits of a quota. A limit is a number, a rate string such as
 * `"100mb/m"`, or `"unlimited"`. Absent in `overrides` means the system default. */
export interface AccountQuotaLimits {
    /** Storage quota in megabytes, or "unlimited". */
    storageQuotaMb?: number | "unlimited";
    /** Read bandwidth limit, e.g. "100mb/m", or "unlimited". */
    rateRead?: string;
    /** Write bandwidth limit, e.g. "50mb/s", or "unlimited". */
    rateWrite?: string;
    /** Burst allowance for reads, in the rate's unit. Absent means burst equals rate. */
    rateReadBurst?: number;
    /** Burst allowance for writes, in the rate's unit. Absent means burst equals rate. */
    rateWriteBurst?: number;
    /** Path prefixes the user may write to. Absent means unrestricted; empty means read-only. */
    allowedWritePaths?: string[];
}

/** A user's quota, both as it applies and as it was customised. */
export interface AccountQuota {
    /** Overrides merged with the homeserver's defaults. */
    effective: AccountQuotaLimits;
    /** Only the per-user overrides. */
    overrides: AccountQuotaLimits;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// A user's quota, both as it applies and as it was customised.
    #[wasm_bindgen(typescript_type = "AccountQuota")]
    pub type AccountQuota;
}

/// camelCase mirror of [`pubky::QuotaLimits`] for the JS object.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QuotaLimitsJs<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_quota_mb: &'a Option<pubky::QuotaLimit<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_read: &'a Option<pubky::QuotaLimit<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_write: &'a Option<pubky::QuotaLimit<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_read_burst: &'a Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_write_burst: &'a Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_write_paths: &'a Option<Vec<pubky::StoragePath>>,
}

impl<'a> From<&'a pubky::QuotaLimits> for QuotaLimitsJs<'a> {
    fn from(limits: &'a pubky::QuotaLimits) -> Self {
        Self {
            storage_quota_mb: &limits.storage_quota_mb,
            rate_read: &limits.rate_read,
            rate_write: &limits.rate_write,
            rate_read_burst: &limits.rate_read_burst,
            rate_write_burst: &limits.rate_write_burst,
            allowed_write_paths: &limits.allowed_write_paths,
        }
    }
}

#[derive(Serialize)]
struct AccountQuotaJs<'a> {
    effective: QuotaLimitsJs<'a>,
    overrides: QuotaLimitsJs<'a>,
}

/// A user's account as returned by `session.account()`.
#[wasm_bindgen]
pub struct AccountInfo(pub(crate) pubky::AccountInfo);

#[wasm_bindgen]
impl AccountInfo {
    /// The user this account belongs to.
    #[wasm_bindgen(getter)]
    pub fn pubky(&self) -> PublicKey {
        self.0.pubky.clone().into()
    }

    /// When the user signed up, as an ISO 8601 date and time without a UTC
    /// offset (e.g. `2026-10-22T10:11:12.123456`).
    #[wasm_bindgen(js_name = "createdAt", getter)]
    pub fn created_at(&self) -> String {
        self.0.created_at.clone()
    }

    /// Whether the account is disabled. Disabled accounts can read and delete
    /// but not write.
    #[wasm_bindgen(getter)]
    pub fn disabled(&self) -> bool {
        self.0.disabled
    }

    /// Bytes of storage currently used.
    #[wasm_bindgen(js_name = "usedBytes", getter)]
    pub fn used_bytes(&self) -> f64 {
        self.0.used_bytes as f64
    }

    /// The quota that applies and the per-user overrides behind it.
    ///
    /// @returns {AccountQuota}
    #[wasm_bindgen(getter)]
    pub fn quota(&self) -> JsResult<AccountQuota> {
        let quota = AccountQuotaJs {
            effective: (&self.0.quota.effective).into(),
            overrides: (&self.0.quota.overrides).into(),
        };
        let value = serde_wasm_bindgen::to_value(&quota).map_err(|e| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                format!("Failed to convert account quota: {e}"),
            )
        })?;
        Ok(value.unchecked_into())
    }
}
