use crate::commands::context::AdminContext;
use crate::commands::users::error::map_http;
use crate::helpers::quota::{Quota, QuotaUpdate, RateLimit};
use anyhow::Result;
use clap::{ArgGroup, Args};
use pubky::PublicKey;

#[derive(Args, Debug)]
#[command(about = "Override quota settings for a specific user")]
#[command(group(
    ArgGroup::new("quota_fields")
        .required(true)
        .multiple(true)
        .args(["storage_quota_mb", "rate_read", "rate_write", "rate_read_burst", "rate_write_burst", "allowed_write_paths"]),
))]
pub struct SetArgs {
    /// Public key of the user to update (z-base-32 encoded).
    pub public_key: PublicKey,

    /// Storage quota in MB. Use a number (e.g. 500) or "unlimited".
    /// System default is defined in the homeserver config.
    #[arg(long, value_name = "MB")]
    pub storage_quota_mb: Option<Quota>,

    /// Read bandwidth limit (e.g. 100mb/s, 1gb/h). Use "unlimited" to remove the limit.
    /// System default is defined in the homeserver config.
    #[arg(long, value_name = "RATE")]
    pub rate_read: Option<RateLimit>,

    /// Write bandwidth limit (e.g. 10mb/s, 500kb/m). Use "unlimited" to remove the limit.
    /// System default is defined in the homeserver config.
    #[arg(long, value_name = "RATE")]
    pub rate_write: Option<RateLimit>,

    /// Read burst size in the rate's unit (e.g. 50 for "50mb" when rate is mb/s).
    /// System default is defined in the homeserver config.
    #[arg(long, value_name = "N")]
    pub rate_read_burst: Option<u32>,

    /// Write burst size in the rate's unit. Defaults to the rate value when not set.
    #[arg(long, value_name = "N")]
    pub rate_write_burst: Option<u32>,

    /// Restrict which paths the user may write to. Repeatable.
    /// Trailing slash = directory prefix match; no slash = exact file match.
    /// Example: --allowed-write-paths /pub/tokens/ --allowed-write-paths /pub/profile.json
    #[arg(long, value_name = "PATH")]
    pub allowed_write_paths: Vec<String>,
}

pub fn run(context: AdminContext, args: &SetArgs) -> Result<()> {
    let public_key = args.public_key.z32();

    let body = QuotaUpdate {
        storage_quota_mb: args.storage_quota_mb,
        rate_read: args.rate_read.clone(),
        rate_write: args.rate_write.clone(),
        rate_read_burst: args.rate_read_burst,
        rate_write_burst: args.rate_write_burst,
        allowed_write_paths: args.allowed_write_paths.clone(),
    };

    let response = context
        .client
        .patch_json(&format!("users/{}/quota", public_key), &body)
        .map_err(map_http)?;
    let body = response.text()?;

    println!("updated quota for user: {}\n{}", public_key, body);

    Ok(())
}
