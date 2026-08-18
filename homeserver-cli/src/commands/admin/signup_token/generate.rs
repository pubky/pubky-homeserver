use crate::commands::admin::context::AdminContext;
use crate::commands::admin::signup_token::error::map_http;
use crate::helpers::quota::{Quota, QuotaUpdate, RateLimit};
use anyhow::{Context, Result};
use clap::Args;

#[derive(Args, Debug)]
#[command(about = "Generate a signup invite token with optional quota overrides")]
pub struct GenerateArgs {
    /// Storage quota in MB for the invited user. Use a number (e.g. 500) or "unlimited".
    /// Omit to apply the system default.
    #[arg(long, value_name = "MB")]
    pub storage_quota_mb: Option<Quota>,

    /// Read bandwidth limit for the invited user (e.g. 100mb/s, 1gb/h).
    /// Use "unlimited" to remove the limit. Omit to apply the system default.
    #[arg(long, value_name = "RATE")]
    pub rate_read: Option<RateLimit>,

    /// Write bandwidth limit for the invited user (e.g. 10mb/s, 500kb/m).
    /// Use "unlimited" to remove the limit. Omit to apply the system default.
    #[arg(long, value_name = "RATE")]
    pub rate_write: Option<RateLimit>,

    /// Read burst size in the rate's unit (e.g. 50 for "50mb" when rate is mb/s).
    /// Defaults to the rate value when not set.
    #[arg(long, value_name = "N")]
    pub rate_read_burst: Option<u32>,

    /// Write burst size in the rate's unit. Defaults to the rate value when not set.
    #[arg(long, value_name = "N")]
    pub rate_write_burst: Option<u32>,

    /// Restrict which paths the invited user may write to. Repeatable.
    /// Trailing slash = directory prefix match; no slash = exact file match.
    /// Example: --allowed-write-paths /pub/tokens/ --allowed-write-paths /pub/profile.json
    #[arg(long, value_name = "PATH")]
    pub allowed_write_paths: Vec<String>,
}

pub fn run(context: AdminContext, args: &GenerateArgs) -> Result<()> {
    let body = QuotaUpdate {
        storage_quota_mb: args.storage_quota_mb,
        rate_read: args.rate_read.clone(),
        rate_write: args.rate_write.clone(),
        rate_read_burst: args.rate_read_burst,
        rate_write_burst: args.rate_write_burst,
        allowed_write_paths: args.allowed_write_paths.clone(),
    };

    let token = context
        .client
        .post_json("generate_signup_token", &body)
        .map_err(map_http)?
        .text()
        .context("failed to read signup token response")?;

    println!("invite code: {token}");
    Ok(())
}
