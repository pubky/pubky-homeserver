use crate::commands::context::AdminContext;
use crate::commands::quota::error::map_http;
use crate::helpers::quota::UserQuota;
use anyhow::{Context, Result};
use clap::Args;
use pubky::PublicKey;

#[derive(Args, Debug)]
#[command(about = "Show the effective quota for a user")]
pub struct GetArgs {
    pub public_key: PublicKey,
}

pub fn run(context: AdminContext, args: &GetArgs) -> Result<()> {
    let public_key = args.public_key.z32();

    let response = context
        .client
        .get(&format!("users/{}/quota", public_key))
        .map_err(map_http)?;

    let quota: UserQuota = response.json().context("failed to parse quota response")?;

    println!("Quota for user {}:", public_key);
    println!("  effective:");
    println!(
        "    storage_quota_mb:    {}",
        quota.effective.display_storage()
    );
    println!(
        "    rate_read:           {}",
        quota.effective.display_rate_read()
    );
    println!(
        "    rate_read_burst:     {}",
        quota.effective.display_rate_read_burst()
    );
    println!(
        "    rate_write:          {}",
        quota.effective.display_rate_write()
    );
    println!(
        "    rate_write_burst:    {}",
        quota.effective.display_rate_write_burst()
    );
    println!(
        "    allowed_write_paths: {}",
        quota.effective.display_allowed_write_paths()
    );

    Ok(())
}
