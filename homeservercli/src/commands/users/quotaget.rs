use crate::commands::context::AdminContext;
use crate::commands::users::error::map_http;
use crate::helpers::quota::UserQuota;
use anyhow::{Context, Result};
use clap::Args;
use pubky::PublicKey;

#[derive(Args, Debug)]
#[command(about = "Show the effective quota for a user")]
pub struct GetArgs {
    /// Public key of the user (z-base-32 encoded).
    pub pubky: PublicKey,
}

pub fn run(context: AdminContext, args: &GetArgs) -> Result<()> {
    let pubky = args.pubky.z32();

    let response = context
        .client
        .get(&format!("users/{}/quota", pubky))
        .map_err(map_http)?;

    let quota: UserQuota = response.json().context("failed to parse quota response")?;

    println!("{}", serde_json::to_string_pretty(&quota)?);

    Ok(())
}
