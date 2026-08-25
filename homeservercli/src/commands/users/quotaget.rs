use crate::commands::context::AdminContext;
use crate::commands::users::error::map_http;
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

    println!("{}", serde_json::to_string_pretty(&quota)?);

    Ok(())
}
