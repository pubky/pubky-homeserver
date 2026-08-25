use crate::commands::context::AdminContext;
use crate::commands::error::map_http;
use anyhow::{Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};

#[derive(Args, Debug)]
#[command(about = "Print homeserver statistics (users, disk usage, signup codes, version)")]
pub struct InfoArgs {}

#[derive(Serialize, Deserialize, Debug)]
pub struct InfoResponse {
    num_users: u64,
    num_disabled_users: u64,
    total_disk_used_mb: u64,
    num_signup_codes: u64,
    num_unused_signup_codes: u64,
    public_key: String,
    pkarr_pubky_address: Option<String>,
    pkarr_icann_domain: Option<String>,
    version: String,
}

pub fn run(context: AdminContext, _args: &InfoArgs) -> Result<()> {
    let response = context.client.get("info").map_err(map_http)?;
    let info: InfoResponse = response.json().context("failed to parse info response")?;
    println!("{}", serde_json::to_string_pretty(&info)?);
    Ok(())
}
