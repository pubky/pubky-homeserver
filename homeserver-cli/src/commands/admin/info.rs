use crate::commands::admin::context::AdminContext;
use crate::commands::admin::error::map_http;
use anyhow::{Context, Result};
use clap::Args;
use reqwest::blocking::Response;
use serde::Deserialize;

#[derive(Args, Debug)]
#[command(about = "Print homeserver statistics (users, disk usage, signup codes, version)")]
pub struct InfoArgs {}

#[derive(Debug, Deserialize)]
struct AdminInfoResponse {
    num_users: u64,
    num_disabled_users: u64,
    total_disk_used_mb: f64,
    num_signup_codes: u64,
    num_unused_signup_codes: u64,
    public_key: String,
    pkarr_pubky_address: String,
    pkarr_icann_domain: String,
    version: String,
}

pub fn run(context: AdminContext, _args: &InfoArgs) -> Result<()> {
    let response = context.client.get("info").map_err(map_http)?;
    let info = parse_info(response)?;
    println!("{}", format_info(&info));
    Ok(())
}

fn parse_info(response: Response) -> Result<AdminInfoResponse> {
    response
        .json()
        .context("failed to parse admin info response")
}

fn format_info(info: &AdminInfoResponse) -> String {
    format!(
        "Homeserver Admin Info\n\
         ---------------------\n\
         Users:            {} ({} disabled)\n\
         Disk used:        {:.1} MB\n\
         Signup codes:     {} ({} unused)\n\
         Public key:       {}\n\
         Pkarr address:    {}\n\
         Pkarr icann:      {}\n\
         Version:          {}\n\
         ",
        info.num_users,
        info.num_disabled_users,
        info.total_disk_used_mb,
        info.num_signup_codes,
        info.num_unused_signup_codes,
        info.public_key,
        info.pkarr_pubky_address,
        info.pkarr_icann_domain,
        info.version,
    )
}
