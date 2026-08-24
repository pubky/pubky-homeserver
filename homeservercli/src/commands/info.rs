use crate::commands::context::AdminContext;
use crate::commands::error::map_http;
use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
#[command(about = "Print homeserver statistics (users, disk usage, signup codes, version)")]
pub struct InfoArgs {}

pub fn run(context: AdminContext, _args: &InfoArgs) -> Result<()> {
    let response = context.client.get("info").map_err(map_http)?;
    println!("{}", response.text()?);
    Ok(())
}
