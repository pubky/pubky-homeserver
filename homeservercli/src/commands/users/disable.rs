use crate::commands::context::AdminContext;
use crate::commands::users::error::map_http;
use anyhow::Result;
use clap::Args;
use pubky::PublicKey;

#[derive(Args, Debug)]
#[command(about = "Disable a user account")]
pub struct DisableArgs {
    /// Public key of the user (z-base-32 encoded).
    pub pubky: PublicKey,
}

pub fn run(context: AdminContext, args: &DisableArgs) -> Result<()> {
    let pk = args.pubky.z32();
    let response = context
        .client
        .post(&format!("users/{}/disable", pk))
        .map_err(map_http)?
        .text()?;
    println!("{}", response);
    Ok(())
}
