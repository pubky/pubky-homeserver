use crate::commands::context::AdminContext;
use crate::commands::users::error::map_http;
use anyhow::Result;
use clap::Args;
use pubky::PublicKey;

#[derive(Args, Debug)]
#[command(about = "Re-enable a previously disabled user account")]
pub struct EnableArgs {
    /// Public key of the user (z-base-32 encoded).
    pub pubky: PublicKey,
}

pub fn run(context: AdminContext, args: &EnableArgs) -> Result<()> {
    let pk = args.pubky.z32();
    let response = context
        .client
        .post(&format!("users/{}/enable", pk))
        .map_err(map_http)?
        .text()?;
    println!("{}", response);
    Ok(())
}
