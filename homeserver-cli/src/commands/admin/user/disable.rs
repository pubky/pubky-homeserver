use crate::commands::admin::context::AdminContext;
use crate::commands::admin::user::error::map_http;
use anyhow::Result;
use clap::Args;
use pubky::PublicKey;

#[derive(Args, Debug)]
#[command(about = "Disable a user account")]
pub struct DisableArgs {
    pub pubky: PublicKey,
}

pub fn run(context: AdminContext, args: &DisableArgs) -> Result<()> {
    let pk = args.pubky.z32();
    context
        .client
        .post(&format!("users/{}/disable", pk))
        .map_err(map_http)?;
    println!("disabled user: {}", pk);
    Ok(())
}
