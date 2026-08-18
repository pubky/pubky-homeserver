use crate::commands::admin::context::AdminContext;
use crate::commands::admin::user::error::map_http;
use anyhow::Result;
use clap::Args;
use pubky::PublicKey;

#[derive(Args, Debug)]
#[command(about = "Re-enable a previously disabled user account")]
pub struct EnableArgs {
    pub pubky: PublicKey,
}

pub fn run(context: AdminContext, args: &EnableArgs) -> Result<()> {
    let pk = args.pubky.z32();
    context
        .client
        .post(&format!("users/{}/enable", pk))
        .map_err(map_http)?;
    println!("enabled user: {}", pk);
    Ok(())
}
