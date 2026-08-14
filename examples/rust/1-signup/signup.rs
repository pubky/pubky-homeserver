use anyhow::Result;
use clap::Parser;
use pubky::{Pubky, PublicKey};
use std::path::PathBuf;

#[path = "../recovery.rs"]
mod recovery;
#[path = "../testnet.rs"]
mod testnet;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Homeserver identifier (for example `8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo`)
    homeserver: Option<String>,

    /// Path to a recovery_file of the Pubky you want to sign in with
    #[arg(long)]
    recovery_file: Option<PathBuf>,

    /// Signup code (optional)
    #[arg(long)]
    signup_code: Option<String>,

    /// Use the local testnet defaults instead of mainnet relays.
    #[arg(long)]
    testnet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let homeserver = derive_homeserver(&cli)?;
    let recovery_file_path = cli
        .recovery_file
        .unwrap_or_else(|| recovery::sample_recovery_file(cli.testnet));
    let keypair = recovery::decrypt_recovery_file(
        &recovery_file_path,
        "Enter your recovery file's passphrase to signup:",
    )?;

    println!("Successfully decrypted the recovery file, signing up to the homeserver:");

    let pubky = if cli.testnet {
        Pubky::testnet()?
    } else {
        Pubky::new()?
    };

    let signer = pubky.signer(keypair);
    signer
        .signup(&homeserver, cli.signup_code.as_deref())
        .await?;

    println!("Successfully signed up and published the homeserver record.");

    Ok(())
}

fn derive_homeserver(cli: &Cli) -> Result<PublicKey> {
    let homeserver = match (&cli.homeserver, cli.testnet) {
        (Some(homeserver), _) => homeserver.as_str(),
        (None, true) => testnet::TESTNET_HOMESERVER,
        (None, false) => anyhow::bail!("homeserver is required unless --testnet is set"),
    };

    Ok(PublicKey::try_from(homeserver)?)
}
