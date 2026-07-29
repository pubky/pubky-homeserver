use anyhow::Result;
use clap::Parser;
use pubky::{deep_links::DeepLink, Pubky, PublicKey};
use std::path::PathBuf;
use url::Url;

#[path = "../recovery.rs"]
mod recovery;
#[path = "../testnet.rs"]
mod testnet;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Pubky Auth URL to approve
    auth_url: Url,

    /// Path to a recovery file of the Pubky you want to sign in with
    #[arg(long)]
    recovery_file: Option<PathBuf>,

    /// Use testnet mode
    #[clap(long)]
    testnet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let homeserver = &PublicKey::try_from(testnet::TESTNET_HOMESERVER).unwrap();
    let recovery_file = cli
        .recovery_file
        .unwrap_or_else(|| recovery::sample_recovery_file(cli.testnet));
    let url = cli.auth_url;

    let deep_link = url
        .to_string()
        .parse::<DeepLink>()
        .map_err(|e| anyhow::anyhow!("Failed to parse Pubky Auth deep link: {e}"))?;

    let (caps, client_id) = match &deep_link {
        DeepLink::Signin(deep_link) => (&deep_link.params().capabilities, None),
        DeepLink::SigninGrant(deep_link) => (
            &deep_link.params().capabilities,
            Some(deep_link.params().client_id.to_string()),
        ),
        _ => anyhow::bail!("Expected a signin or signin_grant Pubky Auth deep link"),
    };

    if let Some(client_id) = client_id {
        println!("\nGrant client id: {client_id}");
    }

    if !caps.is_empty() {
        println!("\nRequested capabilities:\n  {}", caps);
    }

    // === Consent form ===

    let keypair = recovery::decrypt_recovery_file(
        &recovery_file,
        "\nEnter your recovery file's passphrase to confirm:",
    )?;

    println!("Successfully decrypted recovery file...");
    println!("PublicKey: {}", keypair.public_key());

    let signer = if cli.testnet {
        let signer = Pubky::testnet()?.signer(keypair);

        // For the purposes of this demo, we need to make sure
        // the user has an account on the local homeserver.
        testnet::ensure_signup(&signer, homeserver).await?;

        signer
    } else {
        Pubky::new()?.signer(keypair)
    };

    println!("Sending approval to the 3rd party app...");

    signer.approve_auth(&url).await?;

    Ok(())
}
