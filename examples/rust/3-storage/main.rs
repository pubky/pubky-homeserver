use anyhow::Result;
use clap::Parser;
use pubky::{ClientId, Pubky, PublicKey};
use std::path::PathBuf;

#[path = "../recovery.rs"]
mod recovery;
#[path = "../testnet.rs"]
mod testnet;

#[derive(Parser, Debug)]
#[command(version, about = "Pubky homeserver storage lifecycle example")]
struct Cli {
    /// Resource path to write to
    #[arg(default_value = "/pub/my-app/data.json")]
    path: String,

    /// Content to write
    #[arg(short, long, default_value = "my data")]
    content: String,

    /// Path to a recovery file
    #[arg(long)]
    recovery_file: Option<PathBuf>,

    /// Use the local testnet defaults instead of mainnet relays
    #[arg(long)]
    testnet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let recovery_file = cli
        .recovery_file
        .unwrap_or_else(|| recovery::sample_recovery_file(cli.testnet));
    let keypair =
        recovery::decrypt_recovery_file(&recovery_file, "Enter your recovery file passphrase:")?;
    println!("Decrypted recovery file for {}", keypair.public_key());

    let pubky = if cli.testnet {
        println!("Using testnet...");
        Pubky::testnet()?
    } else {
        Pubky::new()?
    };

    let signer = pubky.signer(keypair);
    if cli.testnet {
        let homeserver = &PublicKey::try_from(testnet::TESTNET_HOMESERVER)?;
        testnet::ensure_signup(&signer, homeserver).await?;
    }

    let session = signer.signin(ClientId::new("storage.example")?).await?;
    println!("Signed in successfully!");

    let storage = session.storage();

    println!("\nPUT {} ...", cli.path);
    storage
        .put(&cli.path, cli.content.as_bytes().to_vec())
        .await?;
    println!("  Written successfully.");

    println!("\nGET {} ...", cli.path);
    let response = storage.get(&cli.path).await?;
    let body = response.bytes().await?;
    println!("  Content: {}", String::from_utf8_lossy(&body));

    println!("\nDELETE {} ...", cli.path);
    storage.delete(&cli.path).await?;
    println!("  Deleted successfully.");

    Ok(())
}
