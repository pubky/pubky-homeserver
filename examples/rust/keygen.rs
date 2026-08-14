use anyhow::Result;
use clap::Parser;
use pubky_common::crypto::Keypair;
use pubky_common::recovery_file::create_recovery_file;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Generate a keypair and save a passphrase-encrypted recovery file"
)]
struct Cli {
    /// Path to write the recovery file
    #[arg(short, long, default_value = "recovery.key")]
    output: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 1) Generate a fresh keypair
    let keypair = Keypair::random();
    println!("Generated new keypair");
    println!("Public key: {}", keypair.public_key());

    // 2) Encrypt and save the recovery file
    println!("Enter a passphrase to encrypt the recovery file:");
    let passphrase = rpassword::read_password()?;

    println!("Confirm passphrase:");
    let confirm = rpassword::read_password()?;

    if passphrase != confirm {
        anyhow::bail!("Passphrases do not match");
    }

    if passphrase.is_empty() {
        println!("Warning: You entered an empty passphrase. This is not recommended for a production environment.");
    }

    let recovery_bytes = create_recovery_file(&keypair, &passphrase);
    std::fs::write(&cli.output, &recovery_bytes)?;
    println!("Recovery file written to {}", cli.output.display());

    Ok(())
}
