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

    let recovery_file = cli
        .recovery_file
        .unwrap_or_else(|| recovery::sample_recovery_file(cli.testnet));
    let url = cli.auth_url;

    let deep_link = url
        .to_string()
        .parse::<DeepLink>()
        .map_err(|e| anyhow::anyhow!("Failed to parse Pubky Auth deep link: {e}"))?;

    let (caps, client_id, signup) = match &deep_link {
        DeepLink::Signin(deep_link) => (&deep_link.params().capabilities, None, None),
        DeepLink::SigninGrant(deep_link) => (
            &deep_link.params().capabilities,
            Some(deep_link.params().client_id.to_string()),
            None,
        ),
        DeepLink::Signup(deep_link) => (
            &deep_link.params().capabilities,
            None,
            Some((
                &deep_link.params().homeserver,
                deep_link.params().signup_token.as_deref(),
            )),
        ),
        DeepLink::SignupGrant(deep_link) => (
            &deep_link.params().capabilities,
            Some(deep_link.params().client_id.to_string()),
            Some((
                &deep_link.params().homeserver,
                deep_link.params().signup_token.as_deref(),
            )),
        ),
        _ => anyhow::bail!("Expected a signin or signup Pubky Auth deep link"),
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
        Pubky::testnet()?.signer(keypair)
    } else {
        Pubky::new()?.signer(keypair)
    };

    if let Some((homeserver, signup_token)) = signup {
        println!("Signing up to homeserver: {homeserver}");
        signer.signup(homeserver, signup_token).await?;
        println!("Successfully signed up and published the homeserver record.");
    } else if cli.testnet {
        let homeserver = PublicKey::try_from(testnet::TESTNET_HOMESERVER)?;
        testnet::ensure_signup(&signer, &homeserver).await?;
    }

    println!("Sending approval to the 3rd party app...");

    signer.approve_auth(&url).await?;

    Ok(())
}
