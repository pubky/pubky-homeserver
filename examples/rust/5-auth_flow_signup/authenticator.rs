use anyhow::Result;
use clap::Parser;
use pubky::{deep_links::SignupDeepLink, Pubky};
use url::Url;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Pubky Auth url
    url: Url,

    /// Use testnet mode
    #[clap(long)]
    testnet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let url = cli.url;

    let deep_link = url
        .to_string()
        .parse::<SignupDeepLink>()
        .map_err(|e| anyhow::anyhow!("Failed to parse sign up deep link: {e}"))?;

    println!();
    let params = deep_link.params();
    print!("Signup to homeserver: {}", params.homeserver);
    if let Some(signup_token) = &params.signup_token {
        println!(" using signup token: {}", signup_token);
    } else {
        println!(" not using a signup token");
    }

    let keypair = pubky::Keypair::random();
    println!(
        "Generated a new keypair. Public key: {}",
        keypair.public_key()
    );
    println!("Secret: {:?}", keypair.secret());

    let signer = if cli.testnet {
        Pubky::testnet()?.signer(keypair)
    } else {
        Pubky::new()?.signer(keypair)
    };

    // Sign up to the homeserver with the signup token if provided
    signer
        .signup(&params.homeserver, params.signup_token.as_deref())
        .await?;
    println!("Successfully signed up to the homeserver.");
    println!();

    // === Consent form ===
    // Ask the user for consent to the requested capabilities
    let caps = &params.capabilities;
    if !caps.is_empty() {
        println!("\nRequested capabilities:\n  {}", caps);
    }

    println!("Sending AuthToken to the 3rd party app...");
    signer.approve_auth(&url).await?;

    Ok(())
}
