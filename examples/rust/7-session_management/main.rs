use anyhow::Result;
use clap::{Parser, Subcommand};
use pubky::{ClientId, GrantId, GrantManager, Pubky, PubkySession, PublicKey};
use std::path::PathBuf;

#[path = "../recovery.rs"]
mod recovery;
#[path = "../testnet.rs"]
mod testnet;

const MANAGEMENT_CLIENT_ID: &str = "session-management.example";

#[derive(Parser, Debug)]
#[command(version, about = "Manage Pubky grant-backed sessions")]
struct Cli {
    /// Path to a recovery file
    #[arg(long)]
    recovery_file: Option<PathBuf>,

    /// Use the local testnet defaults instead of mainnet relays
    #[arg(long)]
    testnet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List active grant-backed sessions
    List,

    /// Create a new grant-backed session
    Create {
        /// Client id shown in the user's session list
        #[arg(long, default_value = MANAGEMENT_CLIENT_ID)]
        client_id: String,
    },

    /// Delete a session by revoking its grant id
    Delete {
        /// Grant id from the session list
        grant_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::List => {
            let session = root_session(&cli).await?;
            list_sessions(session).await?;
        }
        Command::Create { client_id } => create_session(&cli, client_id).await?,
        Command::Delete { grant_id } => {
            let session = root_session(&cli).await?;
            delete_session(session, grant_id).await?;
        }
    }

    Ok(())
}

async fn root_session(cli: &Cli) -> Result<PubkySession> {
    create_session_for(cli, MANAGEMENT_CLIENT_ID).await
}

async fn create_session(cli: &Cli, client_id: &str) -> Result<()> {
    let session = create_session_for(cli, client_id).await?;
    let info = session
        .as_grant()
        .ok_or_else(|| anyhow::anyhow!("expected a grant-backed session"))?
        .session_info()
        .await;

    println!("Created session:");
    println!("  pubky: {}", info.pubky);
    println!("  client_id: {}", info.client_id);
    println!("  grant_id: {}", info.grant_id);
    println!("  token_expires_at: {}", info.token_expires_at);
    println!("  grant_expires_at: {}", info.grant_expires_at);

    Ok(())
}

async fn create_session_for(cli: &Cli, client_id: &str) -> Result<PubkySession> {
    let recovery_file = cli
        .recovery_file
        .clone()
        .unwrap_or_else(|| recovery::sample_recovery_file(cli.testnet));
    let keypair =
        recovery::decrypt_recovery_file(&recovery_file, "Enter your recovery file passphrase:")?;

    let pubky = if cli.testnet {
        Pubky::testnet()?
    } else {
        Pubky::new()?
    };

    let signer = pubky.signer(keypair);
    if cli.testnet {
        let homeserver = &PublicKey::try_from(testnet::TESTNET_HOMESERVER)?;
        testnet::ensure_signup(&signer, homeserver).await?;
    }

    Ok(signer.signin(ClientId::new(client_id)?).await?)
}

async fn list_sessions(session: PubkySession) -> Result<()> {
    let current_grant_id = session
        .as_grant()
        .ok_or_else(|| anyhow::anyhow!("expected a grant-backed session"))?
        .grant_id()
        .await;
    let grants = GrantManager::new(&session).list().await?;
    signout(session).await;

    let grants: Vec<_> = grants
        .into_iter()
        .filter(|grant| grant.grant_id != current_grant_id)
        .collect();

    if grants.is_empty() {
        println!("No active sessions.");
        return Ok(());
    }

    println!("Active sessions:");
    for grant in grants {
        println!("\nGrant ID: {}", grant.grant_id);
        println!("  client_id: {}", grant.client_id);
        println!("  capabilities: {}", grant.capabilities);
        println!("  issued_at: {}", grant.issued_at);
        println!("  expires_at: {}", grant.expires_at);
    }

    Ok(())
}

async fn delete_session(session: PubkySession, grant_id: &str) -> Result<()> {
    let grant_id = GrantId::parse(grant_id)?;
    GrantManager::new(&session).revoke(&grant_id).await?;
    signout(session).await;
    println!("Deleted session with grant id {grant_id}.");

    Ok(())
}

async fn signout(session: PubkySession) {
    if let Err((err, _session)) = session.signout().await {
        eprintln!("Warning: failed to sign out management session: {err}");
    }
}
