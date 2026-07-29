use anyhow::Result;
use clap::Parser;
use pubky::{AuthFlowKind, Capabilities, ClientId, Pubky, PubkyGrantAuthFlow, PubkySession};
use url::Url;

const DEFAULT_CLIENT_ID: &str = "grant-auth.example";
const DEFAULT_CAPABILITIES: &str = "/pub/pubky.app/:rw,/pub/example.com/nested:rw";
const TESTNET_RELAY: &str = "http://localhost:15412/inbox";

#[derive(Parser, Debug)]
#[command(version, about = "Start a Pubky grant auth flow")]
struct Cli {
    /// Client id shown in the user's grant/session list
    #[arg(long, default_value = DEFAULT_CLIENT_ID)]
    client_id: String,

    /// Comma-separated capabilities to request
    #[arg(long, default_value = DEFAULT_CAPABILITIES)]
    capabilities: String,

    /// HTTP relay inbox URL. Defaults to the local relay in testnet mode.
    #[arg(long)]
    relay: Option<Url>,

    /// Use the local testnet defaults instead of mainnet relays
    #[arg(long)]
    testnet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let flow = start_flow(&cli)?;

    println!("Pubky Auth URL:\n{}", flow.authorization_url());
    println!("\nApprove it from another terminal:");
    println!(
        "  cargo run --bin authenticator -- \"<AUTH_URL>\"{}",
        testnet_flag(&cli)
    );
    println!("\nWaiting for approval...");

    let session = flow.await_approval().await?;
    print_session(session).await?;

    Ok(())
}

fn start_flow(cli: &Cli) -> Result<PubkyGrantAuthFlow> {
    let pubky = if cli.testnet {
        Pubky::testnet()?
    } else {
        Pubky::new()?
    };
    let caps = cli.capabilities.parse::<Capabilities>()?.normalize();
    let client_id = ClientId::new(&cli.client_id)?;
    let relay = auth_relay(cli)?;

    let mut builder = PubkyGrantAuthFlow::builder(&caps, AuthFlowKind::signin(), client_id)
        .client(pubky.client().clone());

    if let Some(relay) = relay {
        builder = builder.relay(relay);
    }

    Ok(builder.start()?)
}

fn auth_relay(cli: &Cli) -> Result<Option<Url>> {
    if let Some(relay) = &cli.relay {
        return Ok(Some(relay.clone()));
    }

    if cli.testnet {
        return Ok(Some(Url::parse(TESTNET_RELAY)?));
    }

    Ok(None)
}

async fn print_session(session: PubkySession) -> Result<()> {
    let info = session
        .as_grant()
        .ok_or_else(|| anyhow::anyhow!("expected a grant-backed session"))?
        .session_info()
        .await;

    println!("\nApproved grant-backed session:");
    println!("  pubky: {}", info.pubky);
    println!("  client_id: {}", info.client_id);
    println!("  grant_id: {}", info.grant_id);
    println!("  capabilities: {}", session_capabilities(&session));
    println!("  token_expires_at: {}", info.token_expires_at);
    println!("  grant_expires_at: {}", info.grant_expires_at);

    Ok(())
}

fn session_capabilities(session: &PubkySession) -> String {
    session
        .info()
        .capabilities()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn testnet_flag(cli: &Cli) -> &'static str {
    if cli.testnet {
        " --testnet"
    } else {
        ""
    }
}
