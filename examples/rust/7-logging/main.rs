use anyhow::Result;
use clap::Parser;
use pubky_testnet::{
    pubky::{ClientId, Keypair},
    EphemeralTestnet,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::level_filters::LevelFilter;
use tracing::{debug, info};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(
    version,
    about = "Configure tracing before calling into the Pubky SDK."
)]
struct Cli {
    /// Maximum tracing verbosity to enable: error|warn|info|debug|trace
    #[arg(long, default_value_t = LevelFilter::INFO, value_parser = clap::value_parser!(LevelFilter))]
    level: LevelFilter,

    /// Use an external PostgreSQL instance instead of the Docker-managed one.
    /// Connects to TEST_PUBKY_CONNECTION_STRING env var if set,
    /// otherwise defaults to postgres://postgres:postgres@localhost:5432/postgres
    #[arg(long)]
    external_postgres: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.level);
    info!(level = %cli.level, "Tracing initialized");

    info!("Starting ephemeral testnet");
    #[allow(unused_mut)]
    let mut builder = EphemeralTestnet::builder();

    #[cfg(feature = "docker-postgres")]
    let builder = if !cli.external_postgres {
        builder.with_docker_postgres()
    } else {
        builder
    };

    let testnet = builder.build().await?;
    let pubky = testnet.sdk()?;
    let homeserver = testnet.homeserver_app();

    let keypair = Keypair::random();
    let public_key = keypair.public_key().to_string();
    info!(%public_key, "Generated ephemeral signer");

    let signer = pubky.signer(keypair);
    info!(homeserver = %homeserver.public_key(), "Signing up");
    signer.signup(&homeserver.public_key(), None).await?;
    let session = signer.signin(ClientId::new("logging.example")?).await?;

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let path = format!("/pub/logging.example/{timestamp}.txt");
    let body = format!("Tracing level {} at {timestamp}", cli.level);
    info!(%path, "Writing sample data");
    session.storage().put(&path, body).await?;

    debug!(%path, "Fetching what we just wrote");
    let fetched = session.storage().get(&path).await?.text().await?;
    info!(%path, %fetched, "Roundtrip complete");

    Ok(())
}

fn init_tracing(level: LevelFilter) {
    let env_filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .from_env_lossy();

    fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_level(true)
        .init();
}
