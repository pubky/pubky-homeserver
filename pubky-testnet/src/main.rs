use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use pubky_testnet::StaticTestnet;

#[derive(Parser, Debug)]
struct Cli {
    /// Optional path to a homeserver config file.
    /// In in-memory mode (default), this overrides the default config.
    /// With `persist`, this writes the initial config.toml on first run.
    #[clap(long)]
    homeserver_config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a persistent testnet with state stored in the given data directory.
    Persist {
        /// Path to the data directory (config, keypair, files).
        /// Created automatically on first run.
        data_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            "pubky_homeserver=debug,http_relay=debug,pkarr_relay=info,tower_http=debug,pubky_testnet=debug"
                .to_string(),
        )
        .init();

    let mut builder = StaticTestnet::builder();
    if let Some(config) = args.homeserver_config {
        builder = builder.homeserver_config(config);
    }
    if let Some(Command::Persist { data_dir }) = args.command {
        tracing::info!(
            "Persistent testnet configured. data dir: {}",
            data_dir.display()
        );
        builder = builder.persistent(data_dir);
    }

    let testnet = builder.build().await?;
    tracing::info!("Testnet running");
    tracing::info!(
        "DHT Bootstrap Nodes: {}",
        testnet.bootstrap_nodes().join(", ")
    );
    tracing::info!("Pkarr Relay: {}", testnet.pkarr_relay().local_url());
    tracing::info!("Http Relay: {}", testnet.http_relay().local_url());
    tracing::info!(
        "Homeserver ICANN HTTP: {}",
        testnet.homeserver_app().icann_http_url()
    );
    tracing::info!(
        "Homeserver Pubky HTTPS: {}",
        testnet.homeserver_app().pubky_url()
    );
    if let Some(admin_server) = testnet.homeserver_app().admin_server() {
        tracing::info!("Homeserver admin: http://{}", admin_server.listen_socket());
    }
    if let Some(metrics_server) = testnet.homeserver_app().metrics_server() {
        tracing::info!(
            "Homeserver metrics: http://{}",
            metrics_server.listen_socket()
        );
    }

    tokio::signal::ctrl_c().await?;
    drop(testnet);

    // Cleanup ephemeral test databases. They are only registered for the drop
    // after the testnet is dropped, and a persistent testnet registers none.
    pubky_testnet::drop_test_databases().await;

    Ok(())
}
