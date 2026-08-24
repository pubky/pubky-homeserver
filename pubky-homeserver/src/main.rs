use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use pubky_homeserver::{tracing::init_tracing_logs_if_set, HomeserverApp, PersistentDataDir};

fn default_config_dir_path() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".pubky")
}

/// Validate that the data_dir path is a directory.
/// It doesnt need to exist, but if it does, it needs to be a directory.
fn validate_config_dir_path(path: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(path);
    if path.exists() && path.is_file() {
        return Err(format!("Given path is not a directory: {}", path.display()));
    }
    Ok(path)
}

#[derive(Parser, Debug)]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Path to data directory. Defaults to ~/.pubky
    #[clap(short, long, default_value_os_t = default_config_dir_path(), value_parser = validate_config_dir_path)]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialize the data directory (config and keypair) without starting the server.
    Init,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        Some(Command::Init) => {
            let data_dir = PersistentDataDir::new(args.data_dir);
            data_dir.init()?;
            println!(
                "Data directory initialized at {}.",
                data_dir.path().display()
            );
        }
        None => {
            init_tracing_logs_if_set(&args.data_dir)?;

            tracing::info!("Use data directory: {}", args.data_dir.display());
            let server = HomeserverApp::start_with_persistent_data_dir_path(args.data_dir).await?;

            tracing::info!(
                "Homeserver HTTP listening on {}",
                server.client_server().icann_http_url_string()
            );

            tracing::info!(
                "Homeserver Pubky TLS listening on {}",
                server.client_server().pubky_tls_dns_url_string(),
            );
            tracing::info!(
                "Homeserver Pubky TLS listening on {}",
                server.client_server().pubky_tls_ip_url_ring()
            );
            if let Some(admin_server) = server.admin_server() {
                tracing::info!(
                    "Admin server listening on http://{}",
                    admin_server.listen_socket()
                );
            }
            if let Some(metrics_server) = server.metrics_server() {
                tracing::info!(
                    "Metrics server listening on http://{}",
                    metrics_server.listen_socket()
                );
            }

            tracing::info!("Press Ctrl+C to stop the Homeserver");
            tokio::signal::ctrl_c().await?;

            tracing::info!("Shutting down Homeserver");
        }
    }

    Ok(())
}
