use crate::commands::Commands;
use clap::Parser;
use clap_verbosity_flag::Verbosity;
use std::path::PathBuf;
use url::Url;

fn validate_config_dir_path(path: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(path);
    if path.exists() && path.is_file() {
        return Err(format!("Given path is not a directory: {}", path.display()));
    }
    Ok(path)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[clap(short, long, env = "PUBKY_HOMESERVER_DATA_DIR", value_parser = validate_config_dir_path)]
    pub data_dir: Option<PathBuf>,

    #[arg(long, global = true, env = "PUBKY_HOMESERVER_ADMIN_PASSWORD")]
    pub admin_password: Option<String>,

    #[arg(long, global = true, env = "PUBKY_HOMESERVER_ADMIN_ENDPOINT")]
    pub admin_endpoint: Option<Url>,

    #[command(subcommand)]
    pub command: Commands,

    #[command(flatten)]
    pub verbosity: Verbosity,
}
