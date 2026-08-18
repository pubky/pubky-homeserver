use crate::commands::Commands;
use clap::Parser;
use clap_verbosity_flag::Verbosity;
use std::path::PathBuf;

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
    #[clap(short, long, value_parser = validate_config_dir_path)]
    pub data_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,

    #[command(flatten)]
    pub verbosity: Verbosity,
}
