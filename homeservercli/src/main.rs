mod cli;
mod commands;
mod config;
mod helpers;
mod logs;

use clap::Parser;
use cli::Cli;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    logs::init(cli.verbosity.log_level_filter());

    let data_dir = cli
        .data_dir
        .clone()
        .or_else(config::default_config_dir_path);
    let config = config::ConfigToml::load(data_dir.as_deref())?;

    commands::execute(cli, config)?;
    Ok(())
}
