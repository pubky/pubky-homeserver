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

    let config = config::ConfigToml::load(cli.data_dir.as_deref())?;

    commands::execute(cli, config)?;
    Ok(())
}
