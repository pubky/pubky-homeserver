mod admin;

use crate::cli::Cli;
use crate::config::ConfigToml;
use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum Commands {
    Admin(admin::AdminCmd),
}

pub fn execute(cli: Cli, config: Option<ConfigToml>) -> Result<()> {
    match cli.command {
        Commands::Admin(cmd) => cmd.run(config)?,
    };
    Ok(())
}
