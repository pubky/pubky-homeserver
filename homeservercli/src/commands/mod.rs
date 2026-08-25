mod context;
pub mod error;
pub mod info;
pub mod signup_tokens;
pub mod users;

use crate::cli::Cli;
use crate::config::ConfigToml;
use anyhow::Result;
use clap::Subcommand;
use context::AdminContext;

#[derive(Subcommand, Debug)]
pub enum Commands {
    Info(info::InfoArgs),
    SignupTokens(signup_tokens::SignupTokensCmd),
    Users(users::UsersCmd),
}

pub fn execute(cli: Cli, config: Option<ConfigToml>) -> Result<()> {
    let context = AdminContext::resolve(cli.admin_password, cli.admin_endpoint, config.as_ref())?;

    match cli.command {
        Commands::Info(args) => info::run(context, &args)?,
        Commands::SignupTokens(cmd) => cmd.run(context)?,
        Commands::Users(cmd) => cmd.run(context)?,
    };
    Ok(())
}
