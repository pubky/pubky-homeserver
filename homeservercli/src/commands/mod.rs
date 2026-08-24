mod context;
pub mod error;
pub mod info;
pub mod quota;
pub mod signup_token;
pub mod user;

use crate::cli::Cli;
use crate::config::ConfigToml;
use anyhow::Result;
use clap::Subcommand;
use context::AdminContext;

#[derive(Subcommand, Debug)]
pub enum Commands {
    Info(info::InfoArgs),
    SignupToken(signup_token::SignupTokenCmd),
    User(user::UserCmd),
    Quota(quota::QuotaCmd),
}

pub fn execute(cli: Cli, config: Option<ConfigToml>) -> Result<()> {
    let context = AdminContext::resolve(cli.admin_password, cli.admin_endpoint, config.as_ref())?;

    match cli.command {
        Commands::Info(args) => info::run(context, &args)?,
        Commands::SignupToken(cmd) => cmd.run(context)?,
        Commands::User(cmd) => cmd.run(context)?,
        Commands::Quota(cmd) => cmd.run(context)?,
    };
    Ok(())
}
