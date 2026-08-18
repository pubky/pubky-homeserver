use crate::config::ConfigToml;
use clap::{Args, Subcommand};
use url::Url;
mod context;
pub mod error;
pub mod info;
pub mod quota;
pub mod signup_token;
pub mod user;
use context::AdminContext;

#[derive(Args, Debug)]
#[command(about = "Administrate a pubky homeserver")]
pub struct AdminCmd {
    #[arg(long)]
    pub admin_password: bool,

    #[arg(long)]
    pub admin_endpoint: Option<Url>,

    #[command(subcommand)]
    pub subcommand: AdminSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum AdminSubcommands {
    Info(info::InfoArgs),
    SignupToken(signup_token::SignupTokenCmd),
    User(user::UserCmd),
    Quota(quota::QuotaCmd),
}

impl AdminCmd {
    pub fn run(&self, config: Option<ConfigToml>) -> anyhow::Result<()> {
        let context = AdminContext::resolve(self, config.as_ref())?;

        match &self.subcommand {
            AdminSubcommands::Info(sbu_args) => {
                info::run(context, sbu_args)?;
            }
            AdminSubcommands::SignupToken(sbu_args) => {
                sbu_args.run(context)?;
            }
            AdminSubcommands::User(sbu_args) => {
                sbu_args.run(context)?;
            }
            AdminSubcommands::Quota(sbu_args) => {
                sbu_args.run(context)?;
            }
        }
        Ok(())
    }
}
