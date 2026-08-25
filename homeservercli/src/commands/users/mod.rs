use clap::{Args, Subcommand};
pub mod disable;
pub mod enable;
pub mod quotaget;
pub mod quotaset;
use crate::commands::context::AdminContext;
pub mod error;

#[derive(Args, Debug)]
#[command(about = "Manage user accounts", flatten_help = true)]
pub struct UsersCmd {
    #[command(subcommand)]
    pub subcommand: UsersSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum UsersSubcommands {
    Enable(enable::EnableArgs),
    Disable(disable::DisableArgs),
    QuotaSet(quotaset::SetArgs),
    QuotaGet(quotaget::GetArgs),
}

impl UsersCmd {
    pub fn run(&self, context: AdminContext) -> anyhow::Result<()> {
        match &self.subcommand {
            UsersSubcommands::Enable(sbu_args) => {
                enable::run(context, sbu_args)?;
            }
            UsersSubcommands::Disable(sbu_args) => {
                disable::run(context, sbu_args)?;
            }
            UsersSubcommands::QuotaSet(sbu_args) => {
                quotaset::run(context, sbu_args)?;
            }
            UsersSubcommands::QuotaGet(sbu_args) => {
                quotaget::run(context, sbu_args)?;
            }
        }
        Ok(())
    }
}
