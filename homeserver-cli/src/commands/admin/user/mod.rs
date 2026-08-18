use clap::{Args, Subcommand};
pub mod disable;
pub mod enable;
use crate::commands::admin::context::AdminContext;
pub mod error;

#[derive(Args, Debug)]
#[command(about = "Manage user accounts")]
pub struct UserCmd {
    #[command(subcommand)]
    pub subcommand: UserSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum UserSubcommands {
    Enable(enable::EnableArgs),
    Disable(disable::DisableArgs),
}

impl UserCmd {
    pub fn run(&self, context: AdminContext) -> anyhow::Result<()> {
        match &self.subcommand {
            UserSubcommands::Enable(sbu_args) => {
                enable::run(context, sbu_args)?;
            }
            UserSubcommands::Disable(sbu_args) => {
                disable::run(context, sbu_args)?;
            }
        }
        Ok(())
    }
}
