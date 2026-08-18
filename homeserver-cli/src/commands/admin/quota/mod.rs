use clap::{Args, Subcommand};
pub mod error;
pub mod get;
pub mod set;
use crate::commands::admin::context::AdminContext;

#[derive(Args, Debug)]
#[command(about = "Manage per-user quota settings")]
pub struct QuotaCmd {
    #[command(subcommand)]
    pub subcommand: QuotaSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum QuotaSubcommands {
    Get(get::GetArgs),
    Set(set::SetArgs),
}

impl QuotaCmd {
    pub fn run(&self, context: AdminContext) -> anyhow::Result<()> {
        match &self.subcommand {
            QuotaSubcommands::Get(sbu_args) => {
                get::run(context, sbu_args)?;
            }
            QuotaSubcommands::Set(sbu_args) => {
                set::run(context, sbu_args)?;
            }
        }
        Ok(())
    }
}
