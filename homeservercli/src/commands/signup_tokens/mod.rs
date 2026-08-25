use clap::{Args, Subcommand};
pub mod generate;
use crate::commands::context::AdminContext;
pub mod error;

#[derive(Args, Debug)]
#[command(about = "Manage signup invite tokens", flatten_help = true)]
pub struct SignupTokensCmd {
    #[command(subcommand)]
    pub subcommand: SignupTokensSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum SignupTokensSubcommands {
    Generate(generate::GenerateArgs),
}

impl SignupTokensCmd {
    pub fn run(&self, context: AdminContext) -> anyhow::Result<()> {
        match &self.subcommand {
            SignupTokensSubcommands::Generate(sbu_args) => {
                generate::run(context, sbu_args)?;
            }
        }
        Ok(())
    }
}
