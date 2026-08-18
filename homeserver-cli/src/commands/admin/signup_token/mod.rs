use clap::{Args, Subcommand};
pub mod generate;
use crate::commands::admin::context::AdminContext;
pub mod error;

#[derive(Args, Debug)]
#[command(about = "Manage signup invite tokens")]
pub struct SignupTokenCmd {
    #[command(subcommand)]
    pub subcommand: SignupTokenSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum SignupTokenSubcommands {
    Generate(generate::GenerateArgs),
}

impl SignupTokenCmd {
    pub fn run(&self, context: AdminContext) -> anyhow::Result<()> {
        match &self.subcommand {
            SignupTokenSubcommands::Generate(sbu_args) => {
                generate::run(context, sbu_args)?;
            }
        }
        Ok(())
    }
}
