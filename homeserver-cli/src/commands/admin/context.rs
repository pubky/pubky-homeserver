use anyhow::{Context, Result};
use url::Url;

use crate::commands::admin::AdminCmd;
use crate::config::ConfigToml;

use crate::helpers::http_client::{Auth, HttpClient};

pub struct AdminContext {
    pub client: HttpClient,
}

impl AdminContext {
    pub fn resolve(cmd: &AdminCmd, config: Option<&ConfigToml>) -> Result<Self> {
        let password = resolve_password(cmd, config)?;
        let endpoint = resolve_endpoint(cmd, config)?;
        Ok(Self {
            client: HttpClient::new(endpoint, Auth::AdminPassword(password))?,
        })
    }
}

fn resolve_password(cmd: &AdminCmd, config: Option<&ConfigToml>) -> Result<String> {
    if cmd.admin_password {
        return rpassword::prompt_password("Provide Homeserver Admin Password: ")
            .context("Failed to read admin password from terminal");
    }
    config
        .and_then(|c| c.admin.admin_password.clone())
        .context("Missing admin password. Provide it via '--admin-password' (interactive prompt) or in the config file.")
}

fn resolve_endpoint(cmd: &AdminCmd, config: Option<&ConfigToml>) -> Result<Url> {
    cmd.admin_endpoint
        .clone()
        .or_else(|| config.and_then(|c| c.admin.admin_endpoint.clone()))
        .context("Missing admin endpoint. Provide it via '--admin-endpoint' or in the config file.")
}
