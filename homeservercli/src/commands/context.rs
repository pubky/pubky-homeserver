use anyhow::{Context, Result};
use url::Url;

use crate::config::ConfigToml;

use crate::helpers::http_client::{transform_to_url, Auth, HttpClient};

pub struct AdminContext {
    pub client: HttpClient,
}

impl AdminContext {
    pub fn resolve(
        admin_password: Option<String>,
        admin_endpoint: Option<Url>,
        config: Option<&ConfigToml>,
    ) -> Result<Self> {
        let password = resolve_password(admin_password, config)?;
        let endpoint = resolve_endpoint(admin_endpoint, config)?;
        Ok(Self {
            client: HttpClient::new(endpoint, Auth::AdminPassword(password))?,
        })
    }
}

fn resolve_password(admin_password: Option<String>, config: Option<&ConfigToml>) -> Result<String> {
    admin_password
        .or_else(|| config.and_then(|c| c.admin.admin_password.clone()))
        .context("Missing admin password. Provide it via '--admin-password', the PUBKY_HOMESERVER_ADMIN_PASSWORD environment variable, or in the config file.")
}

fn resolve_endpoint(admin_endpoint: Option<Url>, config: Option<&ConfigToml>) -> Result<Url> {
    admin_endpoint
        .or_else(|| {
            config
                .and_then(|c| c.admin.listen_socket.clone())
                .and_then(|s| transform_to_url(&s))
        })
        .context("Missing admin endpoint. Provide it via '--admin-endpoint' or in the config file.")
}
