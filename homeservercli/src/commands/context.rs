use anyhow::{Context, Result};
use url::Url;

use crate::config::ConfigToml;

use crate::helpers::http_client::{Auth, HttpClient};

pub struct AdminContext {
    pub client: HttpClient,
}

impl AdminContext {
    pub fn resolve(
        admin_password: Option<String>,
        listen_socket: Option<Url>,
        config: Option<&ConfigToml>,
    ) -> Result<Self> {
        let password = resolve_password(admin_password, config)?;
        let endpoint = resolve_endpoint(listen_socket, config)?;
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

fn resolve_endpoint(listen_socket: Option<Url>, config: Option<&ConfigToml>) -> Result<Url> {
    listen_socket
        .or_else(|| config.and_then(|c| c.admin.listen_socket.clone()))
        .context("Missing admin endpoint. Provide it via '--listen-socket' or in the config file.")
}
