use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use url::Url;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AdminToml {
    pub admin_password: Option<String>,
    pub admin_endpoint: Option<Url>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ConfigToml {
    pub admin: AdminToml,
}

impl ConfigToml {
    pub fn load(data_dir: Option<&Path>) -> Result<Option<Self>> {
        let Some(dir) = data_dir else {
            return Ok(None);
        };

        let config_path = dir.join("config.toml");
        let content = match std::fs::read_to_string(&config_path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                log::debug!(
                    "config file not found at '{}', skipping",
                    config_path.display()
                );
                return Ok(None);
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to read config file: {}", config_path.display())
                })
            }
        };
        let config = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file: {}", config_path.display()))?;
        Ok(Some(config))
    }
}
