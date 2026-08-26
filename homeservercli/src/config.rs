use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ConfigToml {
    #[serde(default)]
    pub admin: AdminToml,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AdminToml {
    #[serde(default = "default_admin_password")]
    pub admin_password: Option<String>,
    #[serde(default = "default_listen_socket")]
    pub listen_socket: Option<String>,
}

impl Default for AdminToml {
    fn default() -> Self {
        Self {
            admin_password: default_admin_password(),
            listen_socket: default_listen_socket(),
        }
    }
}

fn default_admin_password() -> Option<String> {
    Some("admin".to_string())
}
fn default_listen_socket() -> Option<String> {
    Some("localhost:6288".to_string())
}

/// Default directory to look for `config.toml` when no data dir is provided
/// via `--data-dir` or `PUBKY_HOMESERVER_DATA_DIR`: `~/.config`.
pub fn default_config_dir_path() -> Option<PathBuf> {
    Some(dirs::home_dir().unwrap_or_default().join(".pubky"))
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
