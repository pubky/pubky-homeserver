use super::ConfigToml;

use std::{
    fs::{copy, create_dir_all},
    io::Write,
    path::{Path, PathBuf},
};

/// The data directory for the homeserver.
///
/// This is the directory that will store the homeservers data.
///
#[derive(Debug, Clone)]
pub struct PersistentDataDir {
    expanded_path: PathBuf,
}

impl PersistentDataDir {
    /// Creates a new data directory.
    /// `path` will be expanded to the home directory if it starts with "~".
    pub fn new(path: PathBuf) -> Self {
        Self {
            expanded_path: Self::expand_home_dir(path),
        }
    }

    /// Expands the data directory to the home directory if it starts with "~".
    /// Return the full path to the data directory.
    fn expand_home_dir(path: PathBuf) -> PathBuf {
        let path = match path.to_str() {
            Some(path) => path,
            None => {
                // Path not valid utf-8 so we can't expand it.
                return path;
            }
        };

        if path.starts_with("~/") {
            if let Some(home) = dirs::home_dir() {
                let without_home = path.strip_prefix("~/").expect("Invalid ~ prefix");
                let joined = home.join(without_home);
                return joined;
            }
        }
        PathBuf::from(path)
    }

    /// Returns the full path to the data directory.
    pub fn path(&self) -> &Path {
        &self.expanded_path
    }

    /// Returns the config file path in this directory.
    pub fn get_config_file_path(&self) -> PathBuf {
        self.expanded_path.join("config.toml")
    }

    fn write_sample_config_file(&self) -> anyhow::Result<()> {
        let config_string = ConfigToml::sample_string();
        let config_file_path = self.get_config_file_path();
        let mut config_file = std::fs::File::create(config_file_path)?;
        config_file.write_all(config_string.as_bytes())?;
        Ok(())
    }

    /// Returns the path to the secret file.
    pub fn get_secret_file_path(&self) -> PathBuf {
        self.expanded_path.join("secret")
    }

    /// Copy a config file into this data directory.
    /// Errors if a `config.toml` already exists at the destination.
    pub fn seed_config(&self, source: &Path) -> anyhow::Result<()> {
        let config_path = self.get_config_file_path();
        if config_path.exists() {
            anyhow::bail!("config.toml already exists at {}", config_path.display());
        }
        create_dir_all(self.path())?;
        copy(source, &config_path)?;
        tracing::info!("Copied {} → {}", source.display(), config_path.display());
        Ok(())
    }

    /// Initialize the data directory without starting the server.
    ///
    /// Creates the directory, writes a sample config file (if absent),
    /// and generates a server keypair (if absent).
    pub fn init(&self) -> anyhow::Result<()> {
        self.bootstrap().map(|_| ())
    }

    /// Makes sure the data directory exists.
    /// Create the directory if it doesn't exist.
    pub fn ensure_exists_and_is_writable(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.expanded_path)?;

        // Check if we can write to the data directory
        let test_file_path = self
            .expanded_path
            .join("test_write_f2d560932f9b437fa9ef430ba436d611"); // random file name to not conflict with anything
        std::fs::write(test_file_path.clone(), b"test")
            .map_err(|err| anyhow::anyhow!("Failed to write to data directory: {}", err))?;
        std::fs::remove_file(test_file_path)
            .map_err(|err| anyhow::anyhow!("Failed to write to data directory: {}", err))?;
        Ok(())
    }

    /// Reads the config file from the data directory.
    /// Creates a default config file if it doesn't exist.
    pub fn read_or_create_config_file(&self) -> anyhow::Result<ConfigToml> {
        let config_file_path = self.get_config_file_path();
        if !config_file_path.exists() {
            self.write_sample_config_file()?;
        }
        let config = ConfigToml::from_file(config_file_path)?;
        Ok(config)
    }

    /// Reads the secret file. Creates a new secret file if it doesn't exist.
    pub fn read_or_create_keypair(&self) -> anyhow::Result<pubky_common::crypto::Keypair> {
        let secret_file_path = self.get_secret_file_path();
        if !secret_file_path.exists() {
            // Create a new secret file
            pubky_common::crypto::Keypair::random().write_secret_key_file(&secret_file_path)?;
            tracing::info!("Secret file created at {}", secret_file_path.display());
        }
        // Read the secret file
        let keypair = pubky_common::crypto::Keypair::from_secret_key_file(&secret_file_path)?;
        Ok(keypair)
    }

    /// Seed a specific keypair if no secret file exists yet.
    /// This is a no-op if the secret file already exists on disk.
    pub fn seed_keypair_if_missing(
        &self,
        keypair: &pubky_common::crypto::Keypair,
    ) -> anyhow::Result<()> {
        let secret_file = self.get_secret_file_path();
        if !secret_file.exists() {
            keypair.write_secret_key_file(&secret_file)?;
            tracing::info!(
                "Seeded keypair (pubkey {}) at {}",
                keypair.public_key(),
                secret_file.display()
            );
        }
        Ok(())
    }

    /// Bootstrap the data directory: ensure it exists, read config and keypair.
    /// Returns the resolved `(PathBuf, ConfigToml, Keypair)` ready for `AppContext::new`.
    pub fn bootstrap(
        &self,
    ) -> anyhow::Result<(PathBuf, ConfigToml, pubky_common::crypto::Keypair)> {
        self.ensure_exists_and_is_writable()?;
        let config = self.read_or_create_config_file()?;
        let keypair = self.read_or_create_keypair()?;
        Ok((self.expanded_path.clone(), config, keypair))
    }
}

impl Default for PersistentDataDir {
    fn default() -> Self {
        Self::new(PathBuf::from("~/.pubky"))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use tempfile::TempDir;

    /// Test that the home directory is expanded correctly.
    #[test]
    pub fn test_expand_home_dir() {
        let data_dir = PersistentDataDir::new(PathBuf::from("~/.pubky"));
        let homedir = dirs::home_dir().unwrap();
        let expanded_path = homedir.join(".pubky");
        assert_eq!(data_dir.expanded_path, expanded_path);
    }

    /// Test that the data directory is created if it doesn't exist.
    #[test]
    pub fn test_ensure_data_dir_exists_and_is_accessible() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path().join(".pubky");
        let data_dir = PersistentDataDir::new(test_path.clone());

        data_dir.ensure_exists_and_is_writable().unwrap();
        assert!(test_path.exists());
        // temp_dir will be automatically cleaned up when it goes out of scope
    }

    #[test]
    pub fn test_get_default_config_file_path_exists() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path().join(".pubky");
        let data_dir = PersistentDataDir::new(test_path.clone());
        data_dir.ensure_exists_and_is_writable().unwrap();
        let config_file_path = data_dir.get_config_file_path();
        assert!(!config_file_path.exists()); // Should not exist yet

        let mut config_file = std::fs::File::create(config_file_path.clone()).unwrap();
        config_file.write_all(b"test").unwrap();
        assert!(config_file_path.exists()); // Should exist now
                                            // temp_dir will be automatically cleaned up when it goes out of scope
    }

    #[test]
    pub fn test_read_or_create_config_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path().join(".pubky");
        let data_dir = PersistentDataDir::new(test_path.clone());
        data_dir.ensure_exists_and_is_writable().unwrap();
        let _ = data_dir.read_or_create_config_file().unwrap(); // Should create a default config file
        assert!(data_dir.get_config_file_path().exists());

        let _ = data_dir.read_or_create_config_file().unwrap(); // Should read the existing file
        assert!(data_dir.get_config_file_path().exists());
    }

    #[test]
    pub fn test_read_or_create_config_file_dont_override_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path().join(".pubky");
        let data_dir = PersistentDataDir::new(test_path.clone());
        data_dir.ensure_exists_and_is_writable().unwrap();

        // Write a broken config file
        let config_file_path = data_dir.get_config_file_path();
        std::fs::write(config_file_path.clone(), b"test").unwrap();
        assert!(config_file_path.exists()); // Should exist now

        // Try to read the config file and fail because config is broken
        let read_result = data_dir.read_or_create_config_file();
        assert!(read_result.is_err());

        // Make sure the broken config file is still there
        let content = std::fs::read_to_string(config_file_path).unwrap();
        assert_eq!(content, "test");
    }

    #[test]
    pub fn test_create_secret_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path().join(".pubky");
        let data_dir = PersistentDataDir::new(test_path.clone());
        data_dir.ensure_exists_and_is_writable().unwrap();

        let _ = data_dir.read_or_create_keypair().unwrap();
        assert!(data_dir.get_secret_file_path().exists());
    }

    #[test]
    pub fn test_dont_override_existing_secret_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path().join(".pubky");
        let data_dir = PersistentDataDir::new(test_path.clone());
        data_dir.ensure_exists_and_is_writable().unwrap();

        // Create a secret file
        let secret_file_path = data_dir.get_secret_file_path();
        std::fs::write(secret_file_path.clone(), b"test").unwrap();

        let result = data_dir.read_or_create_keypair();
        assert!(result.is_err());
        assert!(data_dir.get_secret_file_path().exists());
        let content = std::fs::read_to_string(secret_file_path).unwrap();
        assert_eq!(content, "test");
    }

    #[test]
    pub fn test_trim_secret_file_content() {
        let temp_dir = TempDir::new().unwrap();
        let test_path = temp_dir.path().join(".pubky");
        let data_dir = PersistentDataDir::new(test_path.clone());
        data_dir.ensure_exists_and_is_writable().unwrap();

        // Create a secret file
        let keypair = pubky_common::crypto::Keypair::random();
        let secret_file_path = data_dir.get_secret_file_path();
        let file_content = format!("\n {}\n \n", hex::encode(keypair.secret_key()));
        std::fs::write(secret_file_path.clone(), file_content).unwrap();

        let result = data_dir.read_or_create_keypair();
        assert!(result.is_ok());
        let read_keypair = result.unwrap();
        assert_eq!(read_keypair.secret_key(), keypair.secret_key());
    }
}
