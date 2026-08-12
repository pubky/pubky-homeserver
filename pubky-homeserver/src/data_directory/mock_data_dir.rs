use std::path::Path;

use super::DataDir;

/// Mock data directory for testing.
///
/// It uses a temporary directory to store all data in. The data is removed as soon as the object is dropped.
///

#[derive(Debug, Clone)]
pub struct MockDataDir {
    pub(crate) temp_dir: std::sync::Arc<tempfile::TempDir>,
    /// The configuration for the homeserver.
    pub config_toml: super::ConfigToml,
    /// The keypair for the homeserver.
    pub keypair: pubky_common::crypto::Keypair,
}

impl MockDataDir {
    /// Create a new DataDirMock with a temporary directory.
    ///
    /// If keypair is not provided, a new one will be generated.
    pub fn new(
        config_toml: super::ConfigToml,
        keypair: Option<pubky_common::crypto::Keypair>,
    ) -> anyhow::Result<Self> {
        let keypair = keypair.unwrap_or_else(pubky_common::crypto::Keypair::random);
        Ok(Self {
            temp_dir: std::sync::Arc::new(tempfile::TempDir::new()?),
            config_toml,
            keypair,
        })
    }

    /// Creates a mock data directory with a config and keypair appropriate for testing.
    ///
    /// Uses [`super::ConfigToml::default_test_config()`] which enables the admin server.
    /// For lightweight tests, use [`MockDataDir::new()`] with
    /// [`super::ConfigToml::minimal_test_config()`].
    #[cfg(any(test, feature = "testing"))]
    pub fn test() -> Self {
        let config = super::ConfigToml::default_test_config();
        let keypair = pubky_common::crypto::Keypair::from_secret(&[0; 32]);
        Self::new(config, Some(keypair)).expect("failed to create MockDataDir")
    }
}

impl Default for MockDataDir {
    fn default() -> Self {
        Self::test()
    }
}

impl DataDir for MockDataDir {
    fn path(&self) -> &Path {
        self.temp_dir.path()
    }

    fn resolve_database_mode(
        &self,
        conf: &super::ConfigToml,
    ) -> anyhow::Result<crate::persistence::sql::DatabaseMode> {
        crate::persistence::sql::DatabaseMode::resolve_test(conf.general.database_url.clone())
    }

    fn ensure_data_dir_exists_and_is_writable(&self) -> anyhow::Result<()> {
        Ok(()) // Always ok because this is validated by the tempfile crate.
    }

    fn read_or_create_config_file(&self) -> anyhow::Result<super::ConfigToml> {
        Ok(self.config_toml.clone())
    }

    fn read_or_create_keypair(&self) -> anyhow::Result<pubky_common::crypto::Keypair> {
        Ok(self.keypair.clone())
    }
}
