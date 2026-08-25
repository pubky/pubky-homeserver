use super::ConfigToml;
use crate::persistence::sql::DatabaseMode;
use dyn_clone::DynClone;
use std::path::Path;

/// A trait for the data directory.
/// Used to abstract the data directory from the rest of the code.
///
/// To create a real dir and a test dir.
pub trait DataDir: std::fmt::Debug + DynClone + Send + Sync {
    /// Returns the path to the data directory.
    fn path(&self) -> &Path;
    /// Makes sure the data directory exists.
    /// Create the directory if it doesn't exist.
    fn ensure_data_dir_exists_and_is_writable(&self) -> anyhow::Result<()>;

    /// Reads the config file from the data directory.
    /// Creates a default config file if it doesn't exist.
    fn read_or_create_config_file(&self) -> anyhow::Result<ConfigToml>;

    /// Reads the secret file from the data directory.
    /// Creates a new secret file if it doesn't exist.
    fn read_or_create_keypair(&self) -> anyhow::Result<pubky_common::crypto::Keypair>;

    /// Resolve how the homeserver should connect to its database.
    ///
    /// Each implementation selects the appropriate database lifecycle.
    fn resolve_database_mode(&self, conf: &ConfigToml) -> anyhow::Result<DatabaseMode>;
}

dyn_clone::clone_trait_object!(DataDir);
