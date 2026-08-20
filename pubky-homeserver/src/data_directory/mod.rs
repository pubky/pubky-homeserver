//! Server data directory and configuration.
//!
//! Manages the on-disk data directory (default `~/.pubky/`) which contains the
//! server keypair, `config.toml`, and file storage. [`ConfigToml`] is loaded by
//! merging embedded defaults with user overrides and controls all server behavior
//! (listen addresses, signup mode, storage backend, rate limits, logging, etc.).

mod config_toml;
mod data_dir;
#[cfg(any(test, feature = "testing"))]
mod mock_data_dir;
mod persistent_data_dir;
/// Opendal config for the TomlConfig.
pub mod storage_config;

mod log_level;
pub use config_toml::{AdminToml, ConfigReadError, ConfigToml, LoggingToml, MetricsToml};
pub use data_dir::DataDir;
#[cfg(any(test, feature = "testing"))]
pub use mock_data_dir::MockDataDir;
pub use persistent_data_dir::PersistentDataDir;
