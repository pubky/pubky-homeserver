use std::num::NonZeroUsize;

#[cfg(feature = "storage-gcs")]
use super::google_bucket_config::GoogleBucketConfig;

/// The storage config. Files can be either stored in a file system, in memory, or in a Google bucket
/// depending on the configuration.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StorageConfigToml {
    /// Files are stored in a Google bucket.
    #[cfg(feature = "storage-gcs")]
    GoogleBucket(GoogleBucketConfig),
    /// Files are stored in memory.
    #[cfg(any(feature = "storage-memory", test))]
    InMemory,
    /// Files are stored on the local file system.
    FileSystem,
}

/// The `[storage]` configuration for the backend, storage quota, and upload limit.
///
/// # Migrating Rust struct literals
///
/// Adding `max_concurrent_uploads_per_user_per_replica` breaks Rust literals
/// that specify only `backend` and `default_quota_mb`. Keep those values and
/// add `..ConfigToml::default().storage` to use the homeserver's default upload
/// limit. Existing TOML files pick up that default automatically.
///
/// ```
/// use pubky_homeserver::{
///     storage_config::{StorageConfigToml, StorageToml},
///     ConfigToml,
/// };
///
/// let storage = StorageToml {
///     backend: StorageConfigToml::FileSystem,
///     default_quota_mb: Some(1024),
///     ..ConfigToml::default().storage
/// };
/// ```
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StorageToml {
    /// Which backend to use (file_system, google_bucket, in_memory).
    #[serde(flatten)]
    pub backend: StorageConfigToml,
    /// Default per-user storage quota in MB.
    /// Omit for unlimited. `0` means zero storage (not unlimited).
    pub default_quota_mb: Option<u64>,
    /// Maximum simultaneous uploads for one user on this homeserver replica.
    #[serde(default = "default_upload_limit")]
    pub max_concurrent_uploads_per_user_per_replica: NonZeroUsize,
}

// Also honor the embedded default for callers deserializing old TOML directly.
fn default_upload_limit() -> NonZeroUsize {
    crate::ConfigToml::default()
        .storage
        .max_concurrent_uploads_per_user_per_replica
}
