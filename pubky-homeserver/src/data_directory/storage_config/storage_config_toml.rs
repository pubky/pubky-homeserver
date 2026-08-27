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

/// The `[storage]` TOML section: backend selection and storage limits.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StorageToml {
    /// Which backend to use (file_system, google_bucket, in_memory).
    #[serde(flatten)]
    pub backend: StorageConfigToml,
    /// Default per-user storage quota in MB.
    /// Omit for unlimited. `0` means zero storage (not unlimited).
    pub default_quota_mb: Option<u64>,
    /// Maximum combined size of in-progress admin DAV uploads in MB.
    #[serde(default = "default_admin_dav_spool_limit_mb")]
    pub admin_dav_spool_limit_mb: u64,
}

const fn default_admin_dav_spool_limit_mb() -> u64 {
    1024
}
