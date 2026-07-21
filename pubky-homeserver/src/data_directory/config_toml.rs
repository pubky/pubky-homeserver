//! Configuration file for the homeserver.
//!
//! All default values live exclusively in `config.default.toml`.
//! This module embeds that file at compile-time, parses it once,
//! and lets callers optionally layer their own TOML on top.

#[cfg(any(test, feature = "testing"))]
use super::storage_config::StorageConfigToml;
use super::{
    domain_port::DomainPort,
    quota_config::{BandwidthQuota, PathLimit},
    storage_config::StorageToml,
    Domain, SignupMode,
};

use crate::{
    data_directory::log_level::{LogLevel, TargetLevel},
    persistence::sql::ConnectionString,
    shared::toml_merge,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    fs,
    net::{IpAddr, SocketAddr},
    num::{NonZeroU32, NonZeroU64},
    path::Path,
    str::FromStr,
};
use url::Url;

/// Embedded copy of the default configuration (single source of truth for defaults)
pub const DEFAULT_CONFIG: &str = include_str!("config.default.toml");

/// Example configuration file
pub const SAMPLE_CONFIG: &str = include_str!("../../config.sample.toml");

/// Error that can occur when reading a configuration file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigReadError {
    /// The file did not exist or could not be read.
    #[error("config file not found: {0}")]
    ConfigFileNotFound(#[from] std::io::Error),
    /// The TOML was syntactically invalid.
    #[error("config file is not valid TOML: {0}")]
    ConfigFileNotValid(#[from] toml::de::Error),
    /// Failed to merge defaults with overrides.
    #[error("failed to merge embedded and user TOML: {0}")]
    ConfigMergeError(String),
}

/// Config structs

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PkdnsToml {
    pub public_ip: IpAddr,
    pub public_pubky_tls_port: Option<u16>,
    pub public_icann_http_port: Option<u16>,
    pub icann_domain: Option<Domain>,
    pub user_keys_republisher_interval: u64,
    pub dht_bootstrap_nodes: Option<Vec<DomainPort>>,
    pub dht_relay_nodes: Option<Vec<Url>>,
    pub dht_request_timeout_ms: Option<NonZeroU64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DriveToml {
    pub pubky_listen_socket: SocketAddr,
    pub icann_listen_socket: SocketAddr,
    /// Per-path request-count rate limits.
    pub rate_limits: Vec<PathLimit>,
}

/// Default bandwidth limits for the rate limiter.
///
/// Per-user defaults (`rate_read`, `rate_write`) are the system-wide
/// fallback values used when a user's quota is "Default" (NULL in DB).
/// Per-user overrides are managed via the admin API:
///   `PATCH /users/{pubkey}/quota`
///
/// `unauthenticated_ip_rate_read` is a fixed server-level limit for
/// anonymous requests (not overridable per-user).
///
/// Consumed by `BandwidthQuotaLimitLayer`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct DefaultQuotasToml {
    /// Default bandwidth limit for user reads / downloads (e.g. "10mb/s").
    /// Per-user DB overrides take precedence. `None` means no read throttling.
    pub rate_read: Option<BandwidthQuota>,
    /// Default bandwidth limit for user writes / uploads (e.g. "5mb/s").
    /// Per-user DB overrides take precedence. `None` means no write throttling.
    pub rate_write: Option<BandwidthQuota>,
    /// Default burst for read rate, in the rate's natural unit (e.g. MB for "…mb/s").
    /// Per-user DB overrides take precedence. `None` means burst equals rate.
    pub rate_read_burst: Option<NonZeroU32>,
    /// Default burst for write rate, in the rate's natural unit (e.g. MB for "…mb/s").
    /// Per-user DB overrides take precedence. `None` means burst equals rate.
    pub rate_write_burst: Option<NonZeroU32>,
    /// Server-level bandwidth limit for unauthenticated IP reads (e.g. "1mb/s").
    /// `None` means no read throttling for unauthenticated requests.
    pub unauthenticated_ip_rate_read: Option<BandwidthQuota>,
}

/// Admin server configuration
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AdminToml {
    /// Enable or disable the admin server
    pub enabled: bool,
    /// Socket address for the admin HTTP server
    pub listen_socket: SocketAddr,
    /// Password for admin authentication
    pub admin_password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct GeneralToml {
    pub signup_mode: SignupMode,
    /// Deprecated: use `[storage].default_quota_mb` instead.
    /// Kept for backwards compatibility: `0` means unlimited.
    /// Ignored when `[storage].default_quota_mb` is set.
    #[deprecated(
        since = "0.7.0",
        note = "use `storage.default_quota_mb` instead; this field is only resolved at TOML parse time"
    )]
    #[serde(default)]
    pub user_storage_quota_mb: u64,
    #[serde(default)]
    pub database_url: Option<ConnectionString>,
}

/// A config for Homeserver tracing subscriber configuration
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct LoggingToml {
    /// Main log level for global tracing_subscriber
    pub level: LogLevel,
    /// Per-module target log filters for global tracing_subscriber
    pub module_levels: Vec<TargetLevel>,
}

/// Metrics server configuration
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct MetricsToml {
    /// Enable or disable the metrics server
    pub enabled: bool,
    /// Socket address for Prometheus metrics endpoint. Should be isolated from public network.
    pub listen_socket: SocketAddr,
}

/// The overall application configuration, composed of several subsections.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ConfigToml {
    /// General application settings (signup mode, quotas, backups).
    pub general: GeneralToml,
    /// File‐drive API settings (listen sockets for Pubky TLS and HTTP).
    pub drive: DriveToml,
    /// Storage configuration: backend selection and default storage quota.
    pub storage: StorageToml,
    /// Default bandwidth limits for the rate limiter. Overridable per-user via admin API.
    pub default_quotas: DefaultQuotasToml,
    /// Administrative API configuration.
    pub admin: AdminToml,
    /// Metrics server configuration.
    pub metrics: MetricsToml,
    /// Peer‐to‐peer DHT / PKDNS settings (public endpoints, bootstrap, relays).
    pub pkdns: PkdnsToml,
    /// Logging configuration. If provided, the homeserver instance attempts to init
    /// global tracing:Subscriber. If environment variables are set, they override config settings
    pub logging: Option<LoggingToml>,
}

impl Default for ConfigToml {
    fn default() -> Self {
        ConfigToml::from_str(DEFAULT_CONFIG).expect("Embedded config.default.toml must be valid")
    }
}

impl Default for DriveToml {
    fn default() -> Self {
        ConfigToml::default().drive
    }
}

impl Default for AdminToml {
    fn default() -> Self {
        ConfigToml::default().admin
    }
}

impl Default for PkdnsToml {
    fn default() -> Self {
        ConfigToml::default().pkdns
    }
}

impl ConfigToml {
    /// Read and parse a configuration file, overlaying it on top of the embedded defaults.
    ///
    /// # Arguments
    /// * `path` - The path to the TOML configuration file
    ///
    /// # Returns
    /// * `Result<ConfigToml>` - The parsed configuration or an error if reading/parsing fails
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigReadError> {
        let raw = fs::read_to_string(path)?;
        Self::from_str_with_defaults(&raw)
    }

    /// Parse a raw TOML string, overlaying it on top of the embedded defaults.
    pub fn from_str_with_defaults(raw: &str) -> Result<Self, ConfigReadError> {
        // 1. Parse the embedded defaults
        let default_val: toml::Value = DEFAULT_CONFIG
            .parse()
            .expect("embedded defaults invalid TOML");
        // 2. Parse the user's overrides
        let user_val: toml::Value = raw.parse()?;
        // 3. Deep‐merge
        let merged_val = toml_merge::merge_with_options(default_val, user_val, true)
            .map_err(|e| ConfigReadError::ConfigMergeError(e.to_string()))?;

        // 4. Deserialize into our strongly typed struct (can fail with toml::de::Error)
        let mut config: Self = merged_val.try_into()?;
        config.resolve_legacy_quotas();
        Ok(config)
    }

    /// Render the embedded sample config but comment out every value,
    /// producing a handy template for end-users.
    pub fn sample_string() -> String {
        SAMPLE_CONFIG
            .lines()
            .map(|line| {
                let trimmed = line.trim_start();
                let is_comment = trimmed.starts_with('#');
                if !is_comment && !trimmed.is_empty() {
                    format!("# {}", line)
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<String>>()
            .join("\n")
    }

    /// Returns a default config tuned for unit tests with full features enabled.
    /// Note: Admin server is enabled, Metrics server is disabled.
    /// Use this for backward compatibility with external codebases using `EphemeralTestnet::start()`.
    #[cfg(any(test, feature = "testing"))]
    pub fn default_test_config() -> Self {
        let mut config = Self::default();
        config.general.database_url = None; // Resolved downstream via env var or default fallback.
        config.general.signup_mode = SignupMode::Open;
        // Use ephemeral ports (0) so parallel tests don't collide.
        config.drive.icann_listen_socket = SocketAddr::from(([127, 0, 0, 1], 0));
        config.drive.pubky_listen_socket = SocketAddr::from(([127, 0, 0, 1], 0));
        config.admin.enabled = true; // Enabled for backward compat
        config.admin.listen_socket = SocketAddr::from(([127, 0, 0, 1], 0));
        config.pkdns.icann_domain =
            Some(Domain::from_str("localhost").expect("localhost is a valid domain"));
        config.pkdns.dht_relay_nodes = None;
        config.storage.backend = StorageConfigToml::InMemory;
        config.logging = None;
        config
    }

    /// Returns a minimal test config with admin/metrics disabled.
    /// Use for fast internal tests that don't need extra servers.
    #[cfg(any(test, feature = "testing"))]
    pub fn minimal_test_config() -> Self {
        let mut config = Self::default_test_config();
        config.admin.enabled = false;
        config.metrics.enabled = false;
        config
    }

    /// Returns the default test configuration for backward compatibility.
    ///
    /// # Deprecated
    /// Use [`Self::default_test_config()`] for full-featured config (admin enabled),
    /// or [`Self::minimal_test_config()`] for lightweight tests (admin/metrics disabled).
    #[cfg(any(test, feature = "testing"))]
    #[deprecated(
        since = "0.5.0",
        note = "Use default_test_config() or minimal_test_config() directly for explicit behavior"
    )]
    pub fn test() -> Self {
        Self::default_test_config()
    }

    /// Migrate deprecated `[general].user_storage_quota_mb` into
    /// `[storage].default_quota_mb`. Called once at parse time so
    /// downstream code only checks one place.
    fn resolve_legacy_quotas(&mut self) {
        if self.storage.default_quota_mb.is_none() {
            #[allow(deprecated)]
            let legacy = self.general.user_storage_quota_mb;
            self.storage.default_quota_mb = match legacy {
                0 => None,
                n => Some(n),
            };
        }
    }
}

impl FromStr for ConfigToml {
    type Err = toml::de::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut config: Self = toml::from_str(s)?;
        config.resolve_legacy_quotas();
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use crate::data_directory::log_level::LogLevel;

    use super::*;
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
        str::FromStr,
    };

    #[test]
    fn test_default_config() {
        let c = ConfigToml::default();
        assert_eq!(c.general.signup_mode, SignupMode::TokenRequired);
        #[allow(deprecated)]
        {
            assert_eq!(c.general.user_storage_quota_mb, 0);
        }
        assert_eq!(
            c.drive.icann_listen_socket,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 6286))
        );
        assert_eq!(
            c.pkdns.icann_domain,
            Some(Domain::from_str("localhost").unwrap())
        );
        assert_eq!(
            c.drive.pubky_listen_socket,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 6287))
        );
        assert_eq!(
            c.admin.listen_socket,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 6288))
        );
        assert_eq!(c.admin.admin_password, "admin");
        assert_eq!(c.pkdns.public_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(c.pkdns.public_pubky_tls_port, None);
        assert_eq!(c.pkdns.public_icann_http_port, None);
        assert_eq!(c.pkdns.user_keys_republisher_interval, 14400);
        assert_eq!(c.pkdns.dht_bootstrap_nodes, None);
        assert_eq!(c.pkdns.dht_request_timeout_ms, None);
        assert_eq!(c.drive.rate_limits.len(), 1);
        assert_eq!(c.drive.rate_limits[0].path.0, "/signup_tokens/*");
        assert_eq!(c.default_quotas, DefaultQuotasToml::default());
        assert_eq!(c.storage.default_quota_mb, None);
        assert_eq!(c.storage.backend, StorageConfigToml::FileSystem);
        assert_eq!(
            c.logging,
            Some(LoggingToml {
                level: LogLevel::from_str("info").unwrap(),
                module_levels: vec![
                    TargetLevel::from_str("pubky_homeserver=debug").unwrap(),
                    TargetLevel::from_str("tower_http=debug").unwrap()
                ],
            })
        );
    }

    #[test]
    fn test_sample_config() {
        // Validate that the sample config can be parsed
        ConfigToml::from_str(SAMPLE_CONFIG).expect("Embedded config.sample.toml must be valid");
    }

    #[test]
    fn test_sample_config_commented_out() {
        // Sanity check that the sample config is valid even when the variables are commented out.
        // An empty or fully commented out .toml should still be equal to the default ConfigToml
        let s = ConfigToml::sample_string();
        let parsed: ConfigToml =
            ConfigToml::from_str_with_defaults(&s).expect("Should be valid config file");
        assert_eq!(parsed, ConfigToml::default());
    }

    #[test]
    fn test_empty_config() {
        // Test that a minimal config with only the general section works
        let s = "[general]\nsignup_mode = \"open\"\n";
        let parsed: ConfigToml = ConfigToml::from_str_with_defaults(s).unwrap();
        // Check that explicitly set values are preserved
        assert_eq!(parsed.general.signup_mode, SignupMode::Open);
        // Other fields that were not set (left empty) should still match the default.
        assert_eq!(parsed.admin, ConfigToml::default().admin);
        assert_eq!(parsed.logging, ConfigToml::default().logging);
    }

    #[test]
    fn test_merged_config() {
        // Test that a minimal config with optional logging section with empty module_levels
        let s = "[logging]\nlevel=\"trace\"\nmodule_levels = [ ]";
        let merged: ConfigToml = ConfigToml::from_str_with_defaults(s).unwrap();
        // Default rate limits should be preserved from defaults
        assert_eq!(merged.drive.rate_limits.len(), 1);
        assert_eq!(merged.drive.rate_limits[0].path.0, "/signup_tokens/*");
        let expected_logging = Some(LoggingToml {
            level: LogLevel::from_str("trace").unwrap(),
            module_levels: vec![],
        });
        assert_eq!(merged.logging, expected_logging);
    }

    #[test]
    fn test_legacy_general_storage_quota_migrated() {
        // general.user_storage_quota_mb should migrate to storage.default_quota_mb
        let s = "[general]\nuser_storage_quota_mb = 500\n";
        let parsed = ConfigToml::from_str_with_defaults(s).unwrap();
        assert_eq!(parsed.storage.default_quota_mb, Some(500));
    }
}
