//!
//! The application context shared between all components.
//! Think of it as a simple Dependency Injection container.
//!
//! Build via [`AppContext::new`] with independently resolved:
//! - **Data path** — persistent directory or temp dir
//! - **Database mode** — [`DatabaseMode::Direct`] or [`DatabaseMode::EphemeralTest`]
//! - **DHT mode** — [`DhtMode::Public`], [`DhtMode::Isolated`], or [`DhtMode::Custom`]
//!
//! Convenience constructors:
//! - [`AppContext::from_persistent_dir`] — production (persistent dir, public DHT, direct DB)
//! - [`AppContext::new_ephemeral`] — tests (temp dir, isolated DHT, test DB)
//!

use crate::services::user_service::UserService;
use crate::{
    client_server::auth::RevocationListener,
    observability::{Metrics, MetricsInitError},
    persistence::{
        files::{events::EventsService, FileIoError, FileService},
        sql::{DatabaseMode, Migrator, PgEventListener, SqlDb},
    },
    ConfigToml,
};
use pubky_common::crypto::Keypair;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// How the pkarr DHT client should be configured.
///
/// Controls whether the homeserver connects to the public DHT or an isolated testnet.
#[non_exhaustive]
pub enum DhtMode {
    /// Public DHT with config values (bootstrap nodes, relays, timeouts) applied.
    Public,
    /// Isolated from the public DHT (no default network, testnet report policy),
    /// with config values applied on top. Use this for testnets.
    Isolated,
    /// Fully custom pkarr client builder — config values are NOT applied automatically.
    /// Use this when you need full control (e.g. a pre-configured testnet builder).
    Custom(pkarr::ClientBuilder),
}

/// Errors that can occur when building an `AppContext`.
#[derive(Debug, thiserror::Error)]
pub enum AppContextBuildError {
    /// Failed to bootstrap the data directory (ensure writable, read config/keypair).
    #[error("Failed to bootstrap data directory: {0}")]
    Bootstrap(anyhow::Error),
    /// Failed to open SQL DB.
    #[error("Failed to open SQL DB: {0}")]
    SqlDb(sqlx::Error),
    /// Failed to resolve the database mode (e.g. missing URL or invalid TEST_PUBKY_CONNECTION_STRING).
    #[error("Failed to resolve database mode: {0}")]
    DatabaseResolution(anyhow::Error),
    /// Failed to run migrations.
    #[error("Failed to run migrations: {0}")]
    Migrations(anyhow::Error),
    /// Failed to build storage operator.
    #[error("Failed to build storage operator: {0}")]
    Storage(FileIoError),
    /// Failed to build pkarr client.
    #[error("Failed to build pkarr client: {0}")]
    Pkarr(pkarr::errors::BuildError),
    /// Failed to start the Postgres event listener.
    #[error("Failed to start Postgres event listener: {0}")]
    PgEventListener(sqlx::Error),
    /// Failed to start the auth revocation listener.
    #[error("Failed to start the auth revocation listener: {0}")]
    RevocationListener(sqlx::Error),
    /// Failed to initialize metrics.
    #[error("Failed to initialize metrics: {0}")]
    Metrics(MetricsInitError),
}

/// The application context shared between all components.
/// Think of it as a simple Dependency Injection container.
///
/// Implements `Clone` but prefer wrapping in `Arc<AppContext>` for
/// hot paths like axum state (avoids deep-copying config strings).
#[derive(Clone)]
pub struct AppContext {
    /// The SQL database connection.
    pub(crate) sql_db: SqlDb,
    /// The storage operator to store files.
    pub(crate) file_service: FileService,
    pub(crate) config_toml: ConfigToml,
    /// Path to the data directory (used by file storage).
    pub(crate) data_path: PathBuf,
    pub(crate) keypair: Keypair,
    /// Main pkarr instance. This will automatically turn into a DHT server after 15 minutes after startup.
    /// We need to keep this alive.
    pub(crate) pkarr_client: pkarr::Client,
    /// pkarr client builder in case we need to create a more instances.
    /// Comes ready with the correct bootstrap nodes and relays.
    pub(crate) pkarr_builder: pkarr::ClientBuilder,
    /// Events service for managing event creation and broadcasting.
    pub(crate) events_service: EventsService,
    /// Metrics for all endpoints.
    pub(crate) metrics: Metrics,
    /// Background listener for Postgres event notifications.
    /// Enables cross-instance event propagation for /events-stream's SSE functionality.
    /// Kept alive for the background task, not for direct access.
    _pg_event_listener: Arc<PgEventListener>,
    /// Auth revocations are forwarded to private SSE streams on this instance.
    /// Its Postgres listener stops once the last clone is dropped.
    pub(crate) revocation_listener: RevocationListener,
    /// User service for quota resolution and user creation with defaults.
    pub(crate) user_service: UserService,
}

/// An `Arc<AppContext>` paired with a temporary directory that is cleaned up on drop.
///
/// Use this in tests to ensure the temp dir lives as long as the context.
/// The [`Deref`](std::ops::Deref) impl lets this be used anywhere `Arc<AppContext>` is expected by reference.
#[cfg(any(test, feature = "testing"))]
pub struct TempAppContext {
    context: Arc<AppContext>,
    _temp_dir: tempfile::TempDir,
}

#[cfg(any(test, feature = "testing"))]
impl std::ops::Deref for TempAppContext {
    type Target = Arc<AppContext>;
    fn deref(&self) -> &Self::Target {
        &self.context
    }
}

impl AppContext {
    /// Production shorthand: persistent data dir, public DHT, direct DB.
    ///
    /// Reads config and keypair from disk via [`PersistentDataDir::bootstrap`].
    pub async fn from_persistent_dir(
        dir: crate::PersistentDataDir,
    ) -> Result<Self, AppContextBuildError> {
        let (path, config, keypair) = dir.bootstrap().map_err(AppContextBuildError::Bootstrap)?;
        let db_mode = DatabaseMode::require_direct(config.general.database_url.clone())
            .map_err(AppContextBuildError::DatabaseResolution)?;
        Self::new(path, config, keypair, db_mode, DhtMode::Public).await
    }

    /// Quick test context with default config and a deterministic keypair.
    #[cfg(any(test, feature = "testing"))]
    pub async fn test() -> TempAppContext {
        let config = ConfigToml::default_test_config();
        let keypair = Keypair::from_secret(&[0; 32]);
        let (ctx, temp_dir) = Self::new_ephemeral(config, keypair)
            .await
            .expect("failed to build test AppContext");
        TempAppContext {
            context: Arc::new(ctx),
            _temp_dir: temp_dir,
        }
    }

    /// Quick test context with a custom config modifier and a random keypair.
    #[cfg(any(test, feature = "testing"))]
    pub async fn test_with_config(f: impl FnOnce(&mut ConfigToml)) -> TempAppContext {
        let mut config = ConfigToml::default_test_config();
        f(&mut config);
        let (ctx, temp_dir) = Self::new_ephemeral(config, Keypair::random())
            .await
            .expect("failed to build test AppContext");
        TempAppContext {
            context: Arc::new(ctx),
            _temp_dir: temp_dir,
        }
    }

    /// Test shorthand: temp data dir, isolated DHT, test DB.
    ///
    /// Returns the `AppContext` and the `TempDir` whose lifetime
    /// keeps the data directory alive.
    #[cfg(any(test, feature = "testing"))]
    pub async fn new_ephemeral(
        config: ConfigToml,
        keypair: Keypair,
    ) -> Result<(Self, tempfile::TempDir), AppContextBuildError> {
        let temp_dir =
            tempfile::TempDir::new().map_err(|e| AppContextBuildError::Bootstrap(e.into()))?;
        let data_path = temp_dir.path().to_path_buf();
        let db_mode = DatabaseMode::resolve_test(config.general.database_url.clone())
            .map_err(AppContextBuildError::DatabaseResolution)?;

        let ctx = Self::new(data_path, config, keypair, db_mode, DhtMode::Isolated).await?;
        Ok((ctx, temp_dir))
    }

    /// Create an `AppContext` from independently resolved components.
    ///
    /// Each parameter represents a separate concern:
    /// - `data_path` — where file storage lives (persistent dir or temp dir)
    /// - `config` — homeserver configuration
    /// - `keypair` — server identity
    /// - `db_mode` — database lifecycle ([`DatabaseMode::Direct`] or [`DatabaseMode::EphemeralTest`])
    /// - `dht_mode` — DHT connectivity ([`DhtMode::Public`], [`DhtMode::Isolated`], or [`DhtMode::Custom`])
    ///
    /// See [`from_persistent_dir`](Self::from_persistent_dir) and
    /// [`new_ephemeral`](Self::new_ephemeral) for common combinations.
    pub async fn new(
        data_path: PathBuf,
        config: ConfigToml,
        keypair: Keypair,
        db_mode: DatabaseMode,
        dht_mode: DhtMode,
    ) -> Result<Self, AppContextBuildError> {
        let pkarr_builder = Self::resolve_dht_mode(dht_mode, &config);
        let sql_db = SqlDb::connect(db_mode)
            .await
            .map_err(AppContextBuildError::SqlDb)?;
        Migrator::new(&sql_db)
            .run()
            .await
            .map_err(AppContextBuildError::Migrations)?;

        let events_service = EventsService::new(sql_db.clone(), 1000);

        let pg_event_listener = PgEventListener::start(sql_db.pool(), events_service.clone())
            .await
            .map_err(AppContextBuildError::PgEventListener)?;
        let revocation_listener = RevocationListener::start(sql_db.pool())
            .await
            .map_err(AppContextBuildError::RevocationListener)?;

        let user_service = UserService::new(sql_db.clone());

        let file_service = FileService::new_from_config(
            &config,
            &data_path,
            sql_db.clone(),
            events_service.clone(),
            user_service.clone(),
        )
        .map_err(AppContextBuildError::Storage)?;

        Ok(Self {
            sql_db,
            pkarr_client: pkarr_builder
                .clone()
                .build()
                .map_err(AppContextBuildError::Pkarr)?,
            file_service,
            pkarr_builder,
            config_toml: config,
            keypair,
            data_path,
            events_service,
            metrics: Metrics::new().map_err(AppContextBuildError::Metrics)?,
            _pg_event_listener: Arc::new(pg_event_listener),
            revocation_listener,
            user_service,
        })
    }

    /// Resolve a [`DhtMode`] into a concrete pkarr client builder.
    fn resolve_dht_mode(mode: DhtMode, config: &ConfigToml) -> pkarr::ClientBuilder {
        match mode {
            DhtMode::Public => {
                let mut builder = pkarr::ClientBuilder::default();
                Self::apply_config_to_pkarr(&mut builder, config);
                builder
            }
            DhtMode::Isolated => {
                let mut builder = pkarr::ClientBuilder::default();
                builder
                    .no_default_network()
                    // Sentinel bootstrap node so the builder stays valid even when
                    // no config-level bootstrap nodes are provided. Explicit testnet
                    // bootstrap nodes (from config) replace this via apply_config_to_pkarr.
                    // Port 9 is the RFC 863 "discard" protocol — guaranteed unreachable as a DHT node.
                    .bootstrap(&["127.0.0.1:9"])
                    .dht_report_policy(pkarr::dht::ReportPolicy::testnet());
                Self::apply_config_to_pkarr(&mut builder, config);
                builder
            }
            DhtMode::Custom(builder) => builder,
        }
    }

    /// Apply DHT configuration (bootstrap nodes, relays, timeouts) from config
    /// to a pkarr client builder.
    fn apply_config_to_pkarr(builder: &mut pkarr::ClientBuilder, config: &ConfigToml) {
        if let Some(bootstrap_nodes) = &config.pkdns.dht_bootstrap_nodes {
            let nodes = bootstrap_nodes
                .iter()
                .map(|node| node.to_string())
                .collect::<Vec<String>>();
            builder.bootstrap(&nodes);
        }

        if let Some(relays) = &config.pkdns.dht_relay_nodes {
            builder
                .relays(relays)
                .expect("parameters are already urls and therefore valid.");
        }
        if let Some(request_timeout) = &config.pkdns.dht_request_timeout_ms {
            let duration = Duration::from_millis(request_timeout.get());
            builder.request_timeout(duration);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `DhtMode::Public` keeps default relays and applies config values.
    #[test]
    fn public_mode_keeps_defaults_and_applies_config() {
        use crate::DomainPort;
        use std::str::FromStr;

        let mut config = ConfigToml::default_test_config();
        config.pkdns.dht_bootstrap_nodes =
            Some(vec![DomainPort::from_str("127.0.0.1:6881").unwrap()]);

        let builder = AppContext::resolve_dht_mode(DhtMode::Public, &config);
        let debug = format!("{builder:?}");

        assert!(
            debug.contains("127.0.0.1:6881"),
            "bootstrap node from config should be present: {debug}"
        );
        for relay in pkarr::DEFAULT_RELAYS {
            assert!(
                debug.contains(relay),
                "default relay {relay} should still be present: {debug}"
            );
        }
    }

    /// `DhtMode::Isolated` excludes public DHT nodes.
    #[test]
    fn isolated_mode_excludes_public_dht() {
        let builder =
            AppContext::resolve_dht_mode(DhtMode::Isolated, &ConfigToml::default_test_config());
        let debug = format!("{builder:?}");

        for relay in pkarr::DEFAULT_RELAYS {
            assert!(
                !debug.contains(relay),
                "default relay {relay} should not appear after no_default_network: {debug}"
            );
        }
        builder.build().expect("isolated pkarr client should build");
    }

    /// `DhtMode::Custom` passes through the builder unchanged.
    #[test]
    fn custom_mode_passes_through_builder() {
        let mut custom = pkarr::ClientBuilder::default();
        custom.no_default_network();

        let builder = AppContext::resolve_dht_mode(
            DhtMode::Custom(custom),
            &ConfigToml::default_test_config(),
        );
        let debug = format!("{builder:?}");

        // Custom builder had no_default_network, so no default relays.
        for relay in pkarr::DEFAULT_RELAYS {
            assert!(
                !debug.contains(relay),
                "default relay {relay} should not appear in custom builder: {debug}"
            );
        }
    }
}
