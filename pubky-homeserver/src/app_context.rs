//!
//! The application context shared between all components.
//! Think of it as a simple Dependency Injection container.
//!
//! Create with a `DataDir` instance: `AppContext::try_from(data_dir)`
//!

use crate::services::user_service::UserService;
#[cfg(any(test, feature = "testing"))]
use crate::MockDataDir;
use crate::{
    client_server::auth::RevocationListener,
    observability::{Metrics, MetricsInitError},
    persistence::{
        files::{events::EventsService, FileIoError, FileService},
        sql::{DatabaseMode, Migrator, PgEventListener, SqlDb},
    },
    ConfigToml, DataDir,
};
use pubky_common::crypto::Keypair;
use std::sync::Arc;
use std::time::Duration;

/// Errors that can occur when converting a `DataDir` to an `AppContext`.
#[derive(Debug, thiserror::Error)]
pub enum AppContextConversionError {
    /// Failed to ensure data directory exists and is writable.
    #[error("Failed to ensure data directory exists and is writable: {0}")]
    DataDir(anyhow::Error),
    /// Failed to read or create config file.
    #[error("Failed to read or create config file: {0}")]
    Config(anyhow::Error),
    /// Failed to read or create keypair.
    #[error("Failed to read or create keypair: {0}")]
    Keypair(anyhow::Error),
    /// Failed to open SQL DB.
    #[error("Failed to open SQL DB: {0}")]
    SqlDb(sqlx::Error),
    /// No database URL was configured (production builds require an explicit URL).
    #[error("No database_url configured. Set [general].database_url in config.toml.")]
    NoDatabaseUrl,
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
/// Create with a `DataDir` instance: `AppContext::try_from(data_dir)`
///
#[derive(Clone)]
pub struct AppContext {
    /// The SQL database connection.
    pub(crate) sql_db: SqlDb,
    /// The storage operator to store files.
    pub(crate) file_service: FileService,
    pub(crate) config_toml: ConfigToml,
    /// Keep data_dir alive. The mock dir will cleanup on drop.
    pub(crate) data_dir: Arc<dyn DataDir>,
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

impl AppContext {
    /// Create a new AppContext for testing.
    #[cfg(any(test, feature = "testing"))]
    pub async fn test() -> Self {
        let data_dir = MockDataDir::test();
        Self::read_from(data_dir)
            .await
            .expect("failed to build AppContext from DataDirMock")
    }

    /// Create a new AppContext from a data directory.
    pub async fn read_from<D: DataDir + 'static>(
        dir: D,
    ) -> Result<Self, AppContextConversionError> {
        dir.ensure_data_dir_exists_and_is_writable()
            .map_err(AppContextConversionError::DataDir)?;
        let conf = dir
            .read_or_create_config_file()
            .map_err(AppContextConversionError::Config)?;
        let keypair = dir
            .read_or_create_keypair()
            .map_err(AppContextConversionError::Keypair)?;

        let db_mode = Self::resolve_database_mode(&conf)?;
        let sql_db = SqlDb::connect(db_mode)
            .await
            .map_err(AppContextConversionError::SqlDb)?;
        Migrator::new(&sql_db)
            .run()
            .await
            .map_err(AppContextConversionError::Migrations)?;

        let events_service = EventsService::new(1000);

        let pg_event_listener = PgEventListener::start(sql_db.pool(), events_service.clone())
            .await
            .map_err(AppContextConversionError::PgEventListener)?;
        let revocation_listener = RevocationListener::start(sql_db.pool())
            .await
            .map_err(AppContextConversionError::RevocationListener)?;

        let user_service = UserService::new(sql_db.clone());

        let file_service = FileService::new_from_config(
            &conf,
            dir.path(),
            sql_db.clone(),
            events_service.clone(),
            user_service.clone(),
        )
        .map_err(AppContextConversionError::Storage)?;
        let pkarr_builder = Self::build_pkarr_builder_from_config(&conf);

        Ok(Self {
            sql_db,
            pkarr_client: pkarr_builder
                .clone()
                .build()
                .map_err(AppContextConversionError::Pkarr)?,
            file_service,
            pkarr_builder,
            config_toml: conf,
            keypair,
            data_dir: Arc::new(dir),
            events_service,
            metrics: Metrics::new().map_err(AppContextConversionError::Metrics)?,
            _pg_event_listener: Arc::new(pg_event_listener),
            revocation_listener,
            user_service,
        })
    }
}

impl AppContext {
    /// Resolve the [`DatabaseMode`] from config.
    ///
    /// - Production: `database_url` must be `Some`; always [`DatabaseMode::Direct`].
    /// - Test builds: delegates to [`DatabaseMode::resolve_test`] which resolves
    ///   `None` via env var or default, always returning [`DatabaseMode::EphemeralTest`].
    fn resolve_database_mode(conf: &ConfigToml) -> Result<DatabaseMode, AppContextConversionError> {
        #[cfg(any(test, feature = "testing"))]
        {
            Ok(DatabaseMode::resolve_test(
                conf.general.database_url.clone(),
            ))
        }

        #[cfg(not(any(test, feature = "testing")))]
        {
            conf.general
                .database_url
                .clone()
                .map(DatabaseMode::Direct)
                .ok_or(AppContextConversionError::NoDatabaseUrl)
        }
    }

    /// Build the pkarr client builder based on the config.
    fn build_pkarr_builder_from_config(config_toml: &ConfigToml) -> pkarr::ClientBuilder {
        let mut builder = pkarr::ClientBuilder::default();
        #[cfg(any(test, feature = "testing"))]
        // In test builds, no explicit database_url means we're in a test environment
        // where we must avoid contacting the public DHT.
        if config_toml.general.database_url.is_none() {
            builder
                .no_default_network()
                // Keep the client buildable without contacting the public DHT.
                // Explicit testnet bootstrap nodes below replace this sentinel.
                .bootstrap(&["127.0.0.1:9"])
                .dht_report_policy(pkarr::dht::ReportPolicy::testnet());
        }
        if let Some(bootstrap_nodes) = &config_toml.pkdns.dht_bootstrap_nodes {
            let nodes = bootstrap_nodes
                .iter()
                .map(|node| node.to_string())
                .collect::<Vec<String>>();
            builder.bootstrap(&nodes);

            // If we set custom bootstrap nodes, we don't want to use the default pkarr relay nodes.
            // Otherwise, we could end up with a DHT with testnet boostrap nodes and mainnet relays
            // which would give very weird results.
            builder.no_relays();
        }

        if let Some(relays) = &config_toml.pkdns.dht_relay_nodes {
            builder
                .relays(relays)
                .expect("parameters are already urls and therefore valid.");
        }
        if let Some(request_timeout) = &config_toml.pkdns.dht_request_timeout_ms {
            let duration = Duration::from_millis(request_timeout.get());
            builder.request_timeout(duration);
        }
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that the test pkarr builder doesn't contact the public DHT
    /// when database_url is None (the default test config).
    #[test]
    fn pkarr_builder_does_not_use_default_network() {
        let config = ConfigToml::default_test_config();
        assert!(
            config.general.database_url.is_none(),
            "default_test_config should have database_url = None"
        );
        let builder = AppContext::build_pkarr_builder_from_config(&config);
        let builder_debug = format!("{builder:?}");

        assert!(
            builder_debug.contains("127.0.0.1:9"),
            "expected sentinel bootstrap node in builder: {builder_debug}"
        );
        for relay in pkarr::DEFAULT_RELAYS {
            assert!(
                !builder_debug.contains(relay),
                "default relay {relay} should not appear in test builder: {builder_debug}"
            );
        }
        builder.build().expect("isolated pkarr client should build");
    }
}
