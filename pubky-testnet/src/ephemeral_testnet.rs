use crate::Testnet;
use http_relay::HttpRelay;
use pubky::{Keypair, Pubky};
use pubky_homeserver::{ConfigToml, ConnectionString, HomeserverApp, MockDataDir};

#[cfg(feature = "docker-postgres")]
use crate::docker_postgres::DockerPostgres;

/// A testnet for **automated tests** — all ports are random and all state is in-memory.
///
/// Use this when writing `#[tokio::test]` tests. Every instance gets its own
/// isolated DHT and homeserver, so tests can run in parallel without port
/// conflicts.
///
/// For interactive / CLI use with fixed well-known ports, see [`StaticTestnet`](crate::StaticTestnet).
///
/// # Components
/// - A local DHT with bootstrapping nodes (random ports).
/// - A homeserver (default pubkey: `8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo`).
/// - An HTTP relay (optional, use `.with_http_relay()` to enable).
///
/// # Recommended Usage
/// Use [`EphemeralTestnet::builder()`] to create a testnet with explicit configuration:
///
/// ```ignore
/// // Minimal testnet (admin/metrics disabled) - fastest for most tests
/// let testnet = EphemeralTestnet::builder().build().await?;
///
/// // Full-featured testnet (admin enabled) - for tests requiring admin API
/// let testnet = EphemeralTestnet::builder()
///     .config(ConfigToml::default_test_config())
///     .build()
///     .await?;
/// ```
///
/// # Configuration Defaults
/// - `EphemeralTestnet::builder().build()` uses [`ConfigToml::minimal_test_config()`] (admin/metrics **disabled**)
/// - Deprecated [`EphemeralTestnet::start()`] uses [`ConfigToml::default_test_config()`] (admin **enabled**)
pub struct EphemeralTestnet {
    /// Inner flexible testnet.
    pub testnet: Testnet,
    /// Docker PostgreSQL instance (if using docker postgres).
    /// Kept alive as long as the testnet is running.
    #[cfg(feature = "docker-postgres")]
    #[allow(dead_code)]
    docker_postgres: Option<DockerPostgres>,
}

/// Builder for configuring and creating an [`EphemeralTestnet`].
///
/// Provides a fluent API for customizing testnet configuration before creation.
///
/// # Defaults
/// - **Config**: [`ConfigToml::minimal_test_config()`] (admin/metrics disabled)
/// - **Keypair**: Deterministic keypair from `[0; 32]` secret key
/// - **Postgres**: Uses `TEST_PUBKY_CONNECTION_STRING` env var if set, otherwise in-memory
/// - **HTTP Relay**: Disabled by default (use `.with_http_relay()` to enable)
///
/// # Example
/// ```ignore
/// // Use defaults (minimal config, no HTTP relay)
/// let testnet = EphemeralTestnet::builder().build().await?;
///
/// // Enable admin server
/// let testnet = EphemeralTestnet::builder()
///     .config(ConfigToml::default_test_config())
///     .build()
///     .await?;
///
/// // Custom keypair
/// let testnet = EphemeralTestnet::builder()
///     .keypair(Keypair::random())
///     .build()
///     .await?;
///
/// // With HTTP relay (for tests that need it)
/// let testnet = EphemeralTestnet::builder()
///     .with_http_relay()
///     .build()
///     .await?;
/// ```
pub struct EphemeralTestnetBuilder {
    postgres_connection_string: Option<ConnectionString>,
    homeserver_config: Option<ConfigToml>,
    homeserver_keypair: Option<Keypair>,
    http_relay: bool,
    #[cfg(feature = "docker-postgres")]
    use_docker_postgres: bool,
}

impl EphemeralTestnetBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            postgres_connection_string: None,
            homeserver_config: None,
            homeserver_keypair: None,
            http_relay: false,
            #[cfg(feature = "docker-postgres")]
            use_docker_postgres: false,
        }
    }

    /// Set a custom homeserver configuration.
    pub fn config(mut self, config: ConfigToml) -> Self {
        self.homeserver_config = Some(config);
        self
    }

    /// Set a specific keypair for the homeserver.
    pub fn keypair(mut self, keypair: Keypair) -> Self {
        self.homeserver_keypair = Some(keypair);
        self
    }

    /// Set a custom postgres connection string.
    pub fn postgres(mut self, connection_string: ConnectionString) -> Self {
        self.postgres_connection_string = Some(connection_string);
        self
    }

    /// Enable the HTTP relay (disabled by default).
    pub fn with_http_relay(mut self) -> Self {
        self.http_relay = true;
        self
    }

    /// Use a Docker PostgreSQL container instead of an external database.
    ///
    /// This starts a PostgreSQL container via testcontainers that is automatically
    /// managed and cleaned up. Requires Docker to be running on the host.
    ///
    /// This is useful for running tests without requiring a separate
    /// PostgreSQL installation.
    ///
    /// **Note**: Cannot be combined with `.postgres()`. If both are set, `build()` will
    /// return an error.
    ///
    /// # Multiple Tests
    ///
    /// Each call to `.with_docker_postgres()` starts a separate PostgreSQL container.
    /// If you have many tests, prefer starting one [`DockerPostgres`](crate::docker_postgres::DockerPostgres)
    /// instance and passing its connection string via `.postgres()` instead.
    /// See [`DockerPostgres`](crate::docker_postgres::DockerPostgres) docs for the recommended pattern.
    #[cfg(feature = "docker-postgres")]
    pub fn with_docker_postgres(mut self) -> Self {
        self.use_docker_postgres = true;
        self
    }

    /// Deprecated alias for [`Self::with_docker_postgres()`].
    #[cfg(feature = "docker-postgres")]
    #[deprecated(since = "0.9.0", note = "Renamed to `with_docker_postgres()`")]
    pub fn with_embedded_postgres(self) -> Self {
        self.with_docker_postgres()
    }

    /// Build and start the testnet with the configured settings.
    /// Uses minimal_test_config() by default (admin/metrics disabled).
    ///
    /// # Errors
    /// Returns an error if both `.postgres()` and `.with_docker_postgres()` are set.
    pub async fn build(self) -> anyhow::Result<EphemeralTestnet> {
        #[cfg(feature = "docker-postgres")]
        if self.use_docker_postgres && self.postgres_connection_string.is_some() {
            anyhow::bail!(
                "Cannot use both docker postgres and a custom connection string. \
                 Use either .with_docker_postgres() or .postgres(), not both."
            );
        }

        #[cfg(feature = "docker-postgres")]
        let (docker_postgres, postgres_connection_string) = if self.use_docker_postgres {
            let pg = DockerPostgres::start().await?;
            let conn_string = pg.connection_string()?;
            (Some(pg), Some(conn_string))
        } else {
            (None, self.postgres_connection_string)
        };

        #[cfg(not(feature = "docker-postgres"))]
        let postgres_connection_string = self.postgres_connection_string;

        let mut testnet = if let Some(postgres) = postgres_connection_string {
            Testnet::new_with_custom_postgres(postgres).await?
        } else {
            Testnet::new().await?
        };

        if self.http_relay {
            testnet.create_http_relay().await?;
        }

        let mut config = self
            .homeserver_config
            .unwrap_or_else(ConfigToml::minimal_test_config);

        if let Some(connection_string) = testnet.postgres_connection_string.as_ref() {
            config.general.database_url = Some(connection_string.clone());
        }

        let keypair = self
            .homeserver_keypair
            .unwrap_or_else(crate::common::testnet_keypair);
        let mock_dir = MockDataDir::new(config, Some(keypair))?;
        testnet.create_homeserver_app_with_mock(mock_dir).await?;

        Ok(EphemeralTestnet {
            testnet,
            #[cfg(feature = "docker-postgres")]
            docker_postgres,
        })
    }
}

impl Default for EphemeralTestnetBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EphemeralTestnet {
    /// Create a new builder for configuring the testnet.
    ///
    /// This is the recommended way to create a testnet with custom configuration.
    ///
    /// # Example
    /// ```ignore
    /// let testnet = EphemeralTestnet::builder()
    ///     .config(ConfigToml::default_test_config())
    ///     .keypair(Keypair::random())
    ///     .build()
    ///     .await?;
    /// ```
    pub fn builder() -> EphemeralTestnetBuilder {
        EphemeralTestnetBuilder::new()
    }

    /// Run a new simple testnet with full config (admin enabled).
    ///
    /// # Deprecated
    /// Use [`Self::builder()`] for explicit configuration control.
    /// This method uses [`ConfigToml::default_test_config()`] which enables the admin server.
    #[deprecated(
        since = "0.5.0",
        note = "Use EphemeralTestnet::builder().config(ConfigToml::default_test_config()).build() for explicit behavior"
    )]
    pub async fn start() -> anyhow::Result<Self> {
        let mut testnet = Testnet::new().await?;
        testnet.create_http_relay().await?;
        testnet.create_homeserver().await?;
        Ok(Self {
            testnet,
            #[cfg(feature = "docker-postgres")]
            docker_postgres: None,
        })
    }

    /// Run a new simple testnet with custom postgres and full config (admin enabled).
    ///
    /// # Deprecated
    /// Use [`Self::builder()`] with `.postgres()` for explicit configuration control.
    #[deprecated(
        since = "0.5.0",
        note = "Use EphemeralTestnet::builder().postgres(...).config(ConfigToml::default_test_config()).build() instead"
    )]
    pub async fn start_with_custom_postgres(
        postgres_connection_string: ConnectionString,
    ) -> anyhow::Result<Self> {
        let mut testnet = Testnet::new_with_custom_postgres(postgres_connection_string).await?;
        testnet.create_http_relay().await?;
        testnet.create_homeserver().await?;
        Ok(Self {
            testnet,
            #[cfg(feature = "docker-postgres")]
            docker_postgres: None,
        })
    }

    /// Run a new simple testnet with custom postgres but no homeserver (minimal setup).
    ///
    /// # Deprecated
    /// Use [`Testnet`] directly for fine-grained control over component creation.
    #[deprecated(
        since = "0.5.0",
        note = "Use Testnet::new_with_custom_postgres() and create_http_relay() for fine-grained control"
    )]
    pub async fn start_minimal_with_custom_postgres(
        postgres_connection_string: ConnectionString,
    ) -> anyhow::Result<Self> {
        let mut me = Self {
            testnet: Testnet::new_with_custom_postgres(postgres_connection_string).await?,
            #[cfg(feature = "docker-postgres")]
            docker_postgres: None,
        };
        me.testnet.create_http_relay().await?;
        Ok(me)
    }

    /// Run a new simple testnet network with a minimal setup (no homeserver).
    ///
    /// # Deprecated
    /// Use [`Testnet`] directly for fine-grained control over component creation.
    #[deprecated(
        since = "0.5.0",
        note = "Use Testnet::new() and create_http_relay() for fine-grained control"
    )]
    pub async fn start_minimal() -> anyhow::Result<Self> {
        let mut me = Self {
            testnet: Testnet::new().await?,
            #[cfg(feature = "docker-postgres")]
            docker_postgres: None,
        };
        me.testnet.create_http_relay().await?;
        Ok(me)
    }

    /// Create an additional homeserver with a random keypair.
    pub async fn create_random_homeserver(&mut self) -> anyhow::Result<&HomeserverApp> {
        self.create_random_homeserver_with_config(None).await
    }

    /// Create an additional homeserver with a random keypair and custom config.
    /// Uses minimal_test_config() by default (admin/metrics disabled).
    pub async fn create_random_homeserver_with_config(
        &mut self,
        config: Option<ConfigToml>,
    ) -> anyhow::Result<&HomeserverApp> {
        let mut config = config.unwrap_or_else(ConfigToml::minimal_test_config);

        if let Some(connection_string) = self.testnet.postgres_connection_string.as_ref() {
            config.general.database_url = Some(connection_string.clone());
        }

        let mock_dir = MockDataDir::new(config, Some(Keypair::random()))?;
        self.testnet.create_homeserver_app_with_mock(mock_dir).await
    }

    /// Create a new pubky client builder.
    pub fn client_builder(&self) -> pubky::PubkyHttpClientBuilder {
        self.testnet.client_builder()
    }

    /// Creates a [`pubky::PubkyHttpClient`] pre-configured to use this test network.
    pub fn client(&self) -> Result<pubky::PubkyHttpClient, pubky::BuildError> {
        self.testnet.client()
    }

    /// Creates a [`pubky::Pubky`] SDK facade pre-configured to use this test network.
    ///
    /// This is a convenience method that builds a client from `Self::client_builder`.
    pub fn sdk(&self) -> Result<Pubky, pubky::BuildError> {
        self.testnet.sdk()
    }

    /// Create a new pkarr client builder.
    pub fn pkarr_client_builder(&self) -> pkarr::ClientBuilder {
        self.testnet.pkarr_client_builder()
    }

    /// Get the homeserver in the testnet.
    pub fn homeserver_app(&self) -> &pubky_homeserver::HomeserverApp {
        self.testnet
            .homeservers
            .first()
            .expect("homeservers should be non-empty")
    }

    /// Get the http relay in the testnet.
    pub fn http_relay(&self) -> &HttpRelay {
        self.testnet
            .http_relays
            .first()
            .expect("no http relay configured - use .with_http_relay() when building")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Test that two testnets can be run in a row.
    /// This is to prevent the case where the testnet is not cleaned up properly.
    /// For example, if the port is not released after the testnet is stopped.
    #[tokio::test]
    async fn test_two_testnet_in_a_row() {
        {
            let _ = EphemeralTestnet::builder().build().await.unwrap();
        }

        {
            let _ = EphemeralTestnet::builder().build().await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_homeserver_with_random_keypair() {
        // Start with just DHT + http relay, no homeserver
        let mut testnet = Testnet::new().await.unwrap();
        testnet.create_http_relay().await.unwrap();
        let mut network = EphemeralTestnet {
            testnet,
            #[cfg(feature = "docker-postgres")]
            docker_postgres: None,
        };
        assert!(network.testnet.homeservers.is_empty());

        let _ = network.create_random_homeserver().await.unwrap();
        let _ = network.create_random_homeserver().await.unwrap();
        assert!(network.testnet.homeservers.len() == 2);

        // The two newly created homeservers must have distinct public keys.
        assert_ne!(
            network.testnet.homeservers[0].public_key(),
            network.testnet.homeservers[1].public_key()
        );
    }

    #[tokio::test]
    async fn test_builder_default() {
        // Verify builder creates homeserver with minimal config (admin disabled)
        let network = EphemeralTestnet::builder().build().await.unwrap();
        let homeserver = network.homeserver_app();

        // The builder should use minimal_test_config() by default (admin disabled)
        assert!(
            homeserver.admin_server().is_none(),
            "Builder should use minimal config with admin disabled by default"
        );
        assert!(
            homeserver.metrics_server().is_none(),
            "Builder should use minimal config with metrics disabled by default"
        );
    }

    #[tokio::test]
    async fn test_builder_with_custom_config() {
        // Verify custom config is used (e.g., metrics enabled)
        let mut config = ConfigToml::minimal_test_config();
        config.metrics.enabled = true;

        let network = EphemeralTestnet::builder()
            .config(config)
            .build()
            .await
            .unwrap();

        let homeserver = network.homeserver_app();
        assert!(
            homeserver.metrics_server().is_some(),
            "Custom config should enable metrics"
        );
        assert!(
            homeserver.admin_server().is_none(),
            "Custom config should keep admin disabled"
        );
    }

    #[tokio::test]
    async fn test_builder_with_custom_keypair() {
        // Verify custom keypair is used
        let keypair = Keypair::random();
        let expected_public_key = keypair.public_key();

        let network = EphemeralTestnet::builder()
            .keypair(keypair)
            .build()
            .await
            .unwrap();

        let homeserver = network.homeserver_app();
        assert_eq!(
            homeserver.public_key(),
            expected_public_key,
            "Custom keypair should be used"
        );
    }
}
