use crate::pubky::Pubky;
use anyhow::Context;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::common::testnet_keypair;
use crate::Testnet;
use http_relay::HttpRelay;
use pubky_common::constants::testnet_ports;
use pubky_homeserver::{
    AppContext, ConfigToml, ConnectionString, DhtMode, DomainPort, HomeserverApp, PersistentDataDir,
};

/// The bind address used for all static testnet listeners.
const BIND_ALL: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

/// Apply the fixed static-testnet port and DHT overrides to a config.
fn apply_static_testnet_overrides(config: &mut ConfigToml, bootstrap_nodes: Vec<DomainPort>) {
    config.pkdns.dht_bootstrap_nodes = Some(bootstrap_nodes);
    config.pkdns.dht_relay_nodes = None;
    config.drive.icann_listen_socket =
        SocketAddr::new(BIND_ALL, testnet_ports::HOMESERVER_ICANN_HTTP);
    config.drive.pubky_listen_socket =
        SocketAddr::new(BIND_ALL, testnet_ports::HOMESERVER_PUBKY_HTTPS);
    config.admin.enabled = true;
    config.admin.listen_socket = SocketAddr::new(BIND_ALL, testnet_ports::HOMESERVER_ADMIN);
}

/// How the testnet stores homeserver state.
#[derive(Debug)]
enum StorageMode {
    /// All state lives in memory / temp dirs and is lost on shutdown.
    InMemory,
    /// State is persisted to the given data directory across restarts.
    Persistent(PathBuf),
}

/// Builder for configuring and starting a [`StaticTestnet`].
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> anyhow::Result<()> {
/// use pubky_testnet::StaticTestnet;
///
/// // In-memory (default)
/// let testnet = StaticTestnet::builder().build().await?;
///
/// // In-memory with custom config
/// let testnet = StaticTestnet::builder()
///     .homeserver_config("my-config.toml".into())
///     .build()
///     .await?;
///
/// // Persistent
/// let testnet = StaticTestnet::builder()
///     .persistent("./my-testnet".into())
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct StaticTestnetBuilder {
    homeserver_config: Option<PathBuf>,
    mode: StorageMode,
}

impl StaticTestnetBuilder {
    fn new() -> Self {
        Self {
            homeserver_config: None,
            mode: StorageMode::InMemory,
        }
    }

    /// Set a custom homeserver config file.
    ///
    /// In in-memory mode, this overrides the default config.
    /// In persistent mode, this seeds the initial `config.toml` on first run
    /// (errors if one already exists in the data directory).
    pub fn homeserver_config(mut self, path: PathBuf) -> Self {
        self.homeserver_config = Some(path);
        self
    }

    /// Enable persistent mode with the given data directory.
    ///
    /// The directory is auto-initialized on first run (config.toml, secret, data/files/).
    /// On subsequent runs, the existing state is picked up.
    pub fn persistent(mut self, data_dir: PathBuf) -> Self {
        self.mode = StorageMode::Persistent(data_dir);
        self
    }

    /// Build and start the testnet with the configured options.
    pub async fn build(self) -> anyhow::Result<StaticTestnet> {
        let mut testnet = StaticTestnet::start_infra().await?;

        let persistent = match self.mode {
            StorageMode::InMemory => {
                testnet
                    .run_in_memory_homeserver(self.homeserver_config.as_deref())
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to run in-memory homeserver: {}", e))?;
                false
            }
            StorageMode::Persistent(data_dir) => {
                testnet
                    .run_persistent_homeserver(data_dir, self.homeserver_config.as_deref())
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to run persistent homeserver: {}", e))?;
                true
            }
        };
        testnet.is_persistent = persistent;

        Ok(testnet)
    }
}

/// A testnet for **interactive / CLI use** — all ports are fixed and well-known.
///
/// Use this when you need a long-running testnet that external processes can
/// connect to (e.g. browser tests, mobile apps, or manual debugging). The fixed
/// ports make it easy to hard-code endpoints in client configuration.
///
/// Supports two storage modes:
/// - **In-memory** (default) — all state is lost on shutdown.
/// - **Persistent** — state is stored on disk and survives restarts.
///   Enable with `.persistent(data_dir)` on the builder.
///
/// For automated tests with random ports, see [`EphemeralTestnet`](crate::EphemeralTestnet).
///
/// # Fixed ports
/// - DHT bootstrap node: `6881`
/// - pkarr relay: `15411`
/// - HTTP relay: `15412`
/// - Homeserver ICANN HTTP: `6286`
/// - Homeserver Pubky HTTPS: `6287`
/// - Homeserver admin: `6288`
///
/// The homeserver address is hardcoded to `8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo`.
pub struct StaticTestnet {
    /// Inner flexible testnet.
    pub testnet: Testnet,
    /// Whether the homeserver is using persistent on-disk storage.
    is_persistent: bool,
    #[allow(dead_code)]
    fixed_bootstrap_node: Option<mainline::Dht>, // Keep alive
    #[allow(dead_code)]
    temp_dirs: Vec<tempfile::TempDir>, // Keep temp dirs alive for the pkarr relay
}

impl StaticTestnet {
    /// Create a builder for configuring the testnet.
    pub fn builder() -> StaticTestnetBuilder {
        StaticTestnetBuilder::new()
    }

    /// Run an in-memory testnet with the default homeserver config.
    pub async fn start() -> anyhow::Result<Self> {
        Self::builder().build().await
    }

    /// Run an in-memory testnet with a custom homeserver config.
    #[deprecated(
        since = "0.9.0",
        note = "Use StaticTestnet::builder().homeserver_config(path).build() instead"
    )]
    pub async fn start_with_homeserver_config(config_path: PathBuf) -> anyhow::Result<Self> {
        Self::builder().homeserver_config(config_path).build().await
    }

    /// Whether this testnet is running in persistent mode.
    pub fn is_persistent(&self) -> bool {
        self.is_persistent
    }

    /// Start the shared infrastructure (DHT bootstrap node, pkarr relay, http relay)
    /// without a homeserver.
    async fn start_infra() -> anyhow::Result<Self> {
        let testnet = Testnet::new().await?;
        let fixed_bootsrap =
            Self::run_fixed_bootsrap_node(&testnet.dht.bootstrap).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to run bootstrap node on port {}: {}",
                    testnet_ports::BOOTSTRAP,
                    e
                )
            })?;

        let mut testnet = Self {
            testnet,
            fixed_bootstrap_node: fixed_bootsrap,
            temp_dirs: vec![],
            is_persistent: false,
        };

        testnet.run_fixed_pkarr_relays().await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to run pkarr relay on port {}: {}",
                testnet_ports::PKARR_RELAY,
                e
            )
        })?;
        testnet.run_fixed_http_relay().await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to run http relay on port {}: {}",
                testnet_ports::HTTP_RELAY,
                e
            )
        })?;

        Ok(testnet)
    }

    /// Create an additional homeserver with a random keypair.
    pub async fn create_random_homeserver(
        &mut self,
    ) -> anyhow::Result<&pubky_homeserver::HomeserverApp> {
        self.testnet.create_random_homeserver().await
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
            .expect("http relays should be non-empty")
    }

    /// Get the pkarr relay in the testnet.
    pub fn pkarr_relay(&self) -> &pkarr_relay::Relay {
        self.testnet
            .pkarr_relays
            .first()
            .expect("pkarr relays should be non-empty")
    }

    /// Get the bootstrap nodes for the testnet.
    pub fn bootstrap_nodes(&self) -> Vec<String> {
        let mut nodes = vec![];
        if let Some(dht) = &self.fixed_bootstrap_node {
            #[allow(deprecated, reason = "mainline has no synchronous replacement")]
            nodes.push(dht.info().local_addr().to_string());
        }
        nodes.extend(
            self.testnet
                .dht_bootstrap_nodes()
                .iter()
                .map(|node| node.to_string()),
        );
        nodes
    }

    /// Create a fixed bootstrap node on port 6881 if it is not already running.
    /// If it's already running, return None.
    fn run_fixed_bootsrap_node(
        other_bootstrap_nodes: &[String],
    ) -> anyhow::Result<Option<mainline::Dht>> {
        let port_suffix = format!(":{}", testnet_ports::BOOTSTRAP);
        if other_bootstrap_nodes
            .iter()
            .any(|node| node.ends_with(&port_suffix))
        {
            return Ok(None);
        }

        let mut builder = mainline::Dht::builder();
        let dht = builder
            .port(testnet_ports::BOOTSTRAP)
            .bootstrap(other_bootstrap_nodes)
            .server_mode()
            .build()?;
        Ok(Some(dht))
    }

    /// Creates a fixed pkarr relay with a temporary storage directory.
    async fn run_fixed_pkarr_relays(&mut self) -> anyhow::Result<()> {
        let temp_dir = tempfile::tempdir()?; // Gets cleaned up automatically when it drops
        let mut builder = pkarr_relay::Relay::builder();
        builder
            .http_port(testnet_ports::PKARR_RELAY)
            .storage(temp_dir.path().to_path_buf())
            .disable_rate_limiter()
            .report_policy(pkarr::dht::ReportPolicy::testnet())
            .dht(|config| {
                config.bootstrap = Some(
                    self.testnet
                        .dht
                        .bootstrap
                        .iter()
                        .map(|address| address.parse().expect("testnet bootstrap address is valid"))
                        .collect(),
                );
                config
            });
        let relay = unsafe { builder.run() }.await?;
        self.testnet.pkarr_relays.push(relay);
        self.temp_dirs.push(temp_dir);
        Ok(())
    }

    /// Creates a fixed http relay.
    async fn run_fixed_http_relay(&mut self) -> anyhow::Result<()> {
        let relay = HttpRelay::builder()
            .bind_address(BIND_ALL)
            .http_port(testnet_ports::HTTP_RELAY)
            .cors_allow_all(true)
            .run()
            .await?;
        self.testnet.http_relays.push(relay);
        Ok(())
    }

    fn parse_bootstrap_nodes(&self) -> anyhow::Result<Vec<DomainPort>> {
        self.bootstrap_nodes()
            .iter()
            .map(|node| {
                DomainPort::from_str(node).map_err(|e| {
                    anyhow::anyhow!("Failed to parse bootstrap node '{}': {}", node, e)
                })
            })
            .collect()
    }

    async fn run_persistent_homeserver(
        &mut self,
        data_dir: PathBuf,
        config_path: Option<&Path>,
    ) -> anyhow::Result<()> {
        let persistent_dir = PersistentDataDir::new(data_dir);

        if let Some(source) = config_path {
            persistent_dir.seed_config(source).context(
                "Remove --homeserver-config to use the existing config, \
                 or delete the file to replace it.",
            )?;
        }

        persistent_dir.ensure_exists_and_is_writable()?;
        persistent_dir.seed_keypair_if_missing(&testnet_keypair())?;

        // Read config and keypair from disk, then apply testnet overrides.
        let mut config = persistent_dir.read_or_create_config_file()?;
        let keypair = persistent_dir.read_or_create_keypair()?;

        apply_static_testnet_overrides(&mut config, self.parse_bootstrap_nodes()?);
        config.general.database_url = resolve_persistent_database_url(
            self.testnet.postgres_connection_string.clone(),
            config.general.database_url,
        )?;
        let db_mode =
            pubky_homeserver::DatabaseMode::require_direct(config.general.database_url.clone())?;

        let data_path = persistent_dir.path().to_path_buf();
        let context =
            AppContext::new(data_path, config, keypair, db_mode, DhtMode::Isolated).await?;
        let homeserver = HomeserverApp::start(context).await?;
        self.testnet.homeservers.push(homeserver);
        Ok(())
    }

    async fn run_in_memory_homeserver(&mut self, config_path: Option<&Path>) -> anyhow::Result<()> {
        let mut config = if let Some(config_path) = config_path {
            ConfigToml::from_file(config_path)?
        } else {
            ConfigToml::default_test_config()
        };
        apply_static_testnet_overrides(&mut config, self.parse_bootstrap_nodes()?);

        let (context, temp_dir) = AppContext::new_ephemeral(config, testnet_keypair()).await?;
        self.testnet.start_homeserver(context, temp_dir).await?;
        Ok(())
    }
}

/// Resolve the database URL for a persistent testnet homeserver.
///
/// Priority:
/// 1. Programmatic override (e.g. from `Testnet::new_with_custom_postgres`)
/// 2. On-disk config value (`config.toml` → `[general].database_url`)
/// 3. `TEST_PUBKY_CONNECTION_STRING` environment variable
fn resolve_persistent_database_url(
    programmatic: Option<ConnectionString>,
    from_config: Option<ConnectionString>,
) -> anyhow::Result<Option<ConnectionString>> {
    resolve_persistent_database_url_inner(
        programmatic,
        from_config,
        ConnectionString::from_test_env()?,
    )
}

/// Pure resolution logic, separated from env access for testability.
fn resolve_persistent_database_url_inner(
    programmatic: Option<ConnectionString>,
    from_config: Option<ConnectionString>,
    from_env: Option<ConnectionString>,
) -> anyhow::Result<Option<ConnectionString>> {
    Ok(programmatic.or(from_config).or(from_env))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn static_overrides_apply_to_config() {
        let temp = TempDir::new().unwrap();
        let persistent = PersistentDataDir::new(temp.path().to_path_buf());
        persistent.init().unwrap();

        let bootstrap = vec![DomainPort::from_str("127.0.0.1:6881").unwrap()];
        let mut config = persistent.read_or_create_config_file().unwrap();
        apply_static_testnet_overrides(&mut config, bootstrap.clone());

        assert_eq!(config.pkdns.dht_bootstrap_nodes, Some(bootstrap));
        assert_eq!(config.pkdns.dht_relay_nodes, None);
    }

    #[test]
    fn persistent_testnet_seeds_deterministic_keypair() {
        let temp = TempDir::new().unwrap();
        let persistent = PersistentDataDir::new(temp.path().to_path_buf());
        persistent.ensure_exists_and_is_writable().unwrap();

        // No keypair file yet — seeding should create the deterministic one.
        persistent
            .seed_keypair_if_missing(&testnet_keypair())
            .unwrap();

        let expected = testnet_keypair();
        let kp = persistent.read_or_create_keypair().unwrap();
        assert_eq!(
            kp.public_key(),
            expected.public_key(),
            "Should seed the deterministic keypair"
        );

        // Second read should return the same key.
        let kp2 = persistent.read_or_create_keypair().unwrap();
        assert_eq!(kp.public_key(), kp2.public_key());
    }

    #[test]
    fn persistent_testnet_preserves_existing_keypair() {
        let temp = TempDir::new().unwrap();
        let persistent = PersistentDataDir::new(temp.path().to_path_buf());
        persistent.init().unwrap();

        // init() created a random keypair — seeding should NOT overwrite it.
        let existing_kp = persistent.read_or_create_keypair().unwrap();

        persistent
            .seed_keypair_if_missing(&testnet_keypair())
            .unwrap();

        let kp = persistent.read_or_create_keypair().unwrap();
        assert_eq!(
            kp.public_key(),
            existing_kp.public_key(),
            "Should not overwrite an existing keypair"
        );
    }

    #[test]
    fn config_seeding_copies_file_to_empty_data_dir() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("testnet");
        let persistent = PersistentDataDir::new(data_dir);

        let source_config = temp.path().join("custom.toml");
        let sample = ConfigToml::sample_string();
        std::fs::write(&source_config, &sample).unwrap();

        persistent.seed_config(&source_config).unwrap();

        assert!(persistent.get_config_file_path().exists());
        let content = std::fs::read_to_string(persistent.get_config_file_path()).unwrap();
        assert_eq!(content, sample);
    }

    #[test]
    fn config_seeding_rejects_when_config_already_exists() {
        let temp = TempDir::new().unwrap();
        let persistent = PersistentDataDir::new(temp.path().to_path_buf());
        persistent.init().unwrap();

        let source = temp.path().join("other.toml");
        std::fs::write(&source, "[general]\nsignup_mode = \"open\"\n").unwrap();

        let result = persistent.seed_config(&source);
        assert!(
            result.is_err(),
            "Seeding should be rejected when config.toml already exists"
        );
        assert!(
            result.unwrap_err().to_string().contains("already exists"),
            "Error message should mention existing config"
        );
    }

    #[test]
    fn builder_defaults_to_in_memory() {
        let builder = StaticTestnet::builder();
        assert!(
            matches!(builder.mode, StorageMode::InMemory),
            "Default mode should be InMemory"
        );
        assert!(builder.homeserver_config.is_none());
    }

    #[test]
    fn builder_persistent_sets_mode() {
        let dir = PathBuf::from("/tmp/test-data");
        let builder = StaticTestnet::builder().persistent(dir.clone());
        match &builder.mode {
            StorageMode::Persistent(d) => assert_eq!(d, &dir),
            StorageMode::InMemory => panic!("Expected Persistent mode"),
        }
    }

    #[test]
    fn builder_homeserver_config_sets_path() {
        let config = PathBuf::from("/tmp/my-config.toml");
        let builder = StaticTestnet::builder().homeserver_config(config.clone());
        assert_eq!(builder.homeserver_config, Some(config));
    }

    #[test]
    fn builder_chaining_all_options() {
        let dir = PathBuf::from("/tmp/data");
        let config = PathBuf::from("/tmp/config.toml");
        let builder = StaticTestnet::builder()
            .homeserver_config(config.clone())
            .persistent(dir.clone());
        assert_eq!(builder.homeserver_config, Some(config));
        assert!(matches!(builder.mode, StorageMode::Persistent(d) if d == dir));
    }

    #[test]
    fn persistent_data_dir_init_creates_structure() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("new-testnet");
        let persistent = PersistentDataDir::new(data_dir.clone());
        persistent.init().unwrap();

        assert!(
            persistent.get_config_file_path().exists(),
            "config.toml should be created"
        );
        // Keypair file should exist after init
        let kp = persistent.read_or_create_keypair().unwrap();
        let kp2 = persistent.read_or_create_keypair().unwrap();
        assert_eq!(
            kp.public_key(),
            kp2.public_key(),
            "Keypair should be stable across reads"
        );
    }

    #[test]
    fn seeded_config_has_testnet_overrides() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("testnet");
        let persistent = PersistentDataDir::new(data_dir);

        // Write a config override with signup_mode = "token_required" (non-default for tests)
        let config_content = "[general]\nsignup_mode = \"token_required\"\n";
        let source = temp.path().join("seed.toml");
        std::fs::write(&source, config_content).unwrap();

        // Seed: create dir, copy config, init
        std::fs::create_dir_all(persistent.path()).unwrap();
        std::fs::copy(&source, persistent.get_config_file_path()).unwrap();
        persistent.init().unwrap();

        // Read config and apply testnet overrides (as run_persistent_homeserver does)
        let bootstrap = vec![DomainPort::from_str("127.0.0.1:6881").unwrap()];
        let mut config = persistent.read_or_create_config_file().unwrap();
        apply_static_testnet_overrides(&mut config, bootstrap.clone());

        // Seeded value should be preserved
        assert_eq!(
            config.general.signup_mode,
            pubky_homeserver::SignupMode::TokenRequired
        );
        // DHT bootstrap should be overridden
        assert_eq!(config.pkdns.dht_bootstrap_nodes, Some(bootstrap));
        assert_eq!(config.pkdns.dht_relay_nodes, None);
        // Fixed ports should be applied
        assert_eq!(
            config.drive.icann_listen_socket.port(),
            testnet_ports::HOMESERVER_ICANN_HTTP
        );
        assert_eq!(
            config.drive.pubky_listen_socket.port(),
            testnet_ports::HOMESERVER_PUBKY_HTTPS
        );
        assert_eq!(
            config.admin.listen_socket.port(),
            testnet_ports::HOMESERVER_ADMIN
        );
        assert!(config.admin.enabled);
    }

    #[test]
    fn persistent_state_survives_restart() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("testnet");
        let bootstrap = vec![DomainPort::from_str("127.0.0.1:6881").unwrap()];
        let expected_key = testnet_keypair();

        // First "run": seed config, seed deterministic keypair
        let source = temp.path().join("seed.toml");
        std::fs::write(&source, "[general]\nsignup_mode = \"token_required\"\n").unwrap();

        let persistent1 = PersistentDataDir::new(data_dir.clone());
        persistent1.seed_config(&source).unwrap();
        persistent1.ensure_exists_and_is_writable().unwrap();
        persistent1.read_or_create_config_file().unwrap();

        // Seed the deterministic keypair (as run_persistent_homeserver does)
        persistent1
            .seed_keypair_if_missing(&testnet_keypair())
            .unwrap();

        let kp1 = persistent1.read_or_create_keypair().unwrap();
        let mut config1 = persistent1.read_or_create_config_file().unwrap();
        apply_static_testnet_overrides(&mut config1, bootstrap.clone());
        assert_eq!(
            kp1.public_key(),
            expected_key.public_key(),
            "First run should use the deterministic keypair"
        );
        drop(persistent1);

        // Second "run": same dir, no seeding — simulates restart
        let persistent2 = PersistentDataDir::new(data_dir);
        persistent2
            .seed_keypair_if_missing(&testnet_keypair())
            .unwrap(); // Should be a no-op
        let kp2 = persistent2.read_or_create_keypair().unwrap();
        let mut config2 = persistent2.read_or_create_config_file().unwrap();
        apply_static_testnet_overrides(&mut config2, bootstrap);

        assert_eq!(
            kp1.public_key(),
            kp2.public_key(),
            "Keypair should persist across restarts"
        );
        assert_eq!(
            config1.general.signup_mode, config2.general.signup_mode,
            "Config should persist across restarts"
        );
        assert_eq!(
            config2.general.signup_mode,
            pubky_homeserver::SignupMode::TokenRequired
        );
    }

    #[test]
    fn persistent_db_url_programmatic_wins() {
        let programmatic = ConnectionString::new("postgres://prog:5432/db").unwrap();
        let from_config = ConnectionString::new("postgres://config:5432/db").unwrap();
        let from_env = ConnectionString::new("postgres://env:5432/db").unwrap();

        let result = resolve_persistent_database_url_inner(
            Some(programmatic.clone()),
            Some(from_config),
            Some(from_env),
        )
        .unwrap();
        assert_eq!(result.unwrap().as_str(), programmatic.as_str());
    }

    #[test]
    fn persistent_db_url_config_used_when_no_programmatic() {
        let from_config = ConnectionString::new("postgres://config:5432/db").unwrap();
        let from_env = ConnectionString::new("postgres://env:5432/db").unwrap();

        let result =
            resolve_persistent_database_url_inner(None, Some(from_config.clone()), Some(from_env))
                .unwrap();
        assert_eq!(result.unwrap().as_str(), from_config.as_str());
    }

    #[test]
    fn persistent_db_url_env_used_as_fallback() {
        let from_env = ConnectionString::new("postgres://env:5432/db").unwrap();

        let result =
            resolve_persistent_database_url_inner(None, None, Some(from_env.clone())).unwrap();
        assert_eq!(result.unwrap().as_str(), from_env.as_str());
    }

    #[test]
    fn persistent_db_url_none_when_nothing_set() {
        let result = resolve_persistent_database_url_inner(None, None, None).unwrap();
        assert!(result.is_none());
    }
}
