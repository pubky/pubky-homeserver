#![doc = include_str!("../README.md")]
//!

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(any(), deny(clippy::unwrap_used))]
use anyhow::Result;
use http_relay::HttpRelay;
use pubky::{Keypair, Pubky};
use pubky_homeserver::{
    storage_config::StorageConfigToml, ConfigToml, ConnectionString, DomainPort, HomeserverApp,
    MockDataDir,
};
use std::{str::FromStr, time::Duration};
use url::Url;

/// A local test network for Pubky Core development.
/// Can create a flexible amount of pkarr relays, http relays and homeservers.
///
/// Keeps track of the components and can create new ones.
/// Cleans up all resources when dropped.
pub struct Testnet {
    pub(crate) dht: pkarr::mainline::Testnet,
    pub(crate) pkarr_relays: Vec<pkarr_relay::Relay>,
    pub(crate) http_relays: Vec<HttpRelay>,
    pub(crate) homeservers: Vec<HomeserverApp>,
    pub(crate) postgres_connection_string: Option<ConnectionString>,

    temp_dirs: Vec<tempfile::TempDir>,
}

impl Testnet {
    fn new_inner(seeded: bool) -> Result<Self> {
        let dht = pkarr::mainline::Testnet::builder(2)
            .seeded(seeded)
            .build()?;

        let testnet = Self {
            dht,
            pkarr_relays: vec![],
            http_relays: vec![],
            homeservers: vec![],
            temp_dirs: vec![],
            postgres_connection_string: Self::extract_postgres_connection_string_from_env_variable(
            ),
        };

        Ok(testnet)
    }

    /// Run a new testnet with a (fully-initialized) local DHT.
    pub async fn new() -> Result<Self> {
        Self::new_inner(true)
    }

    /// Run a new testnet with a (faster, but partially-initialized) local DHT.
    pub async fn new_unseeded() -> Result<Self> {
        Self::new_inner(false)
    }

    /// Run a new testnet with a local DHT.
    /// Pass an optional postgres connection string to use for the homeserver.
    /// If None, the default test connection string is used.
    pub async fn new_with_custom_postgres(
        postgres_connection_string: ConnectionString,
    ) -> Result<Self> {
        let dht = pkarr::mainline::Testnet::builder(2).build()?;
        let testnet: Testnet = Self {
            dht,
            pkarr_relays: vec![],
            http_relays: vec![],
            homeservers: vec![],
            temp_dirs: vec![],
            postgres_connection_string: Some(postgres_connection_string),
        };

        Ok(testnet)
    }

    /// Extract the postgres connection string from the TEST_PUBKY_CONNECTION_STRING environment variable.
    /// If the environment variable is not set, None is returned.
    /// If the environment variable is set, but the connection string is invalid, a warning is logged and None is returned.
    fn extract_postgres_connection_string_from_env_variable() -> Option<ConnectionString> {
        if let Ok(raw_con_string) = std::env::var("TEST_PUBKY_CONNECTION_STRING") {
            if let Ok(con_string) = ConnectionString::new(&raw_con_string) {
                return Some(con_string);
            } else {
                tracing::warn!("Invalid database connection string in TEST_PUBKY_CONNECTION_STRING environment variable. Ignoring it.");
            }
        }
        None
    }

    /// Run the full homeserver app with core and admin server.
    ///
    /// Uses [`ConfigToml::default_test_config()`] which enables the admin server.
    /// Automatically listens on ephemeral ports and uses this Testnet's bootstrap nodes and relays.
    pub async fn create_homeserver(&mut self) -> Result<&HomeserverApp> {
        let mut config = ConfigToml::default_test_config();
        if let Some(connection_string) = self.postgres_connection_string.as_ref() {
            config.general.database_url = connection_string.clone();
        }
        let mock_dir = MockDataDir::new(config, Some(crate::common::testnet_keypair()))?;
        self.create_homeserver_app_with_mock(mock_dir).await
    }

    /// Run the full homeserver app with core and admin server using a freshly generated random keypair.
    ///
    /// Uses [`ConfigToml::default_test_config()`] which enables the admin server.
    /// Automatically listens on ephemeral ports and uses this Testnet's bootstrap nodes and relays.
    pub async fn create_random_homeserver(&mut self) -> Result<&HomeserverApp> {
        let mut config = ConfigToml::default_test_config();
        if let Some(connection_string) = self.postgres_connection_string.as_ref() {
            config.general.database_url = connection_string.clone();
        }
        let mock_dir = MockDataDir::new(config, Some(Keypair::random()))?;
        self.create_homeserver_app_with_mock(mock_dir).await
    }

    /// Run the full homeserver app with core and admin server
    /// Automatically listens on the configured ports.
    /// Automatically uses the configured bootstrap nodes and relays in this Testnet.
    pub async fn create_homeserver_app_with_mock(
        &mut self,
        mut mock_dir: MockDataDir,
    ) -> Result<&HomeserverApp> {
        mock_dir.config_toml.pkdns.dht_bootstrap_nodes = Some(self.dht_bootstrap_nodes());
        if !self.dht_relay_urls().is_empty() {
            mock_dir.config_toml.pkdns.dht_relay_nodes = Some(self.dht_relay_urls().to_vec());
        }
        mock_dir.config_toml.storage.backend = StorageConfigToml::InMemory;
        let homeserver = HomeserverApp::start_with_mock_data_dir(mock_dir).await?;
        self.homeservers.push(homeserver);
        Ok(self
            .homeservers
            .last()
            .expect("homeservers should be non-empty"))
    }

    /// Run an HTTP Relay
    pub async fn create_http_relay(&mut self) -> Result<&HttpRelay> {
        let relay = HttpRelay::builder()
            .http_port(0) // Random available port
            .cors_allow_all(true)
            .run()
            .await?;
        self.http_relays.push(relay);
        Ok(self
            .http_relays
            .last()
            .expect("http relays should be non-empty"))
    }

    /// Run a new Pkarr relay.
    ///
    /// You can access the list of relays at `Self::pkarr_relays`.
    pub async fn create_pkarr_relay(&mut self) -> Result<Url> {
        let dir = tempfile::tempdir()?;
        let mut builder = pkarr_relay::Relay::builder();
        builder
            .disable_rate_limiter()
            .http_port(0)
            .storage(dir.path().to_path_buf())
            .report_policy(pkarr::dht::ReportPolicy::testnet())
            .dht(|config| {
                config.bootstrap = Some(
                    self.dht
                        .bootstrap
                        .iter()
                        .map(|address| address.parse().expect("testnet bootstrap address is valid"))
                        .collect(),
                );
                config
            });
        let relay = unsafe { builder.run().await? };
        let url = relay.local_url();
        self.pkarr_relays.push(relay);
        self.temp_dirs.push(dir);
        Ok(url)
    }

    // === Getters ===

    /// Returns a list of DHT bootstrapping nodes.
    pub fn dht_bootstrap_nodes(&self) -> Vec<DomainPort> {
        self.dht
            .bootstrap
            .iter()
            .map(|address| {
                DomainPort::from_str(address)
                    .expect("bootstrap nodes from the pkarr dht are always valid domain:port pairs")
            })
            .collect()
    }

    /// Returns a list of pkarr relays.
    pub fn dht_relay_urls(&self) -> Vec<Url> {
        self.pkarr_relays.iter().map(|r| r.local_url()).collect()
    }

    /// Create a [pubky::PubkyHttpClientBuilder] and configure it to use this local test network.
    pub fn client_builder(&self) -> pubky::PubkyHttpClientBuilder {
        let relays = self.dht_relay_urls();

        let mut builder = pubky::PubkyHttpClient::builder();
        builder.pkarr(|builder| {
            builder
                .no_default_network()
                .bootstrap(&self.dht.bootstrap)
                .dht_report_policy(pkarr::dht::ReportPolicy::testnet())
                // 100ms timeout for requests. This makes network-only resolution fast
                // because it doesn't need to wait the default 2s which would slow down the tests.
                .request_timeout(Duration::from_millis(100));
            if relays.is_empty() {
                builder.no_relays()
            } else {
                builder
                    .relays(&relays)
                    .expect("testnet relays should be valid urls")
            }
        });

        builder
    }

    /// Creates a [`pubky::PubkyHttpClient`] pre-configured to use this test network.
    ///
    /// This is a convenience method that builds a client from `Self::client_builder`.
    pub fn client(&self) -> Result<pubky::PubkyHttpClient, pubky::BuildError> {
        self.client_builder().build()
    }

    /// Creates a [`pubky::Pubky`] SDK facade pre-configured to use this test network.
    ///
    /// This is a convenience method that builds a client from `Self::client_builder`.
    pub fn sdk(&self) -> Result<Pubky, pubky::BuildError> {
        Ok(Pubky::with_client(self.client()?))
    }

    /// Create a [pkarr::ClientBuilder] and configure it to use this local test network.
    pub fn pkarr_client_builder(&self) -> pkarr::ClientBuilder {
        let relays = self.dht_relay_urls();
        let mut builder = pkarr::Client::builder();
        builder.no_default_network(); // Remove DHT bootstrap nodes and relays
        builder
            .bootstrap(&self.dht.bootstrap)
            .dht_report_policy(pkarr::dht::ReportPolicy::testnet());
        if !relays.is_empty() {
            builder
                .relays(&relays)
                .expect("Testnet relays should be valid urls");
        }

        builder
    }
}

#[cfg(test)]
mod test {
    use crate::Testnet;
    use pubky::Keypair;

    /// Make sure the components are kept alive even when dropped.
    #[tokio::test]
    #[crate::test]
    async fn test_keep_relays_alive_even_when_dropped() {
        let mut testnet = Testnet::new().await.unwrap();
        {
            let _relay = testnet.create_http_relay().await.unwrap();
        }
        assert_eq!(testnet.http_relays.len(), 1);
    }

    /// Boostrap node conversion
    #[tokio::test]
    #[crate::test]
    async fn test_boostrap_node_conversion() {
        let testnet = Testnet::new().await.unwrap();
        let nodes = testnet.dht_bootstrap_nodes();
        assert_eq!(nodes.len(), 2);
    }

    /// Test that a user can signup in the testnet.
    /// This is an e2e tests to check if everything is correct.
    #[tokio::test]
    #[crate::test]
    async fn test_signup() {
        let mut testnet = Testnet::new().await.unwrap();
        testnet.create_homeserver().await.unwrap();

        let hs = testnet.homeservers.first().unwrap();
        let sdk = testnet.sdk().unwrap();

        let signer = sdk.signer(Keypair::random());

        let session = signer.signup_cookie(&hs.public_key(), None).await.unwrap();
        assert_eq!(session.info().public_key(), &signer.public_key());
    }

    #[tokio::test]
    async fn test_independent_dhts() {
        let t1 = Testnet::new().await.unwrap();
        let t2 = Testnet::new().await.unwrap();

        assert_ne!(t1.dht.bootstrap, t2.dht.bootstrap);
    }

    /// If everything is linked correctly, the hs_pubky should be resolvable from the pkarr client.
    #[tokio::test]
    async fn test_homeserver_resolvable() {
        let mut testnet = Testnet::new().await.unwrap();
        let hs_pubky = testnet.create_homeserver().await.unwrap().public_key();

        // Make sure the pkarr packet of the hs is resolvable.
        let pkarr_client = testnet.pkarr_client_builder().build().unwrap();
        let _packet = pkarr_client
            .resolve(&hs_pubky, pkarr::ResolvePolicy::CacheFirst)
            .await
            .unwrap();

        // Make sure the pkarr can resolve the hs_pubky.
        let pubkey = hs_pubky.z32();
        let _endpoint = pkarr_client
            .resolve_https_endpoint(pubkey.as_str())
            .await
            .unwrap();
    }

    /// Test relay resolvable.
    /// This simulates pkarr clients in a browser.
    /// Made due to https://github.com/pubky/pkarr/issues/140
    #[tokio::test]
    #[crate::test]
    async fn test_pkarr_relay_resolvable() {
        let mut testnet = Testnet::new().await.unwrap();
        testnet.create_pkarr_relay().await.unwrap();

        let keypair = Keypair::random();

        // Publish packet on the DHT without using the relay.
        let client = testnet.pkarr_client_builder().build().unwrap();
        let signed = pkarr::SignedPacket::builder().sign(&keypair).unwrap();
        client.publish(&signed).await.unwrap();

        // Resolve packet with a new client to prevent caching
        // Only use the DHT, no relays
        let client = testnet.pkarr_client_builder().no_relays().build().unwrap();
        let packet = client
            .resolve(&keypair.public_key(), pkarr::ResolvePolicy::CacheFirst)
            .await;
        assert!(
            packet.is_ok(),
            "Published packet is not available over the DHT."
        );

        // Resolve packet with a new client to prevent caching
        // Only use the relay, no DHT
        // This simulates pkarr clients in a browser.
        let client = testnet.pkarr_client_builder().no_dht().build().unwrap();
        let packet = client
            .resolve(&keypair.public_key(), pkarr::ResolvePolicy::CacheFirst)
            .await;
        assert!(
            packet.is_ok(),
            "Published packet is not available over the relay only."
        );
    }
}
