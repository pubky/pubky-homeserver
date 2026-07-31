//! Top-level application orchestrator.
//!
//! [`HomeserverApp`] owns and coordinates the three HTTP servers
//! ([`ClientServer`], [`AdminServer`], [`MetricsServer`]) and the background
//! DHT republishers. It handles startup (config loading, database connection,
//! migration) and graceful shutdown.

use crate::admin_server::{AdminServer, AdminServerBuildError};
use crate::client_server::{ClientServer, ClientServerBuildError};
use crate::metrics_server::{MetricsServer, MetricsServerBuildError};
use crate::republishers::{
    HomeserverKeyRepublisher, KeyRepublisherBuildError, UserKeysRepublisherJob,
};
use crate::tracing::init_tracing_logs_with_config_if_set;
#[cfg(any(test, feature = "testing"))]
use crate::MockDataDir;
use crate::{app_context::AppContext, data_directory::PersistentDataDir};
use anyhow::Result;
use pubky_common::crypto::PublicKey;
use std::path::PathBuf;
use std::time::Duration;

/// Errors that can occur when building a `HomeserverApp`.
#[derive(thiserror::Error, Debug)]
pub enum HomeserverAppBuildError {
    /// Failed to build the homeserver.
    #[error("Failed to build homeserver: {0}")]
    Homeserver(ClientServerBuildError),
    /// Failed to build the admin server.
    #[error("Failed to build admin server: {0}")]
    Admin(AdminServerBuildError),
    /// Failed to build the metrics server.
    #[error("Failed to build metrics server: {0}")]
    Metrics(MetricsServerBuildError),
}

/// Homeserver with all bells and whistles.
/// Core + Admin + Metrics servers.
///
/// When dropped, the homeserver will stop.
pub struct HomeserverApp {
    context: AppContext,

    #[allow(dead_code)] // Keep this alive. When dropped, the homeserver will stop.
    client_server: ClientServer,

    // Republishing is stopped when the UserKeysRepublisherJob is dropped.
    _user_keys_republisher_job: Option<UserKeysRepublisherJob>,

    // Republishing is stopped when the HomeserverKeyRepublisher is dropped.
    _key_republisher: HomeserverKeyRepublisher,

    #[allow(dead_code)] // Keep this alive. When dropped, the admin server will stop.
    admin_server: Option<AdminServer>,

    #[allow(dead_code)] // Keep this alive. When dropped, the metrics server will stop.
    metrics_server: Option<MetricsServer>,
}

impl HomeserverApp {
    /// Run the homeserver with configurations from a data directory.
    pub async fn start_with_persistent_data_dir_path(dir_path: PathBuf) -> Result<Self> {
        let data_dir = PersistentDataDir::new(dir_path);
        let context = AppContext::read_from(data_dir).await?;
        Self::start(context).await
    }

    /// Run the homeserver with configurations from a data directory.
    pub async fn start_with_persistent_data_dir(dir: PersistentDataDir) -> Result<Self> {
        let context = AppContext::read_from(dir).await?;
        Self::start(context).await
    }

    /// Run the homeserver with configurations from a data directory mock.
    #[cfg(any(test, feature = "testing"))]
    pub async fn start_with_mock_data_dir(dir: MockDataDir) -> Result<Self> {
        let context = AppContext::read_from(dir).await?;
        Self::start(context).await
    }

    /// Run a Homeserver
    pub async fn start(context: AppContext) -> Result<Self> {
        // Tracing Subscriber initialization based on the config file.
        let _ = init_tracing_logs_with_config_if_set(&context.config_toml);

        tracing::debug!("Homeserver data dir: {}", context.data_dir.path().display());

        let mut pkarr_builder = context.pkarr_builder.clone();
        pkarr_builder.no_relays(); // Disable relays to avoid their rate limiting.
        let republish_interval =
            Duration::from_secs(context.config_toml.pkdns.user_keys_republisher_interval);
        let user_keys_republisher_job = UserKeysRepublisherJob::start(
            context.sql_db.clone(),
            pkarr_builder,
            context.keypair.public_key(),
            republish_interval,
        );

        let admin_server = if context.config_toml.admin.enabled {
            Some(AdminServer::start(&context).await?)
        } else {
            None
        };
        let metrics_server = if context.config_toml.metrics.enabled {
            Some(MetricsServer::start(&context).await?)
        } else {
            None
        };
        let client_server = ClientServer::start(context.clone()).await?;

        let key_republisher = HomeserverKeyRepublisher::start(
            &context,
            client_server.icann_http_socket.port(),
            client_server.pubky_tls_socket.port(),
        )
        .await
        .map_err(KeyRepublisherBuildError::KeyRepublisher)?;

        Ok(Self {
            context,
            client_server,
            admin_server,
            metrics_server,
            _user_keys_republisher_job: user_keys_republisher_job,
            _key_republisher: key_republisher,
        })
    }

    /// Get the core of the homeserver app.
    pub fn client_server(&self) -> &ClientServer {
        &self.client_server
    }

    /// Get the admin server of the homeserver app.
    pub fn admin_server(&self) -> Option<&AdminServer> {
        self.admin_server.as_ref()
    }

    /// Get the metrics server of the homeserver app.
    pub fn metrics_server(&self) -> Option<&MetricsServer> {
        self.metrics_server.as_ref()
    }

    /// Returns the public_key of this server.
    pub fn public_key(&self) -> PublicKey {
        self.context.keypair.public_key()
    }

    /// Returns the `https://<server public key>` url
    pub fn pubky_url(&self) -> url::Url {
        url::Url::parse(&format!("https://{}", self.public_key().z32())).expect("valid url")
    }

    /// Returns the `https://<server public key>` url
    pub fn icann_http_url(&self) -> url::Url {
        url::Url::parse(&self.client_server.icann_http_url_string()).expect("valid url")
    }
}
