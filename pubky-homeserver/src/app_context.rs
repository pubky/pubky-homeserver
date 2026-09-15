//!
//! The application context shared between all components.
//! Think of it as a simple Dependency Injection container.
//!
//! Build via [`AppContext::new`] with independently resolved:
//! - **Data path** — persistent directory or temp dir
//! - **Database mode** — [`DatabaseMode::Direct`] or `DatabaseMode::EphemeralTest`
//! - **pkarr builder** — a pre-configured [`pkarr::ClientBuilder`]
//!
//! Convenience constructors:
//! - [`AppContext::from_persistent_dir`] — production (persistent dir, public DHT, direct DB)
//! - `AppContext::new_ephemeral` — tests (temp dir, isolated DHT, test DB)
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
    /// `[pkdns].dht_relay_nodes` contains a URL pkarr will not accept as a relay.
    #[error("Invalid `dht_relay_nodes` under [pkdns]: {0}")]
    RelayNodes(anyhow::Error),
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
    /// Keeps an ephemeral data directory alive for as long as any clone of this
    /// context exists, so `data_path` can never outlive the directory it names.
    /// `None` for persistent data directories, which the caller owns.
    #[cfg(any(test, feature = "testing"))]
    _temp_dir: Option<Arc<tempfile::TempDir>>,
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
    /// Production shorthand: persistent data dir, public DHT, direct DB.
    ///
    /// Reads config and keypair from disk via [`crate::PersistentDataDir::bootstrap`].
    ///
    /// This is the **only** constructor that joins the public network: it starts from
    /// `pkarr::ClientBuilder::default()`, so unless `[pkdns]` says otherwise this context
    /// publishes its record to the public pkarr relays and resolves over the public DHT.
    /// That is deliberate for production. Anything under test wants `new_ephemeral`, or
    /// `isolated_pkarr_builder` with [`new`](Self::new).
    ///
    /// When `[general].database_url` is unset, falls back to
    /// [`DEFAULT_DATABASE_URL`](crate::persistence::sql::DEFAULT_DATABASE_URL) — the
    /// fallback lives in code rather than in `config.default.toml` so that the config's
    /// `Option` keeps meaning "the operator chose this". See
    /// [`DatabaseMode::direct_or_default`] for what that accepts.
    pub async fn from_persistent_dir(
        dir: crate::PersistentDataDir,
    ) -> Result<Self, AppContextBuildError> {
        let (path, config, keypair) = dir.bootstrap().map_err(AppContextBuildError::Bootstrap)?;
        let db_mode = DatabaseMode::direct_or_default(config.general.database_url.clone());
        Self::new(
            path,
            config,
            keypair,
            db_mode,
            pkarr::ClientBuilder::default(),
        )
        .await
    }

    /// Quick test context with default config and a deterministic keypair.
    #[cfg(any(test, feature = "testing"))]
    pub async fn test() -> Arc<Self> {
        Arc::new(
            Self::new_ephemeral(
                ConfigToml::default_test_config(),
                Keypair::from_secret(&[0; 32]),
                None,
            )
            .await
            .expect("failed to build test AppContext"),
        )
    }

    /// Quick test context with a custom config modifier and a random keypair.
    #[cfg(any(test, feature = "testing"))]
    pub async fn test_with_config(f: impl FnOnce(&mut ConfigToml)) -> Arc<Self> {
        let mut config = ConfigToml::default_test_config();
        f(&mut config);
        Arc::new(
            Self::new_ephemeral(config, Keypair::random(), None)
                .await
                .expect("failed to build test AppContext"),
        )
    }

    /// Test shorthand: temp data dir, isolated DHT, ephemeral test DB.
    ///
    /// The context owns the temporary directory, so it is removed once the last
    /// clone of the context is dropped — there is no lifetime to manage.
    ///
    /// `database_override` is the top tier of [`DatabaseMode::resolve_test`]: pass a
    /// connection string here to pin the database ahead of `TEST_PUBKY_CONNECTION_STRING`
    /// and `config.general.database_url`, or `None` to let those decide.
    #[cfg(any(test, feature = "testing"))]
    pub async fn new_ephemeral(
        config: ConfigToml,
        keypair: Keypair,
        database_override: Option<crate::persistence::sql::ConnectionString>,
    ) -> Result<Self, AppContextBuildError> {
        Self::new_ephemeral_with_pkarr(
            config,
            keypair,
            database_override,
            Self::isolated_pkarr_builder(),
        )
        .await
    }

    /// Like [`new_ephemeral`](Self::new_ephemeral) but with a caller-supplied pkarr
    /// builder — e.g. one pointed at a `mainline::Testnet`.
    ///
    /// The builder decides which network this context joins, so pass one that is
    /// isolated from the public DHT and relays; [`isolated_pkarr_builder`](Self::isolated_pkarr_builder)
    /// is that starting point.
    ///
    /// As in [`new`](Self::new), the config's `[pkdns]` settings are applied on top of
    /// the given builder, so a config carrying `dht_bootstrap_nodes` overrides the
    /// builder's network — and, because bootstrap nodes clear the relays, also any
    /// relays the builder had set.
    #[cfg(any(test, feature = "testing"))]
    pub async fn new_ephemeral_with_pkarr(
        config: ConfigToml,
        keypair: Keypair,
        database_override: Option<crate::persistence::sql::ConnectionString>,
        pkarr_builder: pkarr::ClientBuilder,
    ) -> Result<Self, AppContextBuildError> {
        let temp_dir =
            tempfile::TempDir::new().map_err(|e| AppContextBuildError::Bootstrap(e.into()))?;
        let data_path = temp_dir.path().to_path_buf();
        let db_mode =
            DatabaseMode::resolve_test(database_override, config.general.database_url.clone())
                .map_err(AppContextBuildError::DatabaseResolution)?;

        let mut ctx = Self::new(data_path, config, keypair, db_mode, pkarr_builder).await?;
        ctx._temp_dir = Some(Arc::new(temp_dir));
        Ok(ctx)
    }

    /// Create an `AppContext` from independently resolved components.
    ///
    /// Each parameter represents a separate concern:
    /// - `data_path` — where file storage lives (persistent dir or temp dir)
    /// - `config` — homeserver configuration
    /// - `keypair` — server identity
    /// - `db_mode` — database lifecycle ([`DatabaseMode::Direct`] or `DatabaseMode::EphemeralTest`)
    /// - `pkarr_builder` — the base [`pkarr::ClientBuilder`], supplying the network to
    ///   join (public by default, or a `mainline::Testnet`) and any transport settings
    ///
    /// The `[pkdns]` DHT settings from `config` are applied on top of `pkarr_builder`,
    /// so a caller can never silently lose them by passing a builder of their own.
    /// Config wins for bootstrap nodes, relays and request timeout; the builder supplies
    /// everything else.
    ///
    /// `data_path` must already exist and be writable — this constructor does not create
    /// it. The convenience constructors handle that for you
    /// ([`from_persistent_dir`](Self::from_persistent_dir) via
    /// [`PersistentDataDir::bootstrap`](crate::PersistentDataDir::bootstrap), `new_ephemeral`
    /// via a temp dir); a caller assembling the parts itself owns that step.
    ///
    /// See [`from_persistent_dir`](Self::from_persistent_dir) and
    /// `new_ephemeral` for common combinations.
    pub async fn new(
        data_path: PathBuf,
        config: ConfigToml,
        keypair: Keypair,
        db_mode: DatabaseMode,
        mut pkarr_builder: pkarr::ClientBuilder,
    ) -> Result<Self, AppContextBuildError> {
        Self::apply_config_to_pkarr(&mut pkarr_builder, &config)?;
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
            #[cfg(any(test, feature = "testing"))]
            _temp_dir: None,
            events_service,
            metrics: Metrics::new().map_err(AppContextBuildError::Metrics)?,
            _pg_event_listener: Arc::new(pg_event_listener),
            revocation_listener,
            user_service,
        })
    }

    /// A pkarr builder isolated from the public network: no default bootstrap nodes,
    /// no default relays, testnet report policy.
    ///
    /// This is the *base* for test and testnet clients. It carries no configuration —
    /// [`new`](Self::new) applies the `[pkdns]` settings to whatever builder it is given,
    /// so applying them here as well would only duplicate the work and its warnings.
    ///
    /// Note that this makes the isolation a property of the *pair*, not of this builder:
    /// the config is applied afterwards and can put the public relays back, because
    /// `config.default.toml` ships them and `no_relays()` is only reached when the config
    /// also names bootstrap nodes. `ConfigToml::default_test_config` clears
    /// `dht_relay_nodes` for exactly this reason; a config assembled some other way must
    /// take care of it too.
    ///
    /// Use it as the base for anything that assembles a context itself —
    /// [`new_ephemeral_with_pkarr`](Self::new_ephemeral_with_pkarr) for a custom network,
    /// or [`new`](Self::new) directly, as the persistent testnet does when it needs a real
    /// data directory but must still stay off the public DHT.
    #[cfg(any(test, feature = "testing"))]
    pub fn isolated_pkarr_builder() -> pkarr::ClientBuilder {
        let mut builder = pkarr::ClientBuilder::default();
        builder
            .no_default_network()
            // Sentinel bootstrap node so the builder stays valid even when neither the
            // caller nor the config supplies bootstrap nodes. Real nodes replace it.
            // Port 9 is the RFC 863 "discard" protocol — guaranteed unreachable as a DHT node.
            .bootstrap(&["127.0.0.1:9"])
            .dht_report_policy(pkarr::dht::ReportPolicy::testnet());
        builder
    }

    /// Apply DHT configuration (bootstrap nodes, relays, timeouts) from config
    /// to a pkarr client builder.
    ///
    /// Setting `dht_bootstrap_nodes` also clears the relays, so a custom DHT is not
    /// silently paired with the public pkarr relays. An explicit `dht_relay_nodes` is
    /// applied afterwards and therefore wins, including on a custom DHT.
    ///
    /// An empty `dht_bootstrap_nodes` list means "no bootstrap nodes" and starts an
    /// isolated DHT.
    fn apply_config_to_pkarr(
        builder: &mut pkarr::ClientBuilder,
        config: &ConfigToml,
    ) -> Result<(), AppContextBuildError> {
        if let Some(bootstrap_nodes) = &config.pkdns.dht_bootstrap_nodes {
            if bootstrap_nodes.is_empty() {
                tracing::warn!(
                    "`dht_bootstrap_nodes = []` under [pkdns] starts an isolated DHT with no \
                     peers: this homeserver will not resolve or publish any records over the \
                     DHT. Remove the key to use the default bootstrap nodes."
                );
            }
            let nodes = bootstrap_nodes
                .iter()
                .map(|node| node.to_string())
                .collect::<Vec<String>>();
            builder.bootstrap(&nodes);
            // Choosing a DHT clears the relays: mixing testnet bootstrap nodes with
            // mainnet relays gives very strange results. An explicit `dht_relay_nodes`
            // below is applied after this and so still wins.
            builder.no_relays();
        }

        // A `url::Url` is not necessarily a valid relay (no host, wrong scheme, ...),
        // so this is a config error to report, not an invariant to assert.
        if let Some(relays) = &config.pkdns.dht_relay_nodes {
            builder
                .relays(relays)
                .map_err(|e| AppContextBuildError::RelayNodes(e.into()))?;
        }
        if let Some(request_timeout) = &config.pkdns.dht_request_timeout_ms {
            let duration = Duration::from_millis(request_timeout.get());
            builder.request_timeout(duration);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The context owns its ephemeral data directory: it survives as long as any clone
    /// does, and goes away with the last one. This is why `AppContext` holds the
    /// `TempDir` rather than handing it back for the caller to keep alive.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn ephemeral_data_dir_outlives_every_clone_of_the_context() {
        let context =
            AppContext::new_ephemeral(ConfigToml::default_test_config(), Keypair::random(), None)
                .await
                .expect("failed to build ephemeral AppContext");
        let data_path = context.data_path.clone();
        assert!(
            data_path.is_dir(),
            "the temp data dir should exist up front"
        );

        let clone = context.clone();
        drop(context);
        assert!(
            data_path.is_dir(),
            "a surviving clone must keep the data dir alive"
        );

        drop(clone);
        assert!(
            !data_path.exists(),
            "dropping the last clone must remove the data dir"
        );
    }

    fn config_with_bootstrap(nodes: &[&str]) -> ConfigToml {
        use crate::DomainPort;
        use std::str::FromStr;

        let mut config = ConfigToml::default_test_config();
        config.pkdns.dht_bootstrap_nodes = Some(
            nodes
                .iter()
                .map(|n| DomainPort::from_str(n).unwrap())
                .collect(),
        );
        config
    }

    fn relays_of(config: &ConfigToml) -> String {
        let mut builder = pkarr::ClientBuilder::default();
        AppContext::apply_config_to_pkarr(&mut builder, config).unwrap();
        format!("{builder:?}")
    }

    fn has_default_relays(debug: &str) -> bool {
        pkarr::DEFAULT_RELAYS.iter().any(|r| debug.contains(r))
    }

    /// Choosing a DHT clears the relays, so testnet bootstrap nodes are never paired
    /// with mainnet relays.
    #[test]
    fn custom_bootstrap_nodes_clear_the_relays() {
        // A literal address: pkarr resolves bootstrap entries to socket addresses, so an
        // unresolvable hostname would simply be dropped and prove nothing.
        let config = config_with_bootstrap(&["127.0.0.1:6881"]);
        assert_eq!(
            config.pkdns.dht_relay_nodes, None,
            "precondition: relays unset"
        );

        let debug = relays_of(&config);
        assert!(debug.contains("127.0.0.1:6881"), "{debug}");
        assert!(
            !has_default_relays(&debug),
            "a custom DHT must not keep the public relays: {debug}"
        );
    }

    /// ...but `dht_relay_nodes` is applied after that, so an explicit list still wins —
    /// including the public relays, which is how a config file that sets both ends up on
    /// a custom DHT *and* the public relays.
    #[test]
    fn an_explicit_relay_list_wins_over_the_bootstrap_clear() {
        let mut config = config_with_bootstrap(&["127.0.0.1:6881"]);
        config.pkdns.dht_relay_nodes =
            Some(vec![url::Url::parse("https://relay.example").unwrap()]);
        let debug = relays_of(&config);
        assert!(debug.contains("relay.example"), "{debug}");
        assert!(!has_default_relays(&debug), "{debug}");

        let mut config = config_with_bootstrap(&["127.0.0.1:6881"]);
        config.pkdns.dht_relay_nodes = Some(
            pkarr::DEFAULT_RELAYS
                .iter()
                .map(|r| url::Url::parse(r).unwrap())
                .collect(),
        );
        let debug = relays_of(&config);
        assert!(
            has_default_relays(&debug),
            "listing the public relays explicitly must keep them: {debug}"
        );
    }

    /// With no bootstrap nodes configured, the builder keeps its own relays unless the
    /// config replaces them.
    #[test]
    fn relays_are_untouched_without_custom_bootstrap_nodes() {
        let mut config = ConfigToml::default_test_config();
        config.pkdns.dht_relay_nodes = None;
        assert_eq!(config.pkdns.dht_bootstrap_nodes, None);
        assert!(
            has_default_relays(&relays_of(&config)),
            "the public relays must survive a config that says nothing about them"
        );

        config.pkdns.dht_relay_nodes =
            Some(vec![url::Url::parse("https://relay.example").unwrap()]);
        let debug = relays_of(&config);
        assert!(debug.contains("relay.example"), "{debug}");
        assert!(!has_default_relays(&debug), "{debug}");
    }

    /// A `url::Url` is not necessarily a valid relay, and it comes straight from the
    /// config file — so a bad value must surface as an error the operator can read,
    /// not a panic at startup.
    #[test]
    fn an_unusable_relay_url_is_a_config_error_not_a_panic() {
        let mut config = ConfigToml::default_test_config();
        config.pkdns.dht_relay_nodes =
            Some(vec![url::Url::parse("mailto:nobody@example").unwrap()]);

        let mut builder = pkarr::ClientBuilder::default();
        let err = AppContext::apply_config_to_pkarr(&mut builder, &config)
            .expect_err("a relay url with no host must be rejected");
        assert!(
            matches!(err, AppContextBuildError::RelayNodes(_)),
            "expected RelayNodes, got {err:?}"
        );
        assert!(err.to_string().contains("dht_relay_nodes"), "{err}");

        // pkarr's error carries a readable explanation; keep it rather than the Debug
        // form, which would render as `Parse(...)` / `NotHttp("...")` and bury the reason.
        let cause = format!("{:#}", anyhow::Error::from(err));
        assert!(
            cause.contains("mailto:nobody@example"),
            "the offending url should be named: {cause}"
        );
        for debug_marker in ["Parse(", "NotHttp("] {
            assert!(
                !cause.contains(debug_marker),
                "error is being rendered with Debug, not Display: {cause}"
            );
        }
    }

    /// An empty bootstrap list means "no bootstrap nodes", mirroring the relay handling.
    #[test]
    fn empty_bootstrap_list_clears_the_default_nodes() {
        let mut builder = pkarr::ClientBuilder::default();
        AppContext::apply_config_to_pkarr(&mut builder, &config_with_bootstrap(&[])).unwrap();
        let debug = format!("{builder:?}");

        assert!(
            debug.contains("bootstrap: Some([])"),
            "an empty list should reach pkarr as an empty bootstrap set: {debug}"
        );
        builder
            .build()
            .expect("a peerless DHT client should still build");
    }

    /// Isolated builder excludes public DHT nodes.
    #[test]
    fn isolated_builder_excludes_public_dht() {
        let builder = AppContext::isolated_pkarr_builder();
        let debug = format!("{builder:?}");

        for relay in pkarr::DEFAULT_RELAYS {
            assert!(
                !debug.contains(relay),
                "default relay {relay} should not appear after no_default_network: {debug}"
            );
        }
        builder.build().expect("isolated pkarr client should build");
    }

    /// The isolation that matters is the one on the *composition*, not on the builder
    /// alone: [`new`](AppContext::new) applies `[pkdns]` on top of whatever builder it is
    /// given, and `no_relays()` is only reached when the config names bootstrap nodes. So
    /// what actually keeps an ephemeral context off the public relays is
    /// `default_test_config` clearing `dht_relay_nodes` — an easy line to "tidy away",
    /// since `config.default.toml` ships the public relays and nothing else asserts this.
    ///
    /// The second half is this test's own control: it proves `has_default_relays` really
    /// does detect relays in pkarr's `Debug` output, so the negative assertion above (and
    /// in [`isolated_builder_excludes_public_dht`]) cannot pass vacuously if that format
    /// ever changes.
    #[test]
    fn the_test_config_keeps_the_isolated_builder_off_the_public_relays() {
        let compose = |config: &ConfigToml| {
            let mut builder = AppContext::isolated_pkarr_builder();
            AppContext::apply_config_to_pkarr(&mut builder, config).unwrap();
            format!("{builder:?}")
        };

        let debug = compose(&ConfigToml::default_test_config());
        assert!(
            !has_default_relays(&debug),
            "an ephemeral context must not reach the public pkarr relays: {debug}"
        );

        // Control: put the packaged relays back and the very same composition lands on
        // them, which is exactly why that line in `default_test_config` is load-bearing.
        let mut config = ConfigToml::default_test_config();
        config.pkdns.dht_relay_nodes = ConfigToml::default().pkdns.dht_relay_nodes;
        assert!(
            config.pkdns.dht_relay_nodes.is_some(),
            "precondition: the packaged defaults still ship relays"
        );
        let debug = compose(&config);
        assert!(
            has_default_relays(&debug),
            "the isolated builder does not defend itself — config relays are applied on \
             top of it: {debug}"
        );
    }

    /// `new` applies the config on top of whatever builder it is given, so a config that
    /// names a network still wins — the documented contract of both constructors.
    #[test]
    fn config_is_applied_on_top_of_a_caller_supplied_builder() {
        use crate::DomainPort;
        use std::str::FromStr;

        let mut config = ConfigToml::default_test_config();
        config.pkdns.dht_bootstrap_nodes =
            Some(vec![DomainPort::from_str("127.0.0.1:7777").unwrap()]);

        let mut builder = AppContext::isolated_pkarr_builder();
        builder.bootstrap(&["127.0.0.1:6881"]);
        AppContext::apply_config_to_pkarr(&mut builder, &config).unwrap();
        let debug = format!("{builder:?}");

        assert!(
            debug.contains("127.0.0.1:7777") && !debug.contains("127.0.0.1:6881"),
            "config bootstrap nodes must replace the caller's: {debug}"
        );
    }
}
