use super::connection_string::ConnectionString;
use crate::ConfigToml;

/// How the homeserver should connect to its database.
///
/// This enum makes the distinction between "connect to an existing database"
/// and "create a fresh ephemeral database for this test" explicit.
#[derive(Debug, Clone)]
pub enum DatabaseMode {
    /// Connect directly to the database identified by the URL.
    /// Used in production and persistent testnets.
    Direct(ConnectionString),

    /// Create an ephemeral `pubky_test_{uuid}` database on the server
    /// identified by the URL, then connect to it.
    ///
    /// Dropping the [`SqlDb`](super::SqlDb) **registers** the database for
    /// cleanup but does not delete it immediately. Actual deletion requires
    /// the `#[pubky_testnet::test]` macro or an explicit call to
    /// [`drop_test_databases()`](pubky_test_utils::drop_test_databases).
    /// Without either, the database will be leaked.
    ///
    /// Only available in test / testing builds.
    #[cfg(any(test, feature = "testing"))]
    EphemeralTest(ConnectionString),
}

impl DatabaseMode {
    /// Returns the underlying connection string, regardless of mode.
    #[cfg(test)]
    pub fn connection_string(&self) -> &ConnectionString {
        match self {
            Self::Direct(url) => url,
            #[cfg(any(test, feature = "testing"))]
            Self::EphemeralTest(url) => url,
        }
    }

    /// Connect to the `database_url` configured in `config.toml`.
    ///
    /// Used by the homeserver binary and
    /// [`AppContext::from_persistent_dir`](crate::AppContext::from_persistent_dir).
    pub fn from_config(config: &ConfigToml) -> anyhow::Result<Self> {
        config
            .general
            .database_url
            .clone()
            .map(Self::Direct)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No database_url configured. Set [general].database_url in config.toml."
                )
            })
    }
}

#[cfg(any(test, feature = "testing"))]
const DEFAULT_TEST_SERVER: &str = "postgres://localhost:5432/postgres";

/// The Postgres maintenance database, which should not hold testnet tables.
#[cfg(any(test, feature = "testing"))]
const MAINTENANCE_DATABASE: &str = "postgres";

#[cfg(any(test, feature = "testing"))]
impl DatabaseMode {
    /// Environment variable naming the Postgres server that ephemeral test
    /// databases are created on.
    pub const EPHEMERAL_SERVER_ENV: &str = "TEST_PUBKY_CONNECTION_STRING";

    /// Environment variable naming the database a persistent testnet keeps
    /// its tables in.
    pub const PERSISTENT_TESTNET_DATABASE_ENV: &str = "PUBKY_TESTNET_DATABASE_URL";

    /// Create a throwaway `pubky_test_{uuid}` database for a test or an
    /// ephemeral testnet.
    ///
    /// The server is, in order of priority: `server`, the
    /// [`Self::EPHEMERAL_SERVER_ENV`] environment variable, then
    /// `postgres://localhost:5432/postgres`.
    pub fn ephemeral(server: Option<ConnectionString>) -> anyhow::Result<Self> {
        let env_val = std::env::var(Self::EPHEMERAL_SERVER_ENV).ok();
        Self::ephemeral_with_env(server, env_val)
    }

    /// Pure resolution logic, separated from env access for testability.
    fn ephemeral_with_env(
        server: Option<ConnectionString>,
        env_val: Option<String>,
    ) -> anyhow::Result<Self> {
        let url = match (server, env_val) {
            (Some(url), _) => url,
            (None, Some(raw)) => parse_env_value(Self::EPHEMERAL_SERVER_ENV, &raw)?,
            (None, None) => ConnectionString::new(DEFAULT_TEST_SERVER)
                .expect("Default test connection string is valid"),
        };
        Ok(Self::EphemeralTest(url))
    }

    /// Connect to the database a persistent testnet keeps its tables in.
    ///
    /// The [`Self::PERSISTENT_TESTNET_DATABASE_ENV`] environment variable
    /// overrides the `database_url` in `config.toml`. Logs which one was used,
    /// and warns when it is the `postgres` maintenance database.
    pub fn persistent_testnet(config: &ConfigToml) -> anyhow::Result<Self> {
        let env_val = std::env::var(Self::PERSISTENT_TESTNET_DATABASE_ENV).ok();
        Self::persistent_testnet_with_env(config, env_val)
    }

    /// [`Self::persistent_testnet`] with the environment variable's value
    /// passed in. For tests only: it lets them supply the value without
    /// changing the process environment, which is not thread-safe.
    #[doc(hidden)]
    pub fn persistent_testnet_with_env(
        config: &ConfigToml,
        env_val: Option<String>,
    ) -> anyhow::Result<Self> {
        let (url, source) = match env_val {
            Some(raw) => (
                parse_env_value(Self::PERSISTENT_TESTNET_DATABASE_ENV, &raw)?,
                Self::PERSISTENT_TESTNET_DATABASE_ENV,
            ),
            None => {
                let url = config.general.database_url.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Persistent testnet requires a database. Set {} or `database_url` \
                         in config.toml under [general].",
                        Self::PERSISTENT_TESTNET_DATABASE_ENV
                    )
                })?;
                (url, "database_url in config.toml")
            }
        };
        tracing::info!("Using database `{}` from {source}", url.database_name());
        if url.database_name() == MAINTENANCE_DATABASE {
            tracing::warn!(
                "Persistent testnet tables are going into the `{MAINTENANCE_DATABASE}` \
                 maintenance database; point {source} at a dedicated database instead"
            );
        }
        Ok(Self::Direct(url))
    }
}

#[cfg(any(test, feature = "testing"))]
/// Parse a connection string from an environment variable. The error names the
/// variable but not its value, which may contain a password.
fn parse_env_value(name: &str, raw: &str) -> anyhow::Result<ConnectionString> {
    ConnectionString::new(raw).map_err(|e| anyhow::anyhow!("Invalid {name}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_database_url(url: Option<&str>) -> ConfigToml {
        let mut config = ConfigToml::default();
        config.general.database_url = url.map(|url| ConnectionString::new(url).unwrap());
        config
    }

    #[test]
    fn from_config_uses_database_url() {
        let config = config_with_database_url(Some("postgres://localhost:5432/mydb"));
        let mode = DatabaseMode::from_config(&config).unwrap();
        assert!(matches!(mode, DatabaseMode::Direct(_)));
        assert_eq!(mode.connection_string().database_name(), "mydb");
    }

    #[test]
    fn from_config_errors_without_database_url() {
        let config = config_with_database_url(None);
        assert!(DatabaseMode::from_config(&config).is_err());
    }

    #[test]
    fn ephemeral_explicit_server_wins_over_env() {
        let explicit = ConnectionString::new("postgres://custom:5432/mydb").unwrap();
        let env_val = Some("postgres://envhost:5432/envdb".to_string());
        let result = DatabaseMode::ephemeral_with_env(Some(explicit.clone()), env_val).unwrap();
        assert_eq!(result.connection_string(), &explicit);
        assert!(matches!(result, DatabaseMode::EphemeralTest(_)));
    }

    #[test]
    fn ephemeral_env_var_used_when_no_explicit_server() {
        let env_val = Some("postgres://envhost:5432/envdb".to_string());
        let result = DatabaseMode::ephemeral_with_env(None, env_val).unwrap();
        assert_eq!(
            result.connection_string().as_str(),
            "postgres://envhost:5432/envdb"
        );
        assert!(matches!(result, DatabaseMode::EphemeralTest(_)));
    }

    #[test]
    fn ephemeral_falls_back_to_default_server() {
        let result = DatabaseMode::ephemeral_with_env(None, None).unwrap();
        assert_eq!(result.connection_string().as_str(), DEFAULT_TEST_SERVER);
        assert!(matches!(result, DatabaseMode::EphemeralTest(_)));
    }

    #[test]
    fn ephemeral_invalid_env_var_errors() {
        let env_val = Some("not-a-valid-url".to_string());
        assert!(DatabaseMode::ephemeral_with_env(None, env_val).is_err());
    }

    #[test]
    fn ephemeral_old_style_url_with_pubky_test_param_still_works() {
        let env_val =
            Some("postgres://user:pass@localhost:5432/postgres?pubky-test=true".to_string());
        let result = DatabaseMode::ephemeral_with_env(None, env_val).unwrap();
        assert!(matches!(result, DatabaseMode::EphemeralTest(_)));
    }

    #[test]
    fn persistent_testnet_env_var_wins_over_config() {
        let config = config_with_database_url(Some("postgres://localhost:5432/configdb"));
        let env_val = Some("postgres://envhost:5432/pubky_testnet".to_string());
        let mode = DatabaseMode::persistent_testnet_with_env(&config, env_val).unwrap();
        assert!(matches!(mode, DatabaseMode::Direct(_)));
        assert_eq!(
            mode.connection_string().as_str(),
            "postgres://envhost:5432/pubky_testnet"
        );
    }

    #[test]
    fn persistent_testnet_uses_config_without_env_var() {
        let config = config_with_database_url(Some("postgres://localhost:5432/configdb"));
        let mode = DatabaseMode::persistent_testnet_with_env(&config, None).unwrap();
        assert!(matches!(mode, DatabaseMode::Direct(_)));
        assert_eq!(mode.connection_string().database_name(), "configdb");
    }

    #[test]
    fn persistent_testnet_errors_without_any_database() {
        let config = config_with_database_url(None);
        assert!(DatabaseMode::persistent_testnet_with_env(&config, None).is_err());
    }

    #[test]
    fn persistent_testnet_invalid_env_var_errors() {
        let config = config_with_database_url(Some("postgres://localhost:5432/configdb"));
        let env_val = Some("not-a-valid-url".to_string());
        assert!(DatabaseMode::persistent_testnet_with_env(&config, env_val).is_err());
    }

    #[test]
    fn invalid_env_var_error_does_not_contain_the_password() {
        let env_val = Some("mysql://user:hunter2@localhost:3306/db".to_string());
        let err = DatabaseMode::ephemeral_with_env(None, env_val)
            .unwrap_err()
            .to_string();
        assert!(err.contains(DatabaseMode::EPHEMERAL_SERVER_ENV), "{err}");
        assert!(!err.contains("hunter2"), "{err}");
    }
}
