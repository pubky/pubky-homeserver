use super::connection_string::ConnectionString;

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
    /// Require an explicit database URL, returning `Direct` mode.
    ///
    /// Returns an error when the URL is `None` — use this for production
    /// and persistent-testnet paths where a database URL must be configured.
    pub fn require_direct(url: Option<ConnectionString>) -> anyhow::Result<Self> {
        url.map(Self::Direct).ok_or_else(|| {
            anyhow::anyhow!(
                "No database_url configured. Set [general].database_url in config.toml."
            )
        })
    }

    /// Returns the underlying connection string, regardless of mode.
    #[cfg(test)]
    pub fn connection_string(&self) -> &ConnectionString {
        match self {
            Self::Direct(url) => url,
            #[cfg(any(test, feature = "testing"))]
            Self::EphemeralTest(url) => url,
        }
    }
}

#[cfg(any(test, feature = "testing"))]
const DEFAULT_TEST_SERVER: &str = "postgres://localhost:5432/postgres";

#[cfg(any(test, feature = "testing"))]
impl DatabaseMode {
    /// Resolve a `database_url` from config into a `DatabaseMode`.
    ///
    /// Priority:
    /// 1. Explicitly provided URL (e.g. from Docker Postgres or config) → `EphemeralTest`
    /// 2. `TEST_PUBKY_CONNECTION_STRING` environment variable → `EphemeralTest`
    /// 3. [`DEFAULT_TEST_SERVER`] fallback → `EphemeralTest`
    pub fn resolve_test(explicit: Option<ConnectionString>) -> anyhow::Result<Self> {
        Self::resolve_test_inner(explicit, ConnectionString::from_test_env()?)
    }

    /// Pure resolution logic, separated from env access for testability.
    fn resolve_test_inner(
        explicit: Option<ConnectionString>,
        from_env: Option<ConnectionString>,
    ) -> anyhow::Result<Self> {
        let url = explicit.or(from_env).unwrap_or_else(|| {
            ConnectionString::new(DEFAULT_TEST_SERVER)
                .expect("Default test connection string is valid")
        });
        Ok(Self::EphemeralTest(url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_test_explicit_wins_over_env() {
        let explicit = ConnectionString::new("postgres://custom:5432/mydb").unwrap();
        let from_env = ConnectionString::new("postgres://env:5432/envdb").unwrap();
        let result =
            DatabaseMode::resolve_test_inner(Some(explicit.clone()), Some(from_env)).unwrap();
        assert_eq!(result.connection_string(), &explicit);
        assert!(matches!(result, DatabaseMode::EphemeralTest(_)));
    }

    #[test]
    fn resolve_test_env_used_when_no_explicit() {
        let from_env = ConnectionString::new("postgres://env:5432/envdb").unwrap();
        let result = DatabaseMode::resolve_test_inner(None, Some(from_env.clone())).unwrap();
        assert_eq!(result.connection_string(), &from_env);
        assert!(matches!(result, DatabaseMode::EphemeralTest(_)));
    }

    #[test]
    fn resolve_test_falls_back_to_default() {
        let result = DatabaseMode::resolve_test_inner(None, None).unwrap();
        assert_eq!(result.connection_string().as_str(), DEFAULT_TEST_SERVER);
        assert!(matches!(result, DatabaseMode::EphemeralTest(_)));
    }

    #[test]
    fn require_direct_returns_direct_when_url_set() {
        let url = ConnectionString::new("postgres://localhost:5432/mydb").unwrap();
        let mode = DatabaseMode::require_direct(Some(url.clone())).unwrap();
        assert!(
            matches!(mode, DatabaseMode::Direct(_)),
            "require_direct should return Direct"
        );
        assert_eq!(mode.connection_string(), &url);
    }

    #[test]
    fn require_direct_errors_when_no_url() {
        let result = DatabaseMode::require_direct(None);
        assert!(
            result.is_err(),
            "require_direct should error when url is None"
        );
    }
}
