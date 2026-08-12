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
    /// identified by the URL, then connect to it. The database is dropped
    /// when the [`SqlDb`](super::SqlDb) is dropped.
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
    ///
    /// Tests always get ephemeral databases — the decision is encoded here,
    /// not in a URL query parameter.
    pub fn resolve_test(explicit: Option<ConnectionString>) -> Self {
        let env_val = std::env::var("TEST_PUBKY_CONNECTION_STRING").ok();
        Self::resolve_test_inner(explicit, env_val)
    }

    /// Pure resolution logic, separated from env access for testability.
    fn resolve_test_inner(explicit: Option<ConnectionString>, env_val: Option<String>) -> Self {
        if let Some(url) = explicit {
            return Self::EphemeralTest(url);
        }

        if let Some(raw) = env_val {
            match ConnectionString::new(&raw) {
                Ok(url) => return Self::EphemeralTest(url),
                Err(e) => {
                    tracing::warn!(
                        "Invalid TEST_PUBKY_CONNECTION_STRING: {raw}. Falling back to default. Error: {e}"
                    );
                }
            }
        }

        Self::EphemeralTest(
            ConnectionString::new(DEFAULT_TEST_SERVER)
                .expect("Default test connection string is valid"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_explicit_wins_over_env() {
        let explicit = ConnectionString::new("postgres://custom:5432/mydb").unwrap();
        let env_val = Some("postgres://envhost:5432/envdb".to_string());
        let result = DatabaseMode::resolve_test_inner(Some(explicit.clone()), env_val);
        assert_eq!(result.connection_string(), &explicit);
        assert!(matches!(result, DatabaseMode::EphemeralTest(_)));
    }

    #[test]
    fn resolve_env_var_used_when_no_explicit() {
        let env_val = Some("postgres://envhost:5432/envdb".to_string());
        let result = DatabaseMode::resolve_test_inner(None, env_val);
        assert_eq!(
            result.connection_string().as_str(),
            "postgres://envhost:5432/envdb"
        );
        assert!(matches!(result, DatabaseMode::EphemeralTest(_)));
    }

    #[test]
    fn resolve_falls_back_to_default() {
        let result = DatabaseMode::resolve_test_inner(None, None);
        assert_eq!(result.connection_string().as_str(), DEFAULT_TEST_SERVER);
        assert!(matches!(result, DatabaseMode::EphemeralTest(_)));
    }

    #[test]
    fn resolve_invalid_env_var_falls_back_to_default() {
        let env_val = Some("not-a-valid-url".to_string());
        let result = DatabaseMode::resolve_test_inner(None, env_val);
        assert_eq!(result.connection_string().as_str(), DEFAULT_TEST_SERVER);
    }

    #[test]
    fn resolve_strips_pubky_test_param_gracefully() {
        // Backwards compat: old-style URLs with ?pubky-test=true still work
        let env_val =
            Some("postgres://user:pass@localhost:5432/postgres?pubky-test=true".to_string());
        let result = DatabaseMode::resolve_test_inner(None, env_val);
        assert!(matches!(result, DatabaseMode::EphemeralTest(_)));
    }
}
