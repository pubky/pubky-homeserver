use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

/// A connection string for a  postgres database.
/// See <https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING-URIS>
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionString(url::Url);

impl ConnectionString {
    /// Create a new connection string from a string.
    /// This function validates that the connection string is a postgres connection string.
    pub fn new(con_string: &str) -> anyhow::Result<Self> {
        Self::validated(url::Url::parse(con_string)?)
    }

    /// Shared validation: ensures the URL uses a postgres scheme.
    fn validated(url: url::Url) -> anyhow::Result<Self> {
        let cs = Self(url);
        if !cs.is_postgres() {
            anyhow::bail!("Only postgres database urls are supported");
        }
        Ok(cs)
    }

    /// Get the connection string as a str.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn is_postgres(&self) -> bool {
        self.0.scheme() == "postgres" || self.0.scheme() == "postgresql"
    }

    /// Get the database name
    /// For postgres, this is the database name directly
    pub fn database_name(&self) -> &str {
        self.0.path().trim_start_matches("/")
    }

    /// Set the database name, clearing any `dbname` query parameter that would
    /// otherwise override the path. See
    /// <https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING-URIS>
    pub fn set_database_name(&mut self, db_name: &str) {
        self.0.set_path(db_name);
        self.remove_query_param("dbname");
    }

    /// Remove all occurrences of a query parameter by key.
    fn remove_query_param(&mut self, key: &str) {
        if self.0.query().is_none() {
            return;
        }
        let pairs: Vec<_> = self
            .0
            .query_pairs()
            .filter(|(k, _)| k != key)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if pairs.is_empty() {
            self.0.set_query(None);
        } else {
            self.0.query_pairs_mut().clear().extend_pairs(&pairs);
        }
    }
}

impl TryFrom<url::Url> for ConnectionString {
    type Error = anyhow::Error;

    fn try_from(url: url::Url) -> Result<Self, Self::Error> {
        Self::validated(url)
    }
}

impl FromStr for ConnectionString {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Display for ConnectionString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for ConnectionString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ConnectionString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_postgres_url() {
        let _: ConnectionString = "postgres://localhost:5432/pubky_homeserver"
            .parse()
            .unwrap();
    }

    #[test]
    fn test_non_postgres_url_rejected() {
        let result: Result<ConnectionString, _> = "sqlite:///path/to/sqlite.db".parse();
        assert!(result.is_err(), "sqlite URLs should be rejected");
    }

    #[test]
    fn set_database_name_changes_path() {
        let mut cs = ConnectionString::new("postgres://user:pass@localhost:5432/original").unwrap();
        cs.set_database_name("new_db");
        assert_eq!(cs.database_name(), "new_db");
    }

    #[test]
    fn set_database_name_strips_dbname_query_param() {
        let mut cs =
            ConnectionString::new("postgres://user:pass@localhost:5432/postgres?dbname=postgres")
                .unwrap();
        cs.set_database_name("pubky_test_abc123");
        assert_eq!(cs.database_name(), "pubky_test_abc123");
        assert!(
            !cs.as_str().contains("dbname="),
            "dbname query param should be removed, got: {}",
            cs.as_str()
        );
    }

    #[test]
    fn set_database_name_preserves_other_query_params() {
        let mut cs = ConnectionString::new(
            "postgres://user:pass@localhost:5432/postgres?dbname=postgres&sslmode=require",
        )
        .unwrap();
        cs.set_database_name("pubky_test_abc123");
        assert_eq!(cs.database_name(), "pubky_test_abc123");
        assert!(
            !cs.as_str().contains("dbname="),
            "dbname should be removed, got: {}",
            cs.as_str()
        );
        assert!(
            cs.as_str().contains("sslmode=require"),
            "other params should be preserved, got: {}",
            cs.as_str()
        );
    }
}
