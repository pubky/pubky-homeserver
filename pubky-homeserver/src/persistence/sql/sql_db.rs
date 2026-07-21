use sqlx::postgres::PgPool;
#[cfg(test)]
use sqlx::postgres::PgPoolOptions;

use crate::persistence::sql::connection_string::ConnectionString;

/// The SqlDb is a wrapper around the postgres connection pool.
/// It is used to connect to the database and run queries.
///
/// It is cheaply cloneable. Internally,
/// the connection pool is simply a reference-counted handle to the inner pool state.
/// When the last remaining handle to the pool is dropped,
/// the connections owned by the pool are immediately closed (also by dropping).
/// See https://docs.rs/sqlx/latest/sqlx/struct.Pool.html
#[derive(Clone)]
pub struct SqlDb {
    /// Connection pool to the database
    pool: PgPool,
    /// Test helper for postgres to drop the test database after the test
    #[cfg(any(test, feature = "testing"))]
    db_dropper: Option<std::sync::Arc<TestDbDropper>>,
}

/// Errors from [`SqlDb::connect`].
#[derive(Debug, thiserror::Error)]
pub enum SqlDbConnectError {
    /// SQL connection or database creation failed.
    #[error("{0}")]
    Sql(sqlx::Error),
    /// No database URL configured (production builds only).
    #[error("No database_url configured. Set [general].database_url in config.toml.")]
    NoDatabaseUrl,
}

impl std::fmt::Debug for SqlDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DbConnection")
    }
}

impl SqlDb {
    /// Connect to the database.
    ///
    /// In test builds (`#[cfg(test)]` or `feature = "testing"`):
    /// - Resolves `None` via env var (`TEST_PUBKY_CONNECTION_STRING`) or built-in default
    /// - Creates an ephemeral `pubky_test_{uuid}` database when the URL has `?pubky-test=true`
    /// - Connects directly for non-test URLs (e.g. a real Postgres instance)
    ///
    /// In production builds, `None` is an error.
    pub async fn connect(con_string: Option<ConnectionString>) -> Result<Self, SqlDbConnectError> {
        #[cfg(any(test, feature = "testing"))]
        {
            let resolved = Self::derive_connection_string(con_string);
            return if resolved.is_test_db() {
                Self::create_ephemeral_test_db(resolved)
                    .await
                    .map_err(SqlDbConnectError::Sql)
            } else {
                Self::connect_inner(&resolved)
                    .await
                    .map_err(SqlDbConnectError::Sql)
            };
        }

        #[cfg(not(any(test, feature = "testing")))]
        {
            let resolved = con_string.ok_or(SqlDbConnectError::NoDatabaseUrl)?;
            Self::connect_inner(&resolved)
                .await
                .map_err(SqlDbConnectError::Sql)
        }
    }

    /// Connect to the database directly without any test db logic.
    async fn connect_inner(con_string: &ConnectionString) -> Result<Self, sqlx::Error> {
        let pool: PgPool = PgPool::connect(con_string.as_str()).await?;
        Ok(Self {
            pool,
            #[cfg(any(test, feature = "testing"))]
            db_dropper: None,
        })
    }

    /// Get the connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Helper struct to drop the postgres test database after the db connection is dropped.
#[cfg(any(test, feature = "testing"))]
struct TestDbDropper {
    db_name: String,
    connection_string: String,
}

#[cfg(any(test, feature = "testing"))]
impl TestDbDropper {
    pub fn new(db_name: String, connection_string: String) -> Self {
        Self {
            db_name,
            connection_string,
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Drop for TestDbDropper {
    fn drop(&mut self) {
        // Drop the database after the test.
        // This works in combination with the pubky_test macro.
        let _ = pubky_test_utils::register_db_to_drop(
            self.db_name.clone(),
            self.connection_string.clone(),
        );
    }
}

#[cfg(any(test, feature = "testing"))]
pub(crate) const DEFAULT_TEST_CONNECTION_STRING: &str =
    "postgres://localhost:5432/postgres?pubky-test=true";

#[cfg(any(test, feature = "testing"))]
impl SqlDb {
    /// Creates a new `pubky_test_{uuid}` database on the server identified by
    /// `admin_con_string`. The database name in that URL is used only for the
    /// initial admin connection; the actual test database gets a unique name.
    async fn create_test_database(
        admin_con_string: ConnectionString,
    ) -> Result<ConnectionString, sqlx::Error> {
        use uuid::Uuid;
        let admin_con = Self::connect_inner(&admin_con_string).await?;
        let test_db_name = format!("pubky_test_{}", Uuid::new_v4().as_simple());
        let query = format!("CREATE DATABASE \"{}\"", test_db_name);
        sqlx::query(&query).execute(admin_con.pool()).await?;
        let mut test_db_con_string = admin_con_string.clone();
        test_db_con_string.set_database_name(&test_db_name);
        Ok(test_db_con_string)
    }
    /// Creates an ephemeral `pubky_test_{uuid}` database and connects to it.
    /// The returned `SqlDb` will drop its database when it goes out of scope.
    async fn create_ephemeral_test_db(
        admin_con_string: ConnectionString,
    ) -> Result<Self, sqlx::Error> {
        let test_db_con_string = Self::create_test_database(admin_con_string.clone()).await?;

        let mut con = Self::connect_inner(&test_db_con_string).await?;
        con.db_dropper = Some(std::sync::Arc::new(TestDbDropper::new(
            test_db_con_string.database_name().to_string(),
            admin_con_string.to_string(),
        )));
        Ok(con)
    }

    /// Derives the connection string for test database creation.
    ///
    /// Priority:
    /// 1. Explicitly provided URL (e.g. Docker Postgres) — used as-is
    /// 2. `TEST_PUBKY_CONNECTION_STRING` environment variable
    /// 3. [`DEFAULT_TEST_CONNECTION_STRING`] fallback
    pub(crate) fn derive_connection_string(explicit: Option<ConnectionString>) -> ConnectionString {
        let env_val = std::env::var("TEST_PUBKY_CONNECTION_STRING").ok();
        Self::resolve_connection_string(explicit, env_val)
    }

    /// Pure resolution logic, separated from env access for testability.
    fn resolve_connection_string(
        explicit: Option<ConnectionString>,
        env_val: Option<String>,
    ) -> ConnectionString {
        if let Some(url) = explicit {
            return url;
        }

        if let Some(raw) = env_val {
            match ConnectionString::new(&raw) {
                Ok(con_string) => return con_string,
                Err(e) => {
                    tracing::warn!("Invalid TEST_PUBKY_CONNECTION_STRING: {raw}. Falling back to default. Error: {e}");
                }
            }
        }

        ConnectionString::new(DEFAULT_TEST_CONNECTION_STRING)
            .expect("Default test connection string is valid")
    }

    /// Create a test database without running migrations.
    #[cfg(test)]
    pub async fn test_without_migrations() -> Self {
        let resolved = Self::derive_connection_string(None);
        Self::create_ephemeral_test_db(resolved)
            .await
            .expect("Failed to create test database")
    }

    /// Create a test database and run migrations.
    /// Convenience wrapper around [`Self::test_without_migrations`] + [`Migrator::run`].
    #[cfg(test)]
    pub async fn test() -> Self {
        use crate::persistence::sql::migrator::Migrator;
        let db = Self::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator.run().await.expect("Failed to run migrations");
        db
    }

    /// Create a migrated test database with an explicitly bounded connection pool.
    /// Useful for regression tests that need to prove nested acquisitions cannot deadlock.
    #[cfg(test)]
    pub async fn test_with_pool_options(
        max_connections: u32,
        acquire_timeout: std::time::Duration,
    ) -> Self {
        let admin_con_string = Self::derive_connection_string(None);
        let test_db_con_string = Self::create_test_database(admin_con_string.clone())
            .await
            .expect("Failed to create test database");
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(acquire_timeout)
            .connect(test_db_con_string.as_str())
            .await
            .expect("Failed to connect to test database");
        let db = Self {
            pool,
            db_dropper: Some(std::sync::Arc::new(TestDbDropper::new(
                test_db_con_string.database_name().to_string(),
                admin_con_string.to_string(),
            ))),
        };
        let migrator = crate::persistence::sql::migrator::Migrator::new(&db);
        migrator.run().await.expect("Failed to run migrations");
        db
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_pg_db_available() {
        let resolved = SqlDb::derive_connection_string(None);
        let _db = SqlDb::create_ephemeral_test_db(resolved).await.unwrap();
    }

    #[test]
    fn resolve_explicit_wins_over_env() {
        let explicit =
            ConnectionString::new("postgres://custom:5432/mydb?pubky-test=true").unwrap();
        let env_val = Some("postgres://envhost:5432/envdb?pubky-test=true".to_string());
        let result = SqlDb::resolve_connection_string(Some(explicit.clone()), env_val);
        assert_eq!(result, explicit);
    }

    #[test]
    fn resolve_env_var_used_when_no_explicit() {
        let env_val = Some("postgres://envhost:5432/envdb?pubky-test=true".to_string());
        let result = SqlDb::resolve_connection_string(None, env_val);
        assert_eq!(
            result.as_str(),
            "postgres://envhost:5432/envdb?pubky-test=true"
        );
    }

    #[test]
    fn resolve_falls_back_to_default() {
        let result = SqlDb::resolve_connection_string(None, None);
        assert_eq!(result.as_str(), DEFAULT_TEST_CONNECTION_STRING);
    }

    #[test]
    fn resolve_invalid_env_var_falls_back_to_default() {
        let env_val = Some("not-a-valid-url".to_string());
        let result = SqlDb::resolve_connection_string(None, env_val);
        assert_eq!(result.as_str(), DEFAULT_TEST_CONNECTION_STRING);
    }
}
