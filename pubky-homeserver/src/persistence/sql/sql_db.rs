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

impl std::fmt::Debug for SqlDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DbConnection")
    }
}

impl SqlDb {
    /// Connect to the database. Respects the pubky_test flag
    pub async fn connect(con_string: &ConnectionString) -> Result<Self, sqlx::Error> {
        #[cfg(any(test, feature = "testing"))]
        if con_string.is_test_db() {
            return Self::test_postgres_db(Some(con_string.clone())).await;
        }

        Self::connect_inner(con_string).await
    }

    /// Connect to the database. directly without any test db logic.
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
const DEFAULT_TEST_CONNECTION_STRING: &str = "postgres://localhost:5432/postgres";

#[cfg(any(test, feature = "testing"))]
impl SqlDb {
    /// Creates a new test database with the name `pubky_test_{uuid}`.
    /// The provided `admin_con_string` is used to create the test database. The database name defined by the admin connection string
    /// is only used to create the actual test database.
    /// If no connection string is passed, the connection string is read from the TEST_PUBKY_CONNECTION_STRING environment variable.
    /// If the environment variable is not set, the default test connection string is used.
    async fn create_test_database(
        admin_con_string: ConnectionString,
    ) -> Result<ConnectionString, sqlx::Error> {
        use uuid::Uuid;
        let admin_con = Self::connect_inner(&admin_con_string).await?;
        let test_db_name = format!("pubky_test_{}", Uuid::new_v4().as_simple());
        let query = format!("CREATE DATABASE {}", test_db_name);
        sqlx::query(&query).execute(admin_con.pool()).await?;
        let mut test_db_con_string = admin_con_string.clone();
        test_db_con_string.set_database_name(&test_db_name);
        Ok(test_db_con_string)
    }
    /// Creates a new test database with the name `pubky_test_{uuid}`.
    /// The provided `admin_con_string` is used to create the test database. The database name defined by the admin connection string
    /// is only used to create the actual test database.
    /// If no connection string is passed, the connection string is read from the TEST_PUBKY_CONNECTION_STRING environment variable.
    /// If the environment variable is not set, the default test connection string is used.
    pub async fn test_postgres_db(
        admin_con_string: Option<ConnectionString>,
    ) -> Result<Self, sqlx::Error> {
        let admin_con_string = Self::derive_connection_string(admin_con_string);

        let test_db_con_string = Self::create_test_database(admin_con_string.clone()).await?;

        // Connect to the test database.
        let mut con = Self::connect_inner(&test_db_con_string).await?;
        con.db_dropper = Some(std::sync::Arc::new(TestDbDropper::new(
            test_db_con_string.database_name().to_string(),
            admin_con_string.to_string(),
        )));
        Ok(con)
    }

    /// Derives the admin connection string to use for the test database creation.
    /// If the user passed a connection string, use it.
    /// If the user passed a connection string as a env variable, use it.
    /// If no connection string is passed, use the default test connection string.
    pub fn derive_connection_string(
        admin_con_string: Option<ConnectionString>,
    ) -> ConnectionString {
        if let Some(con_string) = admin_con_string {
            // If the user passed a connection string, use it.
            return con_string.clone();
        }
        if let Ok(raw_con_string) = std::env::var("TEST_PUBKY_CONNECTION_STRING") {
            // If the user passed a connection string as a env variable, use it.
            match ConnectionString::new(&raw_con_string) {
                Ok(con_string) => return con_string,
                Err(e) => {
                    tracing::warn!("Invalid database connection string in TEST_PUBKY_CONNECTION_STRING environment variable: {}. Fallback to default test connection string. Error: {e}", raw_con_string);
                }
            }
        }

        // If no connection string is passed, use the default test connection string.
        ConnectionString::new(DEFAULT_TEST_CONNECTION_STRING)
            .expect("Default test connection string is valid")
    }

    /// Create a test database without running migrations
    /// If the DB_CONNECTION_STRING environment variable is not set, a temporary directory is used for the sqlite database
    /// If the DB_CONNECTION_STRING environment variable is set, the test database is created on the existing database
    pub async fn test_without_migrations() -> Self {
        Self::test_postgres_db(None)
            .await
            .expect("Failed to create test database")
    }

    /// Create a test database and run migrations
    /// If the DB_CONNECTION_STRING environment variable is not set, a temporary directory is used for the sqlite database
    /// If the DB_CONNECTION_STRING environment variable is set, the migrations are run on the existing database
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
        let _db = SqlDb::test_postgres_db(None).await.unwrap();
    }
}
