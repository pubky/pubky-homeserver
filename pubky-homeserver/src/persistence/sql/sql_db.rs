use sqlx::postgres::PgPool;
#[cfg(test)]
use sqlx::postgres::PgPoolOptions;

use crate::persistence::sql::connection_string::ConnectionString;
use crate::persistence::sql::database_mode::DatabaseMode;

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
    /// Connect to the database using the given [`DatabaseMode`].
    ///
    /// - [`DatabaseMode::Direct`]: connects to the database identified by the URL.
    /// - [`DatabaseMode::EphemeralTest`]: creates a fresh `pubky_test_{uuid}` database
    ///   on the server, connects to it, and drops it when this `SqlDb` is dropped.
    pub async fn connect(mode: DatabaseMode) -> Result<Self, sqlx::Error> {
        match mode {
            DatabaseMode::Direct(url) => Self::connect_inner(&url).await,
            #[cfg(any(test, feature = "testing"))]
            DatabaseMode::EphemeralTest(admin_url) => {
                Self::create_ephemeral_test_db(admin_url).await
            }
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
impl SqlDb {
    /// Creates an ephemeral `pubky_test_{uuid}` database and connects to it.
    ///
    /// `admin_con_string` is used for the initial admin connection that creates
    /// the database. The returned `SqlDb` will drop its database on scope exit.
    async fn create_ephemeral_test_db(
        admin_con_string: ConnectionString,
    ) -> Result<Self, sqlx::Error> {
        use uuid::Uuid;

        let admin_con = Self::connect_inner(&admin_con_string).await?;
        let test_db_name = format!("pubky_test_{}", Uuid::new_v4().as_simple());
        let query = format!("CREATE DATABASE \"{}\"", test_db_name);
        sqlx::query(&query).execute(admin_con.pool()).await?;

        let mut test_db_url = admin_con_string.clone();
        test_db_url.set_database_name(&test_db_name);

        let mut con = Self::connect_inner(&test_db_url).await?;
        con.db_dropper = Some(std::sync::Arc::new(TestDbDropper::new(
            test_db_name,
            admin_con_string.to_string(),
        )));
        Ok(con)
    }

    /// Create a test database without running migrations.
    #[cfg(test)]
    pub async fn test_without_migrations() -> Self {
        let mode = DatabaseMode::resolve_test(None).expect("Failed to resolve test database mode");
        Self::connect(mode)
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
        use uuid::Uuid;

        let mode = DatabaseMode::resolve_test(None).expect("Failed to resolve test database mode");
        let admin_url = match mode {
            DatabaseMode::EphemeralTest(url) => url,
            DatabaseMode::Direct(url) => url,
        };
        let admin_con = Self::connect_inner(&admin_url)
            .await
            .expect("Failed to connect to admin database");
        let test_db_name = format!("pubky_test_{}", Uuid::new_v4().as_simple());
        let query = format!("CREATE DATABASE \"{}\"", test_db_name);
        sqlx::query(&query)
            .execute(admin_con.pool())
            .await
            .expect("Failed to create test database");

        let mut test_db_url = admin_url.clone();
        test_db_url.set_database_name(&test_db_name);

        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(acquire_timeout)
            .connect(test_db_url.as_str())
            .await
            .expect("Failed to connect to test database");
        let db = Self {
            pool,
            db_dropper: Some(std::sync::Arc::new(TestDbDropper::new(
                test_db_name,
                admin_url.to_string(),
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
    async fn pg_db_available() {
        let mode = DatabaseMode::resolve_test(None).unwrap();
        let _db = SqlDb::connect(mode).await.unwrap();
    }
}
