use sqlx::PgPool;
use std::sync::{Arc, Mutex, OnceLock};

/// Global list of databases to drop.
static GLOBAL_DBS_TO_DROP: OnceLock<Arc<Mutex<Vec<DbToDrop>>>> = OnceLock::new();

/// Helper method to get the global vector.
fn get_vec() -> &'static Arc<Mutex<Vec<DbToDrop>>> {
    GLOBAL_DBS_TO_DROP.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

/// Helper struct to drop a database after the test.
#[derive(Debug)]
pub struct DbToDrop {
    pub connection_string: String,
    pub db_name: String,
}

impl DbToDrop {
    /// Drop the database.
    pub async fn drop(&self) -> Result<(), sqlx::Error> {
        let pool = PgPool::connect(&self.connection_string).await?;
        let query = format!("DROP DATABASE \"{}\" WITH (FORCE)", self.db_name);
        sqlx::query(&query).execute(&pool).await?;
        let _ = pool.close().await; // Close connection properly.
        Ok(())
    }
}

/// Register a database to be dropped after the test.
/// May panic if the mutex is poisoned.
/// `connection_string` is the connection string usually to the `postgres` database.
/// It can't be the same database as the one to drop otherwise the drop will fail.
pub fn register_db_to_drop(
    db_name: String,
    connection_string: String,
) -> Result<(), std::sync::PoisonError<std::sync::MutexGuard<'static, Vec<DbToDrop>>>> {
    let mut vec = get_vec().lock()?;
    vec.push(DbToDrop {
        db_name,
        connection_string,
    });
    Ok(())
}

fn get_db_to_drop() -> Option<DbToDrop> {
    let mut vec = get_vec().lock().expect("Should always work");
    vec.pop()
}

/// Drops all registered empheral test databases
/// This must be executed AFTER the homeserver or testnet is dropped.
pub async fn drop_test_databases() {
    // Drop all databases that are registered to be dropped.
    while let Some(db) = get_db_to_drop() {
        match db.drop().await {
            Ok(_) => {}
            Err(e) => {
                // Readd the database to the list to be dropped.
                // let _ = register_db_to_drop(db.db_name.clone(), db.connection_string.clone());
                eprintln!(
                    "pubky_test_utils: Failed to drop test database {}: {}",
                    db.db_name, e
                );
            }
        }
    }
}
