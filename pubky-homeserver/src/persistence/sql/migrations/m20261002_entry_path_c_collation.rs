use async_trait::async_trait;
use sqlx::Transaction;

use crate::persistence::sql::migration::MigrationTrait;

/// Compares entry paths byte-wise instead of by the database locale.
///
/// A path prefix is a contiguous range of the `(user, path)` index only in byte
/// order, so in a database created with a linguistic locale every prefix lookup
/// had to read all entries of the user. Postgres rebuilds the index as part of
/// the statement; the table itself is not rewritten.
pub struct M20261002EntryPathCCollationMigration;

#[async_trait]
impl MigrationTrait for M20261002EntryPathCCollationMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        sqlx::query(r#"ALTER TABLE entries ALTER COLUMN path TYPE varchar COLLATE "C""#)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    fn name(&self) -> &str {
        "m20261002_entry_path_c_collation"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::{
        migrations::{M20250806CreateUserMigration, M20250815CreateEntryMigration},
        migrator::Migrator,
        SqlDb,
    };

    async fn path_index_collation(db: &SqlDb) -> String {
        sqlx::query_scalar(
            "SELECT pg_collation.collname::text \
             FROM pg_index \
             JOIN pg_collation ON pg_collation.oid = pg_index.indcollation[1] \
             WHERE pg_index.indexrelid = 'idx_entry_user_path'::regclass",
        )
        .fetch_one(db.pool())
        .await
        .unwrap()
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_entry_path_index_is_rebuilt_in_byte_order() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250815CreateEntryMigration),
            ])
            .await
            .expect("Should run successfully");
        sqlx::query("INSERT INTO users (public_key) VALUES ('user')")
            .execute(db.pool())
            .await
            .unwrap();
        // A linguistic locale such as en_US sorts these the other way around.
        sqlx::query(
            "INSERT INTO entries (\"user\", path, content_hash, content_length, content_type) \
             SELECT 1, path, '\\x00', 0, 'text/plain' FROM unnest(ARRAY['/aa', '/a/b', '/B']) AS path",
        )
        .execute(db.pool())
        .await
        .unwrap();
        assert_eq!(path_index_collation(&db).await, "default");

        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250815CreateEntryMigration),
                Box::new(M20261002EntryPathCCollationMigration),
            ])
            .await
            .expect("Should run successfully");

        assert_eq!(path_index_collation(&db).await, "C");
        let paths: Vec<String> = sqlx::query_scalar("SELECT path FROM entries ORDER BY path")
            .fetch_all(db.pool())
            .await
            .unwrap();
        assert_eq!(paths, vec!["/B", "/a/b", "/aa"]);
    }
}
