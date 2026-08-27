use async_trait::async_trait;
use sqlx::Transaction;

use crate::persistence::sql::migration::MigrationTrait;

/// Adds immutable blob pointers and durable upload/garbage tracking.
pub struct M20260827AddImmutableBlobStorageMigration;

#[async_trait]
impl MigrationTrait for M20260827AddImmutableBlobStorageMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        sqlx::query("ALTER TABLE entries ADD COLUMN IF NOT EXISTS blob_key TEXT")
            .execute(&mut **tx)
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS blob_uploads (
                blob_key TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                content_length BIGINT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS blob_uploads_updated_at_idx ON blob_uploads (updated_at)",
        )
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS blob_garbage (
                blob_key TEXT PRIMARY KEY,
                user_id INTEGER,
                content_length BIGINT NOT NULL,
                available_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                claimed_at TIMESTAMP,
                claim_token TEXT
            )
            "#,
        )
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS blob_garbage_available_idx ON blob_garbage (available_at, blob_key)",
        )
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS blob_read_leases (
                blob_key TEXT NOT NULL,
                lease_id TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                PRIMARY KEY (blob_key, lease_id)
            )
            "#,
        )
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS blob_read_leases_expiry_idx ON blob_read_leases (expires_at, blob_key)",
        )
        .execute(&mut **tx)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS blob_uploads_user_idx ON blob_uploads (user_id)")
            .execute(&mut **tx)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS blob_garbage_user_idx ON blob_garbage (user_id)")
            .execute(&mut **tx)
            .await?;

        Ok(())
    }

    fn name(&self) -> &str {
        "m20260827_add_immutable_blob_storage"
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

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_adds_blob_pointer_and_tracking_tables() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250815CreateEntryMigration),
            ])
            .await
            .unwrap();
        let user_id: i32 = sqlx::query_scalar(
            "INSERT INTO users (public_key) VALUES ('legacy-user') RETURNING id",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        sqlx::query(
            r#"
            INSERT INTO entries
                ("user", path, content_hash, content_length, content_type)
            VALUES ($1, '/pub/legacy.txt', $2, 6, 'text/plain')
            "#,
        )
        .bind(user_id)
        .bind(vec![0u8; 32])
        .execute(db.pool())
        .await
        .unwrap();

        migrator
            .run_migrations(vec![Box::new(M20260827AddImmutableBlobStorageMigration)])
            .await
            .unwrap();

        let blob_key_nullable: String = sqlx::query_scalar(
            r#"
            SELECT is_nullable
            FROM information_schema.columns
            WHERE table_name = 'entries' AND column_name = 'blob_key'
            "#,
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(blob_key_nullable, "YES");

        let (blob_key, path): (Option<String>, String) =
            sqlx::query_as("SELECT blob_key, path FROM entries WHERE \"user\" = $1")
                .bind(user_id)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(blob_key, None);
        assert_eq!(path, "/pub/legacy.txt");

        for table in ["blob_uploads", "blob_garbage", "blob_read_leases"] {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)",
            )
            .bind(table)
            .fetch_one(db.pool())
            .await
            .unwrap();
            assert!(exists, "{table} should exist");
        }
        for (table, column) in [
            ("blob_uploads", "user_id"),
            ("blob_uploads", "content_length"),
            ("blob_garbage", "user_id"),
            ("blob_garbage", "content_length"),
        ] {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (\
                    SELECT 1 FROM information_schema.columns \
                    WHERE table_name = $1 AND column_name = $2\
                )",
            )
            .bind(table)
            .bind(column)
            .fetch_one(db.pool())
            .await
            .unwrap();
            assert!(exists, "{table}.{column} should exist");
        }
        let garbage_user_nullable: String = sqlx::query_scalar(
            r#"
            SELECT is_nullable
            FROM information_schema.columns
            WHERE table_name = 'blob_garbage' AND column_name = 'user_id'
            "#,
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(garbage_user_nullable, "YES");

        sqlx::query(
            "INSERT INTO blob_read_leases (blob_key, lease_id, expires_at) \
             VALUES ('blob-a', 'reader-a', CURRENT_TIMESTAMP), \
                    ('blob-a', 'reader-b', CURRENT_TIMESTAMP)",
        )
        .execute(db.pool())
        .await
        .unwrap();
        let leases: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM blob_read_leases WHERE blob_key = 'blob-a'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(leases, 2);
    }
}
