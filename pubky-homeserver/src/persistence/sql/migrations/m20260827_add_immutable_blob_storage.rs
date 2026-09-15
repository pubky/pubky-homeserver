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

        sqlx::query("CREATE INDEX IF NOT EXISTS entries_blob_key_idx ON entries (blob_key)")
            .execute(&mut **tx)
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS unreferenced_blobs (
                blob_key TEXT PRIMARY KEY,
                user_id INTEGER,
                content_length BIGINT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('uploading', 'retained', 'garbage')),
                eligible_at TIMESTAMP NOT NULL
            )
            "#,
        )
        .execute(&mut **tx)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS unreferenced_blobs_eligible_idx ON unreferenced_blobs (eligible_at, blob_key)",
        )
        .execute(&mut **tx)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS unreferenced_blobs_user_idx ON unreferenced_blobs (user_id)")
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

        let index: String = sqlx::query_scalar(
            "SELECT indexdef FROM pg_indexes WHERE tablename = 'entries' AND indexname = 'entries_blob_key_idx'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert!(index.contains("(blob_key)"));

        for column in ["user_id", "content_length", "state", "eligible_at"] {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (\
                    SELECT 1 FROM information_schema.columns \
                    WHERE table_name = 'unreferenced_blobs' AND column_name = $1\
                )",
            )
            .bind(column)
            .fetch_one(db.pool())
            .await
            .unwrap();
            assert!(exists, "unreferenced_blobs.{column} should exist");
        }
        let garbage_user_nullable: String = sqlx::query_scalar(
            r#"
            SELECT is_nullable
            FROM information_schema.columns
            WHERE table_name = 'unreferenced_blobs' AND column_name = 'user_id'
            "#,
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(garbage_user_nullable, "YES");
    }
}
