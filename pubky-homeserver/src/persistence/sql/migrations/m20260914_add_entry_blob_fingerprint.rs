use async_trait::async_trait;
use sqlx::Transaction;

use crate::persistence::sql::migration::MigrationTrait;

/// Adds the fingerprint of the stored blob, as the storage backend reports it,
/// to each entry. It lets a conditional write verify with a `stat` that the
/// row still describes the blob, instead of reading and hashing it.
///
/// Existing rows start as NULL: the first conditional write or delete that
/// probes such a row, accepted or rejected, verifies it by hashing the blob
/// and records the fingerprint.
pub struct M20260914AddEntryBlobFingerprintMigration;

#[async_trait]
impl MigrationTrait for M20260914AddEntryBlobFingerprintMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        sqlx::query("ALTER TABLE entries ADD COLUMN IF NOT EXISTS blob_fingerprint TEXT")
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    fn name(&self) -> &str {
        "m20260914_add_entry_blob_fingerprint"
    }
}

#[cfg(test)]
mod tests {
    use crate::persistence::sql::sql_db::SqlDb;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn adds_a_nullable_fingerprint_column() {
        let db = SqlDb::test().await;
        let (is_nullable,): (String,) = sqlx::query_as(
            "SELECT is_nullable FROM information_schema.columns \
             WHERE table_name = 'entries' AND column_name = 'blob_fingerprint'",
        )
        .fetch_one(db.pool())
        .await
        .expect("blob_fingerprint column should exist");
        assert_eq!(is_nullable, "YES");
    }
}
