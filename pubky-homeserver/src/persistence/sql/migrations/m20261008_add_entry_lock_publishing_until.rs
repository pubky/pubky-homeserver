use async_trait::async_trait;
use sqlx::Transaction;

use crate::persistence::sql::migration::MigrationTrait;

/// Adds `publishing_until` to `entry_locks`: the Unix seconds until which a
/// write or delete under the lock may still reach the storage backend. Zero,
/// the default, means nothing is reserved.
pub struct M20261008AddEntryLockPublishingUntilMigration;

#[async_trait]
impl MigrationTrait for M20261008AddEntryLockPublishingUntilMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        sqlx::query(
            "ALTER TABLE entry_locks \
             ADD COLUMN IF NOT EXISTS publishing_until BIGINT NOT NULL DEFAULT 0",
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    fn name(&self) -> &str {
        "m20261008_add_entry_lock_publishing_until"
    }
}
