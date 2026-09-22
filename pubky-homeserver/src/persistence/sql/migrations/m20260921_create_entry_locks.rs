use async_trait::async_trait;
use sea_query::{ColumnDef, Index, PostgresQueryBuilder, Table};
use sqlx::Transaction;

use crate::persistence::sql::{
    entities::entry_lock::{EntryLockIden, ENTRY_LOCK_TABLE},
    migration::MigrationTrait,
};

/// One exclusive WebDAV write lock per storage path.
pub struct M20260921CreateEntryLocksMigration;

#[async_trait]
impl MigrationTrait for M20260921CreateEntryLocksMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        let statement = Table::create()
            .table(ENTRY_LOCK_TABLE)
            .if_not_exists()
            .col(
                ColumnDef::new(EntryLockIden::Path)
                    .string()
                    .not_null()
                    .primary_key(),
            )
            .col(
                ColumnDef::new(EntryLockIden::Token)
                    .string_len(36)
                    .not_null(),
            )
            .col(
                ColumnDef::new(EntryLockIden::ExpiresAt)
                    .big_integer()
                    .not_null(),
            )
            .to_owned();
        let query = statement.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Expired rows are swept on every LOCK request.
        let index = Index::create()
            .name("idx_entry_locks_expires_at")
            .table(ENTRY_LOCK_TABLE)
            .col(EntryLockIden::ExpiresAt)
            .to_owned();
        let query = index.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;
        Ok(())
    }

    fn name(&self) -> &str {
        "m20260921_create_entry_locks"
    }
}
