use async_trait::async_trait;
use sqlx::Transaction;

use crate::persistence::sql::migration::MigrationTrait;

/// Adds per-user quota columns to both the `users` and `signup_codes` tables.
///
/// All four columns start as NULL which means `Default` — the system-wide
/// default from config is resolved at enforcement time.
pub struct M20260327AddQuotaColumnsMigration;

/// Add the four limit columns to the given table.
async fn add_quota_columns(
    tx: &mut Transaction<'static, sqlx::Postgres>,
    table: &str,
) -> anyhow::Result<()> {
    for (col, typ) in [
        ("quota_storage_mb", "INTEGER"),
        ("quota_rate_read", "VARCHAR(32)"),
        ("quota_rate_write", "VARCHAR(32)"),
        ("quota_rate_read_burst", "INTEGER"),
        ("quota_rate_write_burst", "INTEGER"),
    ] {
        sqlx::query(&format!(
            "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {typ}"
        ))
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

#[async_trait]
impl MigrationTrait for M20260327AddQuotaColumnsMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        add_quota_columns(tx, "users").await?;
        add_quota_columns(tx, "signup_codes").await?;
        Ok(())
    }

    fn name(&self) -> &str {
        "m20260327_add_quota_columns"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::entities::signup_code::{
        SignupCode, SignupCodeIden, SIGNUP_CODE_TABLE,
    };
    use crate::persistence::sql::entities::user::{UserIden, USER_TABLE};
    use crate::persistence::sql::migrations::{
        M20250806CreateUserMigration, M20250812CreateSignupCodeMigration,
        M20250813CreateSessionMigration, M20250814CreateEventMigration,
        M20250815CreateEntryMigration, M20251014EventsTableIndexAndContentHashMigration,
    };
    use crate::persistence::sql::migrator::Migrator;
    use crate::persistence::sql::sql_db::SqlDb;
    use pubky_common::crypto::Keypair;
    use sea_query::{PostgresQueryBuilder, Query, SimpleExpr};
    use sea_query_sqlx::SqlxBinder;

    type QuotaColumns = (
        Option<i32>,
        Option<String>,
        Option<String>,
        Option<i32>,
        Option<i32>,
    );

    /// Helper: run all prior migrations plus the quota columns migration.
    async fn run_all_migrations(db: &SqlDb) {
        let migrator = Migrator::new(db);
        let migrations: Vec<Box<dyn crate::persistence::sql::migration::MigrationTrait>> = vec![
            Box::new(M20250806CreateUserMigration),
            Box::new(M20250812CreateSignupCodeMigration),
            Box::new(M20250813CreateSessionMigration),
            Box::new(M20250814CreateEventMigration),
            Box::new(M20250815CreateEntryMigration),
            Box::new(M20251014EventsTableIndexAndContentHashMigration),
            Box::new(M20260327AddQuotaColumnsMigration),
        ];
        migrator
            .run_migrations(migrations)
            .await
            .expect("migrations should succeed");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_adds_columns_to_users() {
        let db = SqlDb::test_without_migrations().await;
        run_all_migrations(&db).await;

        let pubkey = Keypair::random().public_key();
        let statement = Query::insert()
            .into_table(USER_TABLE)
            .columns([UserIden::PublicKey])
            .values(vec![SimpleExpr::Value(pubkey.z32().into())])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        let row: QuotaColumns = sqlx::query_as(
            "SELECT quota_storage_mb, quota_rate_read, quota_rate_write, quota_rate_read_burst, quota_rate_write_burst FROM users WHERE public_key = $1",
        )
        .bind(pubkey.z32())
        .fetch_one(db.pool())
        .await
        .unwrap();
        // All columns should be NULL (= Default)
        assert_eq!(row, (None, None, None, None, None));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_adds_columns_to_signup_codes() {
        let db = SqlDb::test_without_migrations().await;
        run_all_migrations(&db).await;

        let code_id = SignupCode::random();
        let statement = Query::insert()
            .into_table(SIGNUP_CODE_TABLE)
            .columns([SignupCodeIden::Id])
            .values(vec![SimpleExpr::Value(code_id.to_string().into())])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        let row: QuotaColumns = sqlx::query_as(
            "SELECT quota_storage_mb, quota_rate_read, quota_rate_write, quota_rate_read_burst, quota_rate_write_burst FROM signup_codes WHERE id = $1",
        )
        .bind(code_id.to_string())
        .fetch_one(db.pool())
        .await
        .unwrap();
        // All columns should be NULL (= Default)
        assert_eq!(row, (None, None, None, None, None));
    }

    /// Existing rows should have NULL for all quota columns after migration
    /// (no backfill needed — NULL = Default = resolve from config at runtime).
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_existing_rows_stay_null() {
        let db = SqlDb::test_without_migrations().await;

        // Run only the pre-quota migrations first
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250812CreateSignupCodeMigration),
                Box::new(M20250813CreateSessionMigration),
                Box::new(M20250814CreateEventMigration),
                Box::new(M20250815CreateEntryMigration),
                Box::new(M20251014EventsTableIndexAndContentHashMigration),
            ])
            .await
            .unwrap();

        // Create a user and signup code before the quota migration
        let pubkey = Keypair::random().public_key();
        let statement = Query::insert()
            .into_table(USER_TABLE)
            .columns([UserIden::PublicKey])
            .values(vec![SimpleExpr::Value(pubkey.z32().into())])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        let code_id = SignupCode::random();
        sqlx::query("INSERT INTO signup_codes (id) VALUES ($1)")
            .bind(code_id.to_string())
            .execute(db.pool())
            .await
            .unwrap();

        // Now run the quota columns migration
        migrator
            .run_migrations(vec![Box::new(M20260327AddQuotaColumnsMigration)])
            .await
            .unwrap();

        // Existing user should have all NULLs (= Default)
        let row: QuotaColumns = sqlx::query_as(
            "SELECT quota_storage_mb, quota_rate_read, quota_rate_write, quota_rate_read_burst, quota_rate_write_burst FROM users WHERE public_key = $1",
        )
        .bind(pubkey.z32())
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(row, (None, None, None, None, None));

        // Existing signup code should have all NULLs (= Default)
        let row: QuotaColumns = sqlx::query_as(
            "SELECT quota_storage_mb, quota_rate_read, quota_rate_write, quota_rate_read_burst, quota_rate_write_burst FROM signup_codes WHERE id = $1",
        )
        .bind(code_id.to_string())
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(row, (None, None, None, None, None));
    }
}
