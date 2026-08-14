use sea_query::{ColumnDef, Expr, PostgresQueryBuilder, Query, SimpleExpr, Table};
use sea_query_binder::SqlxBinder;
use sqlx::{Row, Transaction};

use crate::persistence::sql::{
    migration::MigrationTrait,
    migrations::{
        M20250806CreateUserMigration, M20250812CreateSignupCodeMigration,
        M20250813CreateSessionMigration, M20250814CreateEventMigration,
        M20250815CreateEntryMigration, M20251014EventsTableIndexAndContentHashMigration,
        M20260325CreateGrantSessionsMigration, M20260327AddQuotaColumnsMigration,
        M20260507AddAllowedWritePathsMigration, M20260609AddSignupCodeUsedAtMigration,
        M20260723SanitizeCapabilitiesMigration,
    },
    sql_db::SqlDb,
};

/// The name of the migration table to keep track of which migrations have been applied.
const MIGRATION_TABLE: &str = "migrations";

/// Migrator is responsible for running migrations on the database.
pub struct Migrator<'a> {
    db: &'a SqlDb,
}

impl<'a> Migrator<'a> {
    /// Creates a new migrator.
    /// db: The database connection to use.
    pub fn new(db: &'a SqlDb) -> Self {
        Self { db }
    }

    /// Returns a list of migrations to run.
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        // Add new migrations here. They run from top to bottom.
        vec![
            Box::new(M20250806CreateUserMigration),
            Box::new(M20250812CreateSignupCodeMigration),
            Box::new(M20250813CreateSessionMigration),
            Box::new(M20250814CreateEventMigration),
            Box::new(M20250815CreateEntryMigration),
            Box::new(M20251014EventsTableIndexAndContentHashMigration),
            Box::new(M20260325CreateGrantSessionsMigration),
            Box::new(M20260327AddQuotaColumnsMigration),
            Box::new(M20260507AddAllowedWritePathsMigration),
            Box::new(M20260609AddSignupCodeUsedAtMigration),
            Box::new(M20260723SanitizeCapabilitiesMigration),
        ]
    }

    /// Runs all migrations that are not yet applied.
    pub async fn run(&self) -> anyhow::Result<()> {
        self.run_migrations(Self::migrations()).await
    }

    /// Runs a specific list of migrations.
    pub async fn run_migrations(
        &self,
        migrations: Vec<Box<dyn MigrationTrait>>,
    ) -> anyhow::Result<()> {
        self.create_migration_table()
            .await
            .map_err(|e| e.context("Failed to create migration table"))?;
        let already_applied_migrations = self
            .get_applied_migrations()
            .await
            .map_err(|e| e.context("Failed to get applied migrations"))?;
        let migrations_to_run = migrations
            .into_iter()
            .filter(|m| !already_applied_migrations.contains(&m.name().to_string()))
            .collect::<Vec<_>>();

        for migration in migrations_to_run {
            self.run_migration(&*migration)
                .await
                .map_err(|e| e.context(format!("Failed to run migration {}", migration.name())))?;
        }
        Ok(())
    }

    /// Runs a single migration.
    async fn run_migration(&self, migration: &dyn MigrationTrait) -> anyhow::Result<()> {
        tracing::info!("Running migration {}", migration.name());

        let result: anyhow::Result<()> = async {
            let mut tx = self.db.pool().begin().await?;
            migration.up(&mut tx).await?;
            self.mark_migration_as_done(&mut tx, migration.name())
                .await
                .map_err(|e| e.context("Failed to mark migration as done"))?;
            tx.commit().await?;
            Ok(())
        }
        .await;

        match &result {
            Ok(()) => tracing::info!("Migration {} applied successfully", migration.name()),
            Err(e) => tracing::error!("Failed to run migration {}: {}", migration.name(), e),
        }
        result
    }

    /// Creates the migration table if it doesn't exist.
    /// This table keeps track of which migrations have been applied.
    async fn create_migration_table(&self) -> anyhow::Result<()> {
        let statement = Table::create()
            .table(MIGRATION_TABLE)
            .if_not_exists()
            .col(
                ColumnDef::new("id")
                    .integer()
                    .primary_key()
                    .auto_increment()
                    .not_null(),
            )
            .col(ColumnDef::new("name").string().not_null().unique_key())
            .col(
                ColumnDef::new("created_at")
                    .timestamp()
                    .not_null()
                    .default(Expr::current_timestamp()),
            )
            .to_owned();
        let query = statement.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(self.db.pool()).await?;
        Ok(())
    }

    /// Returns a list of migrations that have already run.
    async fn get_applied_migrations(&self) -> anyhow::Result<Vec<String>> {
        let statement = Query::select()
            .column("name")
            .from(MIGRATION_TABLE)
            .to_owned();
        let (query, _) = statement.build_sqlx(PostgresQueryBuilder);

        let rows = sqlx::query(&query).fetch_all(self.db.pool()).await?;

        let migration_names: Vec<String> = rows
            .iter()
            .map(|row| row.try_get::<String, _>("name").unwrap_or_default())
            .collect();

        Ok(migration_names)
    }

    /// Marks a migration as done.
    /// This is done by inserting a row into the migrations table with the migration name.
    pub async fn mark_migration_as_done(
        &self,
        tx: &mut Transaction<'static, sqlx::Postgres>,
        migration_name: &str,
    ) -> anyhow::Result<()> {
        let statement = Query::insert()
            .into_table(MIGRATION_TABLE)
            .columns(["name"])
            .values([SimpleExpr::Value(migration_name.into())])?
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);

        sqlx::query_with(&query, values).execute(&mut **tx).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_table() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator.create_migration_table().await.unwrap();
        let mut tx = db.pool().begin().await.unwrap();
        migrator
            .mark_migration_as_done(&mut tx, "test_migration")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let applied_migrations = migrator.get_applied_migrations().await.unwrap();
        assert_eq!(applied_migrations, vec!["test_migration"]);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_run_successful() {
        struct TestMigration;
        #[async_trait::async_trait]
        impl MigrationTrait for TestMigration {
            fn name(&self) -> &str {
                "test_migration"
            }

            async fn up(
                &self,
                tx: &mut Transaction<'static, sqlx::Postgres>,
            ) -> anyhow::Result<()> {
                let statement = Table::create()
                    .table("test_table")
                    .if_not_exists()
                    .col(
                        ColumnDef::new("id")
                            .integer()
                            .primary_key()
                            .auto_increment()
                            .not_null(),
                    )
                    .to_owned();
                let query = statement.build(PostgresQueryBuilder);
                sqlx::query(query.as_str()).execute(&mut **tx).await?;
                Ok(())
            }
        }

        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![Box::new(TestMigration)])
            .await
            .unwrap();
        let applied_migrations = migrator.get_applied_migrations().await.unwrap();
        assert_eq!(applied_migrations, vec!["test_migration"]);

        sqlx::query(
            "SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename='test_table';",
        )
        .fetch_one(db.pool())
        .await
        .expect("Table should exist");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_run_failed_rollback() {
        struct TestMigration;
        #[async_trait::async_trait]
        impl MigrationTrait for TestMigration {
            fn name(&self) -> &str {
                "test_migration"
            }

            async fn up(
                &self,
                tx: &mut Transaction<'static, sqlx::Postgres>,
            ) -> anyhow::Result<()> {
                // Create table
                let statement = Table::create()
                    .table("test_table")
                    .if_not_exists()
                    .col(
                        ColumnDef::new("id")
                            .integer()
                            .primary_key()
                            .auto_increment()
                            .not_null(),
                    )
                    .to_owned();
                let query = statement.build(PostgresQueryBuilder);
                sqlx::query(query.as_str()).execute(&mut **tx).await?;
                // Fail after the table is created
                anyhow::bail!("test error");
            }
        }

        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![Box::new(TestMigration)])
            .await
            .expect_err("Migration should fail");
        let applied_migrations = migrator.get_applied_migrations().await.unwrap();
        assert!(applied_migrations.is_empty());

        let rows = sqlx::query(
            "SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'test_table';",
        )
        .fetch_all(db.pool())
        .await
        .expect("Query should succeed");
        assert!(rows.is_empty(), "Table should not exist after rollback");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_run_migration_twice() {
        struct TestMigration;
        #[async_trait::async_trait]
        impl MigrationTrait for TestMigration {
            fn name(&self) -> &str {
                "test_migration"
            }

            async fn up(
                &self,
                _tx: &mut Transaction<'static, sqlx::Postgres>,
            ) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator.create_migration_table().await.unwrap();
        // Mark the migration as done
        migrator
            .run_migration(&TestMigration)
            .await
            .expect("Should work as usual");
        // Try to forcefully run it again
        migrator
            .run_migration(&TestMigration)
            .await
            .expect_err("Should fail because it was already run (unique constraint)");
        let applied_migrations = migrator.get_applied_migrations().await.unwrap();
        assert_eq!(
            applied_migrations.len(),
            1,
            "Migration should only be run once"
        );
    }
}
