use async_trait::async_trait;
use sqlx::Transaction;

use crate::persistence::sql::migration::MigrationTrait;

const INDEX_NAME: &str = "idx_events_path_id";

/// Lets an event stream over every user filter by path without reading the
/// whole table.
///
/// `idx_events_user_path_id` leads with `user`, so a path filter with no user
/// had only the primary key to walk, discarding every event outside the path.
/// Event paths now compare byte-wise, as entry paths do, because a path prefix
/// is a contiguous index range only in byte order; this also lets the per-user
/// index serve prefixes. Postgres rebuilds that index as part of the statement;
/// the table itself is not rewritten.
pub struct M20261113EventsPathIndexMigration;

#[async_trait]
impl MigrationTrait for M20261113EventsPathIndexMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        sqlx::query(r#"ALTER TABLE events ALTER COLUMN path TYPE varchar COLLATE "C""#)
            .execute(&mut **tx)
            .await?;
        sqlx::query(&format!("CREATE INDEX {INDEX_NAME} ON events (path, id)"))
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    fn name(&self) -> &str {
        "m20261113_events_path_index"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::{
        migrations::{
            M20250806CreateUserMigration, M20250814CreateEventMigration,
            M20251014EventsTableIndexAndContentHashMigration,
        },
        migrator::Migrator,
        SqlDb,
    };

    /// The plan for a path-prefix query over every user. Sequential scans are
    /// disabled because the planner prefers one on a table this small.
    async fn prefix_query_plan(db: &SqlDb) -> String {
        let mut tx = db.pool().begin().await.unwrap();
        sqlx::query("SET LOCAL enable_seqscan = off")
            .execute(&mut *tx)
            .await
            .unwrap();
        let plan: Vec<String> = sqlx::query_scalar(
            "EXPLAIN SELECT id FROM events WHERE path LIKE '/pub/app/%' ORDER BY id LIMIT 100",
        )
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        plan.join("\n")
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_path_prefix_becomes_an_index_range() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250814CreateEventMigration),
                Box::new(M20251014EventsTableIndexAndContentHashMigration),
            ])
            .await
            .expect("Should run successfully");
        sqlx::query("INSERT INTO users (public_key) VALUES ('user')")
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO events (type, \"user\", path) \
             SELECT 'PUT', 1, path FROM unnest(ARRAY['/pub/app/a', '/pub/other/b']) AS path",
        )
        .execute(db.pool())
        .await
        .unwrap();

        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250814CreateEventMigration),
                Box::new(M20251014EventsTableIndexAndContentHashMigration),
                Box::new(M20261113EventsPathIndexMigration),
            ])
            .await
            .expect("Should run successfully");

        // The prefix must appear as a range in the index condition, not only as a filter.
        let plan = prefix_query_plan(&db).await;
        assert!(plan.contains(INDEX_NAME), "path index unused in: {plan}");
        assert!(
            plan.contains("path >= '/pub/app/'"),
            "prefix is not an index range in: {plan}"
        );

        let paths: Vec<String> =
            sqlx::query_scalar("SELECT path FROM events WHERE path LIKE '/pub/app/%'")
                .fetch_all(db.pool())
                .await
                .unwrap();
        assert_eq!(paths, vec!["/pub/app/a"]);
    }
}
