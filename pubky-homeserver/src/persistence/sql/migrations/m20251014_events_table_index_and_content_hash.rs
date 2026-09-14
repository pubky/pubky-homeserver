use async_trait::async_trait;
use sea_query::{ColumnDef, Index, PostgresQueryBuilder, Table};
use sqlx::Transaction;

use crate::persistence::{files::events::EventIden, sql::migration::MigrationTrait};

const TABLE: &str = "events";
const INDEX_NAME: &str = "idx_events_user_path_id";

pub struct M20251014EventsTableIndexAndContentHashMigration;

#[async_trait]
impl MigrationTrait for M20251014EventsTableIndexAndContentHashMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        // Create index on (user, path, id) for efficient per-user event streaming with path filtering
        let statement = Index::create()
            .name(INDEX_NAME)
            .table(TABLE)
            .col("user")
            .col("path")
            .col("id")
            .to_owned();
        let query = statement.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Add nullable content_hash column for tracking file content hashes
        let statement = Table::alter()
            .table(TABLE)
            .add_column(ColumnDef::new(EventIden::ContentHash).binary().null())
            .to_owned();
        let query = statement.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Backfill content_hash for existing PUT events
        // Step 1: Update events where matching entry exists in entries table (if table exists)
        let table_exists = sqlx::query_scalar::<_, bool>(
            r#"SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = 'entries'
            )"#,
        )
        .fetch_one(&mut **tx)
        .await?;

        if table_exists {
            // Use an optimized query that leverages the idx_entry_user_path index on entries
            // and the idx_events_user_path_id index on events for efficient lookups
            let backfill_from_entries = r#"
                UPDATE events
                SET content_hash = entries.content_hash
                FROM entries
                WHERE events."user" = entries."user"
                  AND events.path = entries.path
                  AND events.type = 'PUT'
                  AND events.content_hash IS NULL
            "#;
            let result = sqlx::query(backfill_from_entries)
                .execute(&mut **tx)
                .await?;
            tracing::info!(
                "Backfilled {} PUT events with content_hash from entries table",
                result.rows_affected()
            );
        }

        // Step 2: Update remaining PUT events (where entry no longer exists) with zero hash
        let zero_hash = vec![0u8; 32];
        let result = sqlx::query(
            r#"UPDATE events SET content_hash = $1 WHERE type = 'PUT' AND content_hash IS NULL"#,
        )
        .bind(zero_hash)
        .execute(&mut **tx)
        .await?;
        tracing::info!(
            "Backfilled {} PUT events with zero hash (no matching entry)",
            result.rows_affected()
        );

        Ok(())
    }

    fn name(&self) -> &str {
        "m20251014_enhance_events_table"
    }
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Hash;
    use pubky_common::crypto::Keypair;
    use sea_query::{Iden, Query, SimpleExpr};
    use sea_query_sqlx::SqlxBinder;

    use crate::persistence::sql::{
        entities::{
            entry::EntryIden,
            user::{UserIden, USER_TABLE},
        },
        migrations::{
            M20250806CreateUserMigration, M20250814CreateEventMigration,
            M20250815CreateEntryMigration,
        },
        migrator::Migrator,
        SqlDb,
    };
    use sqlx::{postgres::PgRow, FromRow, Row};

    use super::*;

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct EventEntity {
        pub id: i64,
        pub event_type: String,
        pub user_id: i32,
        pub path: String,
        pub created_at: sqlx::types::chrono::NaiveDateTime,
        pub content_hash: Option<Vec<u8>>,
    }

    impl FromRow<'_, PgRow> for EventEntity {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            let id: i64 = row.try_get(EventIden::Id.to_string().as_str())?;
            let event_type: String = row.try_get(EventIden::Type.to_string().as_str())?;
            let user_id: i32 = row.try_get(EventIden::User.to_string().as_str())?;
            let path: String = row.try_get(EventIden::Path.to_string().as_str())?;
            let created_at: sqlx::types::chrono::NaiveDateTime =
                row.try_get(EventIden::CreatedAt.to_string().as_str())?;
            let content_hash: Option<Vec<u8>> =
                row.try_get(EventIden::ContentHash.to_string().as_str())?;
            Ok(EventEntity {
                id,
                event_type,
                user_id,
                path,
                created_at,
                content_hash,
            })
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_table_index_and_content_hash_migration() {
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

        // Create a user
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

        // Create an event without content_hash
        let statement = Query::insert()
            .into_table(TABLE)
            .columns([EventIden::Type, EventIden::User, EventIden::Path])
            .values(vec![
                SimpleExpr::Value("put".into()),
                SimpleExpr::Value(1.into()),
                SimpleExpr::Value("/test".into()),
            ])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        // Create an event with content_hash
        let hash = Hash::from_bytes([42u8; 32]);
        let statement = Query::insert()
            .into_table(TABLE)
            .columns([
                EventIden::Type,
                EventIden::User,
                EventIden::Path,
                EventIden::ContentHash,
            ])
            .values(vec![
                SimpleExpr::Value("put".into()),
                SimpleExpr::Value(1.into()),
                SimpleExpr::Value("/test2".into()),
                SimpleExpr::Value(hash.as_bytes().to_vec().into()),
            ])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        // Read events
        let statement = Query::select()
            .from(TABLE)
            .columns([
                EventIden::Id,
                EventIden::Type,
                EventIden::User,
                EventIden::Path,
                EventIden::CreatedAt,
                EventIden::ContentHash,
            ])
            .order_by(EventIden::Id, sea_query::Order::Asc)
            .to_owned();
        let (query, _) = statement.build_sqlx(PostgresQueryBuilder);
        let events: Vec<EventEntity> = sqlx::query_as(query.as_str())
            .fetch_all(db.pool())
            .await
            .unwrap();

        assert_eq!(events.len(), 2);

        // First event has no content_hash
        assert_eq!(events[0].event_type, "put");
        assert_eq!(events[0].user_id, 1);
        assert_eq!(events[0].path, "/test");
        assert_eq!(events[0].content_hash, None);

        // Second event has content_hash
        assert_eq!(events[1].event_type, "put");
        assert_eq!(events[1].user_id, 1);
        assert_eq!(events[1].path, "/test2");
        assert_eq!(events[1].content_hash, Some(hash.as_bytes().to_vec()));

        // Verify index exists
        let index_check = sqlx::query(
            "SELECT indexname FROM pg_indexes WHERE tablename = 'events' AND indexname = $1",
        )
        .bind(INDEX_NAME)
        .fetch_optional(db.pool())
        .await
        .unwrap();

        assert!(index_check.is_some(), "Index {} should exist", INDEX_NAME);

        // Verify index columns are (user, path, id)
        let index_columns: Vec<(i16, String)> = sqlx::query_as(
            "SELECT a.attnum, a.attname
             FROM pg_index i
             JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
             WHERE i.indrelid = 'events'::regclass
             AND i.indexrelid = $1::regclass
             ORDER BY array_position(i.indkey, a.attnum)",
        )
        .bind(INDEX_NAME)
        .fetch_all(db.pool())
        .await
        .unwrap();

        assert_eq!(index_columns.len(), 3, "Index should have 3 columns");
        assert_eq!(index_columns[0].1, "user", "First column should be 'user'");
        assert_eq!(index_columns[1].1, "path", "Second column should be 'path'");
        assert_eq!(index_columns[2].1, "id", "Third column should be 'id'");
    }

    // Simplified test-only entity struct to avoid using complex types (EntryPath, Hash)
    #[allow(dead_code)]
    #[derive(Debug, PartialEq, Eq, Clone)]
    struct TestEntryEntity {
        pub id: i64,
        pub user_id: i32,
        pub path: String,
        pub content_hash: Vec<u8>,
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_content_hash_backfill() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);

        // Run migrations up to (but not including) the content_hash migration
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250814CreateEventMigration),
                Box::new(M20250815CreateEntryMigration),
            ])
            .await
            .expect("Should run successfully");

        // Create a user
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

        // Create an entry in entries table
        let entry_hash = Hash::from_bytes([99u8; 32]);
        let statement = Query::insert()
            .into_table("entries")
            .columns([
                EntryIden::User,
                EntryIden::Path,
                EntryIden::ContentHash,
                EntryIden::ContentLength,
                EntryIden::ContentType,
            ])
            .values(vec![
                SimpleExpr::Value(1.into()),
                SimpleExpr::Value("/with-entry".into()),
                SimpleExpr::Value(entry_hash.as_bytes().to_vec().into()),
                SimpleExpr::Value(100.into()),
                SimpleExpr::Value("text/plain".into()),
            ])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        // Create PUT event that corresponds to the entry (should get backfilled with entry's hash)
        let statement = Query::insert()
            .into_table(TABLE)
            .columns([EventIden::Type, EventIden::User, EventIden::Path])
            .values(vec![
                SimpleExpr::Value("PUT".into()),
                SimpleExpr::Value(1.into()),
                SimpleExpr::Value("/with-entry".into()),
            ])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        // Create PUT event with no corresponding entry (should get zero hash)
        let statement = Query::insert()
            .into_table(TABLE)
            .columns([EventIden::Type, EventIden::User, EventIden::Path])
            .values(vec![
                SimpleExpr::Value("PUT".into()),
                SimpleExpr::Value(1.into()),
                SimpleExpr::Value("/no-entry".into()),
            ])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        // Create DEL event (should remain NULL after migration)
        let statement = Query::insert()
            .into_table(TABLE)
            .columns([EventIden::Type, EventIden::User, EventIden::Path])
            .values(vec![
                SimpleExpr::Value("DEL".into()),
                SimpleExpr::Value(1.into()),
                SimpleExpr::Value("/deleted".into()),
            ])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        // Now run the content_hash migration
        migrator
            .run_migrations(vec![Box::new(
                M20251014EventsTableIndexAndContentHashMigration,
            )])
            .await
            .expect("Should run content_hash migration successfully");

        // Read all events
        let statement = Query::select()
            .from(TABLE)
            .columns([
                EventIden::Id,
                EventIden::Type,
                EventIden::User,
                EventIden::Path,
                EventIden::CreatedAt,
                EventIden::ContentHash,
            ])
            .order_by(EventIden::Id, sea_query::Order::Asc)
            .to_owned();
        let (query, _) = statement.build_sqlx(PostgresQueryBuilder);
        let events: Vec<EventEntity> = sqlx::query_as(query.as_str())
            .fetch_all(db.pool())
            .await
            .unwrap();

        assert_eq!(events.len(), 3);

        // First event: PUT with matching entry - should have entry's content_hash
        assert_eq!(events[0].event_type, "PUT");
        assert_eq!(events[0].path, "/with-entry");
        assert_eq!(
            events[0].content_hash,
            Some(entry_hash.as_bytes().to_vec()),
            "PUT event with matching entry should have entry's content_hash"
        );

        // Second event: PUT without matching entry - should have zero hash
        assert_eq!(events[1].event_type, "PUT");
        assert_eq!(events[1].path, "/no-entry");
        assert_eq!(
            events[1].content_hash,
            Some(vec![0u8; 32]),
            "PUT event without matching entry should have zero hash"
        );

        // Third event: DEL - should remain NULL
        assert_eq!(events[2].event_type, "DEL");
        assert_eq!(events[2].path, "/deleted");
        assert_eq!(
            events[2].content_hash, None,
            "DEL event should have NULL content_hash"
        );
    }
}
