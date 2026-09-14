use async_trait::async_trait;
use sea_query::{
    ColumnDef, Expr, ForeignKey, ForeignKeyAction, Iden, Index, PostgresQueryBuilder, Table,
};
use sqlx::Transaction;

use crate::persistence::sql::{
    entities::user::{UserIden, USER_TABLE},
    migration::MigrationTrait,
};

const TABLE: &str = "entries";

pub struct M20250815CreateEntryMigration;

#[async_trait]
impl MigrationTrait for M20250815CreateEntryMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        // Create table
        let statement = Table::create()
            .table(TABLE)
            .if_not_exists()
            .col(
                ColumnDef::new(EntryIden::Id)
                    .big_integer()
                    .primary_key()
                    .auto_increment(),
            )
            .col(ColumnDef::new(EntryIden::Path).string().not_null())
            .col(ColumnDef::new(EntryIden::User).integer().not_null())
            .col(ColumnDef::new(EntryIden::ContentHash).blob().not_null())
            .col(
                ColumnDef::new(EntryIden::ContentLength)
                    .big_unsigned()
                    .not_null(),
            )
            .col(ColumnDef::new(EntryIden::ContentType).string().not_null())
            .col(
                ColumnDef::new(EntryIden::ModifiedAt)
                    .timestamp()
                    .not_null()
                    .default(Expr::current_timestamp()),
            )
            .col(
                ColumnDef::new(EntryIden::CreatedAt)
                    .timestamp()
                    .not_null()
                    .default(Expr::current_timestamp()),
            )
            .to_owned();
        let query = statement.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Create foreign key
        // Ensures that the user exists when creating an entry.
        let foreign_key = ForeignKey::create()
            .name("fk_entry_user")
            .from(TABLE, EntryIden::User)
            .to(USER_TABLE, UserIden::Id)
            .on_delete(ForeignKeyAction::Cascade)
            .to_owned();
        let query = foreign_key.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Create a unique index on user and path.
        // Speeds up lookups for specific entries by user and path.
        // Makes sure that there are no duplicate entries for the same user and path.
        let index = Index::create()
            .name("idx_entry_user_path")
            .table(TABLE)
            .col(EntryIden::User)
            .col(EntryIden::Path)
            .unique()
            .index_type(sea_query::IndexType::BTree)
            .to_owned();
        let query = index.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        Ok(())
    }

    fn name(&self) -> &str {
        "m20250815_create_entry"
    }
}

#[derive(Iden)]
enum EntryIden {
    Id,
    Path,
    User,
    ContentHash,
    ContentLength,
    ContentType,
    ModifiedAt,
    CreatedAt,
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Keypair;
    use sea_query::{Query, SimpleExpr};
    use sea_query_sqlx::SqlxBinder;

    use super::*;
    use crate::persistence::sql::{
        entities::user::{UserIden, USER_TABLE},
        migrations::M20250806CreateUserMigration,
        migrator::Migrator,
        SqlDb,
    };
    use sqlx::{postgres::PgRow, FromRow, Row};

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct EntryEntity {
        pub id: i64,
        pub user_id: i32,
        pub path: String,
        pub content_hash: Vec<u8>,
        pub content_length: i64,
        pub content_type: String,
        pub modified_at: sqlx::types::chrono::NaiveDateTime,
        pub created_at: sqlx::types::chrono::NaiveDateTime,
    }

    impl FromRow<'_, PgRow> for EntryEntity {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            let id: i64 = row.try_get(EntryIden::Id.to_string().as_str())?;
            let user_id: i32 = row.try_get(EntryIden::User.to_string().as_str())?;
            let path: String = row.try_get(EntryIden::Path.to_string().as_str())?;
            let content_hash: Vec<u8> = row.try_get(EntryIden::ContentHash.to_string().as_str())?;
            let content_length: i64 = row.try_get(EntryIden::ContentLength.to_string().as_str())?;
            let content_type: String = row.try_get(EntryIden::ContentType.to_string().as_str())?;
            let modified_at: sqlx::types::chrono::NaiveDateTime =
                row.try_get(EntryIden::ModifiedAt.to_string().as_str())?;
            let created_at: sqlx::types::chrono::NaiveDateTime =
                row.try_get(EntryIden::CreatedAt.to_string().as_str())?;
            Ok(EntryEntity {
                id,
                user_id,
                path,
                content_hash,
                content_length,
                content_type,
                modified_at,
                created_at,
            })
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_entry_migration() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
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

        let bytes: Vec<u8> = vec![0; 32];
        // Create an entry
        let statement = Query::insert()
            .into_table(TABLE)
            .columns([
                EntryIden::User,
                EntryIden::Path,
                EntryIden::ContentHash,
                EntryIden::ContentLength,
                EntryIden::ContentType,
            ])
            .values(vec![
                SimpleExpr::Value(1.into()),
                SimpleExpr::Value("/test".into()),
                SimpleExpr::Value(bytes.clone().into()),
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

        // Read entry
        let statement = Query::select()
            .from(TABLE)
            .columns([
                EntryIden::Id,
                EntryIden::User,
                EntryIden::Path,
                EntryIden::ContentHash,
                EntryIden::ContentLength,
                EntryIden::ContentType,
                EntryIden::CreatedAt,
                EntryIden::ModifiedAt,
            ])
            .to_owned();
        let (query, _) = statement.build_sqlx(PostgresQueryBuilder);
        let entry: EntryEntity = sqlx::query_as(query.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(entry.user_id, 1);
        assert_eq!(entry.path, "/test");
        assert_eq!(entry.content_hash, vec![0; 32]);
        assert_eq!(entry.content_length, 100);
        assert_eq!(entry.content_type, "text/plain");
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_entry_twice_should_fail() {
        // Test Unique constraint. Unique user and path.
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
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

        let bytes: Vec<u8> = vec![0; 32];
        // Create an entry
        let statement = Query::insert()
            .into_table(TABLE)
            .columns([
                EntryIden::User,
                EntryIden::Path,
                EntryIden::ContentHash,
                EntryIden::ContentLength,
                EntryIden::ContentType,
            ])
            .values(vec![
                SimpleExpr::Value(1.into()),
                SimpleExpr::Value("/test".into()),
                SimpleExpr::Value(bytes.clone().into()),
                SimpleExpr::Value(100.into()),
                SimpleExpr::Value("text/plain".into()),
            ])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values.clone())
            .execute(db.pool())
            .await
            .expect("Should work first time");

        // Create the same entry again
        let result = sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await;
        assert!(result.is_err(), "Should fail second time");
    }
}
