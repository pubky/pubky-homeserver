use async_trait::async_trait;
use sea_query::{ColumnDef, Expr, ForeignKey, ForeignKeyAction, Iden, PostgresQueryBuilder, Table};
use sqlx::Transaction;

use crate::persistence::sql::{
    entities::user::{UserIden, USER_TABLE},
    migration::MigrationTrait,
};

const TABLE: &str = "events";

pub struct M20250814CreateEventMigration;

#[async_trait]
impl MigrationTrait for M20250814CreateEventMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        // Create table
        let statement = Table::create()
            .table(TABLE)
            .if_not_exists()
            .col(
                ColumnDef::new(EventIden::Id)
                    .big_integer()
                    .primary_key()
                    .auto_increment(),
            )
            .col(ColumnDef::new(EventIden::Type).string_len(3).not_null())
            .col(ColumnDef::new(EventIden::User).integer().not_null())
            .col(ColumnDef::new(EventIden::Path).string().not_null())
            .col(
                ColumnDef::new(EventIden::CreatedAt)
                    .timestamp()
                    .not_null()
                    .default(Expr::current_timestamp()),
            )
            .to_owned();
        let query = statement.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Create foreign key
        let foreign_key = ForeignKey::create()
            .name("fk_event_user")
            .from(TABLE, EventIden::User)
            .to(USER_TABLE, UserIden::Id)
            .on_delete(ForeignKeyAction::Cascade)
            .to_owned();
        let query = foreign_key.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        Ok(())
    }

    fn name(&self) -> &str {
        "m20250814_create_event"
    }
}

#[derive(Iden)]
enum EventIden {
    Id,
    Type,
    User,
    Path,
    CreatedAt,
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Keypair;
    use sea_query::{Query, SimpleExpr};
    use sea_query_sqlx::SqlxBinder;

    use crate::persistence::sql::{
        entities::user::{UserIden, USER_TABLE},
        migrations::M20250806CreateUserMigration,
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
    }

    impl FromRow<'_, PgRow> for EventEntity {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            let id: i64 = row.try_get(EventIden::Id.to_string().as_str())?;
            let event_type: String = row.try_get(EventIden::Type.to_string().as_str())?;
            let user_id: i32 = row.try_get(EventIden::User.to_string().as_str())?;
            let path: String = row.try_get(EventIden::Path.to_string().as_str())?;
            let created_at: sqlx::types::chrono::NaiveDateTime =
                row.try_get(EventIden::CreatedAt.to_string().as_str())?;
            Ok(EventEntity {
                id,
                event_type,
                user_id,
                path,
                created_at,
            })
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_event_migration() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250814CreateEventMigration),
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

        // Create an event
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

        // Read event
        let statement = Query::select()
            .from(TABLE)
            .columns([
                EventIden::Id,
                EventIden::Type,
                EventIden::User,
                EventIden::Path,
                EventIden::CreatedAt,
            ])
            .to_owned();
        let (query, _) = statement.build_sqlx(PostgresQueryBuilder);
        let event: EventEntity = sqlx::query_as(query.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(event.event_type, "put");
        assert_eq!(event.user_id, 1);
        assert_eq!(event.path, "/test");
    }
}
