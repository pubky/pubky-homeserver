use async_trait::async_trait;
use sea_query::{ColumnDef, Expr, ForeignKey, ForeignKeyAction, Iden, PostgresQueryBuilder, Table};

use sqlx::Transaction;

use crate::persistence::sql::{
    entities::user::{UserIden, USER_TABLE},
    migration::MigrationTrait,
};

const TABLE: &str = "sessions";

pub struct M20250813CreateSessionMigration;

#[async_trait]
impl MigrationTrait for M20250813CreateSessionMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        // Create table
        let statement = Table::create()
            .table(TABLE)
            .if_not_exists()
            .col(
                ColumnDef::new(SessionIden::Id)
                    .integer()
                    .primary_key()
                    .auto_increment(),
            )
            .col(
                ColumnDef::new(SessionIden::Secret)
                    .string_len(26)
                    .not_null()
                    .unique_key(),
            )
            .col(ColumnDef::new(SessionIden::User).integer().not_null())
            .col(ColumnDef::new(SessionIden::Capabilities).text().not_null())
            .col(
                ColumnDef::new(SessionIden::CreatedAt)
                    .timestamp()
                    .not_null()
                    .default(Expr::current_timestamp()),
            )
            .to_owned();
        let query = statement.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Create foreign key
        let foreign_key = ForeignKey::create()
            .name("fk_session_user")
            .from(TABLE, SessionIden::User)
            .to(USER_TABLE, UserIden::Id)
            .on_delete(ForeignKeyAction::Cascade)
            .to_owned();
        let query = foreign_key.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Create index on secret
        let index = sea_query::Index::create()
            .name("idx_session_secret")
            .table(TABLE)
            .col(SessionIden::Secret)
            .index_type(sea_query::IndexType::BTree)
            .to_owned();
        let query = index.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        Ok(())
    }

    fn name(&self) -> &str {
        "m20250813_create_session"
    }
}

#[derive(Iden)]
enum SessionIden {
    Id,
    Secret,
    User,
    Capabilities,
    CreatedAt,
}

#[cfg(test)]
mod tests {
    use pubky_common::capabilities::{Capabilities, Capability, CapsBuilder};
    use pubky_common::crypto::Keypair;
    use sea_query::{Query, SimpleExpr};
    use sea_query_binder::SqlxBinder;
    use sqlx::{postgres::PgRow, FromRow, Row};

    use crate::persistence::sql::{
        entities::user::{UserIden, USER_TABLE},
        migrations::M20250806CreateUserMigration,
        migrator::Migrator,
        SqlDb,
    };

    use super::*;

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct SessionEntity {
        pub id: i32,
        pub secret: String,
        pub user: i32,
        pub capabilities: Capabilities,
        pub created_at: sqlx::types::chrono::NaiveDateTime,
    }

    impl FromRow<'_, PgRow> for SessionEntity {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            let id: i32 = row.try_get(SessionIden::Id.to_string().as_str())?;
            let secret: String = row.try_get(SessionIden::Secret.to_string().as_str())?;
            let user: i32 = row.try_get(SessionIden::User.to_string().as_str())?;
            let capabilities: String =
                row.try_get(SessionIden::Capabilities.to_string().as_str())?;
            let capabilities: Capabilities = capabilities.parse().map_err(
                |e: pubky_common::capabilities::CapabilitiesParseError| {
                    sqlx::Error::Decode(e.into())
                },
            )?;
            let created_at: sqlx::types::chrono::NaiveDateTime =
                row.try_get(SessionIden::CreatedAt.to_string().as_str())?;
            Ok(SessionEntity {
                id,
                secret,
                user,
                capabilities,
                created_at,
            })
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_user_migration() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250813CreateSessionMigration),
            ])
            .await
            .expect("Should run successfully");

        // Create a user
        let pubkey = Keypair::random().public_key();
        let secret = "6HHZ06GHB964CZMDAA0WCNV2C8";
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

        // Create a session
        let caps = CapsBuilder::new().cap(Capability::root()).finish();
        let statement = Query::insert()
            .into_table(TABLE)
            .columns([
                SessionIden::Secret,
                SessionIden::User,
                SessionIden::Capabilities,
            ])
            .values(vec![
                SimpleExpr::Value(secret.into()),
                SimpleExpr::Value(1.into()),
                SimpleExpr::Value(caps.to_string().into()),
            ])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        // Read session
        let statement = Query::select()
            .from(TABLE)
            .columns([
                SessionIden::Id,
                SessionIden::Secret,
                SessionIden::User,
                SessionIden::Capabilities,
                SessionIden::CreatedAt,
            ])
            .to_owned();
        let (query, _) = statement.build_sqlx(PostgresQueryBuilder);
        let session: SessionEntity = sqlx::query_as(query.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(session.secret, secret);
        assert_eq!(session.user, 1);
        assert_eq!(session.capabilities, caps);
    }
}
