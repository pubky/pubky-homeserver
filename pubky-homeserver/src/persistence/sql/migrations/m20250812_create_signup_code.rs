use async_trait::async_trait;
use sea_query::{ColumnDef, Expr, Iden, PostgresQueryBuilder, Table};
use sqlx::Transaction;

use crate::persistence::sql::migration::MigrationTrait;

const SIGNUP_CODE_TABLE: &str = "signup_codes";

pub struct M20250812CreateSignupCodeMigration;

#[async_trait]
impl MigrationTrait for M20250812CreateSignupCodeMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        let statement = Table::create()
            .table(SIGNUP_CODE_TABLE)
            .if_not_exists()
            .col(
                ColumnDef::new(SignupCodeIden::Id)
                    .string_len(14)
                    .not_null()
                    .primary_key(),
            )
            .col(
                ColumnDef::new(SignupCodeIden::CreatedAt)
                    .timestamp()
                    .not_null()
                    .default(Expr::current_timestamp()),
            )
            // UsedBy is the user pubkey directly. No Foreign Key needed because
            // if the user is deleted, we don't want the code to be reused.
            .col(ColumnDef::new(SignupCodeIden::UsedBy).string_len(52).null())
            .to_owned();
        let query = statement.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        Ok(())
    }

    fn name(&self) -> &str {
        "m20250812_create_signup_code"
    }
}

#[derive(Iden)]
enum SignupCodeIden {
    Id,
    CreatedAt,
    UsedBy,
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::{Keypair, PublicKey};
    use sea_query::{ExprTrait, Query, SimpleExpr};
    use sea_query_sqlx::SqlxBinder;
    use sqlx::{postgres::PgRow, FromRow, Row};

    use crate::persistence::sql::{
        migrations::M20250806CreateUserMigration, migrator::Migrator, SqlDb,
    };

    use super::*;

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct SignupCodeEntity {
        pub id: String,
        pub created_at: sqlx::types::chrono::NaiveDateTime,
        pub used_by: Option<PublicKey>,
    }

    impl FromRow<'_, PgRow> for SignupCodeEntity {
        fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
            let token: String = row.try_get(SignupCodeIden::Id.to_string().as_str())?;
            let created_at: sqlx::types::chrono::NaiveDateTime =
                row.try_get(SignupCodeIden::CreatedAt.to_string().as_str())?;
            let used_by_raw: Option<String> =
                row.try_get(SignupCodeIden::UsedBy.to_string().as_str())?;
            let used_by = used_by_raw
                .map(|s| {
                    PublicKey::try_from_z32(s.as_str())
                        .map_err(|e| sqlx::Error::Decode(Box::new(e)))
                })
                .transpose()?;
            Ok(SignupCodeEntity {
                id: token,
                created_at,
                used_by,
            })
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_code_migration() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250812CreateSignupCodeMigration),
            ])
            .await
            .expect("Should run successfully");

        // Create a user
        let pubkey = Keypair::random().public_key();
        let code_id = "JZY0-D6MY-ZFNG";
        // Create a signup code
        let statement = Query::insert()
            .into_table(SIGNUP_CODE_TABLE)
            .columns([SignupCodeIden::Id])
            .values(vec![SimpleExpr::Value(code_id.into())])
            .unwrap()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        // Read signup code
        let statement = Query::select()
            .from(SIGNUP_CODE_TABLE)
            .columns([
                SignupCodeIden::Id,
                SignupCodeIden::CreatedAt,
                SignupCodeIden::UsedBy,
            ])
            .to_owned();
        let (query, _) = statement.build_sqlx(PostgresQueryBuilder);
        let code: SignupCodeEntity = sqlx::query_as(query.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(code.id, code_id);
        assert_eq!(code.used_by, None);

        // Use signup code
        let statement = Query::update()
            .table(SIGNUP_CODE_TABLE)
            .values(vec![(
                SignupCodeIden::UsedBy,
                SimpleExpr::Value(pubkey.z32().into()),
            )])
            .and_where(Expr::col(SignupCodeIden::Id).eq(code.id))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        sqlx::query_with(query.as_str(), values)
            .execute(db.pool())
            .await
            .unwrap();

        // Read signup code again
        let statement = Query::select()
            .from(SIGNUP_CODE_TABLE)
            .columns([
                SignupCodeIden::Id,
                SignupCodeIden::CreatedAt,
                SignupCodeIden::UsedBy,
            ])
            .to_owned();
        let (query, _) = statement.build_sqlx(PostgresQueryBuilder);
        let code: SignupCodeEntity = sqlx::query_as(query.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(code.id, code_id);
        assert_eq!(code.used_by, Some(pubkey.clone()));
    }
}
