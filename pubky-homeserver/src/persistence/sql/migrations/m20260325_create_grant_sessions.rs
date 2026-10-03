use async_trait::async_trait;
use sea_query::{ColumnDef, Expr, ForeignKey, ForeignKeyAction, Iden, PostgresQueryBuilder, Table};
use sqlx::Transaction;

use crate::persistence::sql::{
    entities::user::UserIden, migration::MigrationTrait, user::USER_TABLE,
};

pub const GRANTS_TABLE: &str = "grants";
pub const GRANT_SESSIONS_TABLE: &str = "grant_sessions";
pub const POP_NONCES_TABLE: &str = "pop_nonces";

pub struct M20260325CreateGrantSessionsMigration;

#[async_trait]
impl MigrationTrait for M20260325CreateGrantSessionsMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        self.create_grants_table(tx).await?;
        self.create_grant_sessions_table(tx).await?;
        self.create_pop_nonces_table(tx).await?;
        Ok(())
    }

    fn name(&self) -> &str {
        "m20260325_create_grant_sessions"
    }
}

impl M20260325CreateGrantSessionsMigration {
    async fn create_grants_table(
        &self,
        tx: &mut Transaction<'static, sqlx::Postgres>,
    ) -> anyhow::Result<()> {
        let statement = Table::create()
            .table(GRANTS_TABLE)
            .if_not_exists()
            .col(
                ColumnDef::new(GrantIden::Id)
                    .string_len(36)
                    .not_null()
                    .primary_key(),
            )
            .col(ColumnDef::new(GrantIden::User).integer().not_null())
            .col(
                ColumnDef::new(GrantIden::ClientId)
                    .string_len(253)
                    .not_null(),
            )
            .col(
                ColumnDef::new(GrantIden::ClientCnfKey)
                    .string_len(52)
                    .not_null(),
            )
            .col(ColumnDef::new(GrantIden::Capabilities).text().not_null())
            .col(ColumnDef::new(GrantIden::IssuedAt).big_integer().not_null())
            .col(
                ColumnDef::new(GrantIden::ExpiresAt)
                    .big_integer()
                    .not_null(),
            )
            .col(ColumnDef::new(GrantIden::RevokedAt).big_integer())
            .col(
                ColumnDef::new(GrantIden::CreatedAt)
                    .timestamp()
                    .not_null()
                    .default(Expr::current_timestamp()),
            )
            .to_owned();
        let query = statement.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Foreign key: user → users.id
        let fk = ForeignKey::create()
            .name("fk_grant_user")
            .from(GRANTS_TABLE, GrantIden::User)
            .to(USER_TABLE, UserIden::Id)
            .on_delete(ForeignKeyAction::Cascade)
            .to_owned();
        let query = fk.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Index on user
        let idx = sea_query::Index::create()
            .name("idx_grants_user")
            .table(GRANTS_TABLE)
            .col(GrantIden::User)
            .index_type(sea_query::IndexType::BTree)
            .to_owned();
        let query = idx.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        Ok(())
    }

    async fn create_grant_sessions_table(
        &self,
        tx: &mut Transaction<'static, sqlx::Postgres>,
    ) -> anyhow::Result<()> {
        let statement = Table::create()
            .table(GRANT_SESSIONS_TABLE)
            .if_not_exists()
            .col(
                ColumnDef::new(GrantSessionIden::Id)
                    .integer()
                    .primary_key()
                    .auto_increment(),
            )
            .col(
                ColumnDef::new(GrantSessionIden::TokenHash)
                    .binary_len(32)
                    .not_null()
                    .unique_key(),
            )
            .col(
                ColumnDef::new(GrantSessionIden::GrantId)
                    .string_len(36)
                    .not_null(),
            )
            .col(
                ColumnDef::new(GrantSessionIden::ExpiresAt)
                    .big_integer()
                    .not_null(),
            )
            .col(
                ColumnDef::new(GrantSessionIden::CreatedAt)
                    .timestamp()
                    .not_null()
                    .default(Expr::current_timestamp()),
            )
            .to_owned();
        let query = statement.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Foreign key: grant_id → grants.id
        let fk = ForeignKey::create()
            .name("fk_grant_session_grant")
            .from(GRANT_SESSIONS_TABLE, GrantSessionIden::GrantId)
            .to(GRANTS_TABLE, GrantIden::Id)
            .on_delete(ForeignKeyAction::Cascade)
            .to_owned();
        let query = fk.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        // Index on grant_id
        let idx = sea_query::Index::create()
            .name("idx_grant_sessions_grant_id")
            .table(GRANT_SESSIONS_TABLE)
            .col(GrantSessionIden::GrantId)
            .index_type(sea_query::IndexType::BTree)
            .to_owned();
        let query = idx.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        Ok(())
    }

    async fn create_pop_nonces_table(
        &self,
        tx: &mut Transaction<'static, sqlx::Postgres>,
    ) -> anyhow::Result<()> {
        let statement = Table::create()
            .table(POP_NONCES_TABLE)
            .if_not_exists()
            .col(
                ColumnDef::new(PopNonceIden::Nonce)
                    .string_len(36)
                    .primary_key(),
            )
            .col(
                ColumnDef::new(PopNonceIden::CreatedAt)
                    .timestamp()
                    .not_null()
                    .default(Expr::current_timestamp()),
            )
            .to_owned();
        let query = statement.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        let idx = sea_query::Index::create()
            .name("idx_pop_nonces_created_at")
            .table(POP_NONCES_TABLE)
            .col(PopNonceIden::CreatedAt)
            .index_type(sea_query::IndexType::BTree)
            .to_owned();
        let query = idx.build(PostgresQueryBuilder);
        sqlx::query(query.as_str()).execute(&mut **tx).await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum GrantIden {
    Id,
    User,
    ClientId,
    ClientCnfKey,
    Capabilities,
    IssuedAt,
    ExpiresAt,
    RevokedAt,
    CreatedAt,
}

#[derive(Iden)]
pub enum GrantSessionIden {
    Id,
    TokenHash,
    GrantId,
    ExpiresAt,
    CreatedAt,
}

#[derive(Iden)]
pub enum PopNonceIden {
    Nonce,
    CreatedAt,
}
