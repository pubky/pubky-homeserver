use async_trait::async_trait;
use sqlx::Transaction;

use crate::persistence::sql::migration::MigrationTrait;

/// Records delegation parents, their child grants, and blocked apps.
///
/// Existing rows become direct grants through the column default, so they keep
/// working without a data rewrite. Revoked and replaced grants stay in the table
/// and fall outside the partial index, so one app can have many past children
/// but only one that isn't revoked.
pub struct M20261103AddGrantDelegationMigration;

#[async_trait]
impl MigrationTrait for M20261103AddGrantDelegationMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        for statement in [
            "ALTER TABLE grants
                ADD COLUMN kind VARCHAR(16) NOT NULL DEFAULT 'direct',
                ADD COLUMN parent_id VARCHAR(36) REFERENCES grants (id) ON DELETE CASCADE,
                ADD CONSTRAINT chk_grants_kind CHECK (kind IN ('direct', 'delegation', 'child')),
                ADD CONSTRAINT chk_grants_parent CHECK ((kind = 'child') = (parent_id IS NOT NULL))",
            "CREATE INDEX idx_grants_parent_id ON grants (parent_id)",
            r#"CREATE UNIQUE INDEX uq_grants_active_child ON grants ("user", parent_id, client_id)
                WHERE kind = 'child' AND revoked_at IS NULL"#,
            r#"CREATE TABLE grant_app_blocks (
                "user" INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                parent_id VARCHAR(36) NOT NULL REFERENCES grants (id) ON DELETE CASCADE,
                client_id VARCHAR(253) NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY ("user", parent_id, client_id)
            )"#,
            "CREATE INDEX idx_grant_app_blocks_parent_id ON grant_app_blocks (parent_id)",
        ] {
            sqlx::query(statement).execute(&mut **tx).await?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "m20261103_add_grant_delegation"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::{
        migrations::{M20250806CreateUserMigration, M20260325CreateGrantSessionsMigration},
        migrator::Migrator,
        SqlDb,
    };
    use pubky_common::crypto::Keypair;

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn existing_grants_become_direct_and_keep_their_sessions() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20260325CreateGrantSessionsMigration),
            ])
            .await
            .unwrap();

        let user_id: i32 =
            sqlx::query_scalar("INSERT INTO users (public_key) VALUES ($1) RETURNING id")
                .bind(Keypair::random().public_key().z32())
                .fetch_one(db.pool())
                .await
                .unwrap();
        sqlx::query(
            r#"INSERT INTO grants (id, "user", client_id, client_cnf_key, capabilities, issued_at, expires_at)
               VALUES ('old', $1, 'old.app', 'key', '/:rw', 1, 2)"#,
        )
        .bind(user_id)
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO grant_sessions (token_hash, grant_id, expires_at) VALUES ($1, 'old', 2)",
        )
        .bind(vec![0u8; 32])
        .execute(db.pool())
        .await
        .unwrap();

        migrator
            .run_migrations(vec![Box::new(M20261103AddGrantDelegationMigration)])
            .await
            .unwrap();

        let (kind, parent_id): (String, Option<String>) =
            sqlx::query_as("SELECT kind, parent_id FROM grants WHERE id = 'old'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(kind, "direct");
        assert_eq!(parent_id, None);
        let sessions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM grant_sessions WHERE grant_id = 'old'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(sessions, 1);
    }
}
