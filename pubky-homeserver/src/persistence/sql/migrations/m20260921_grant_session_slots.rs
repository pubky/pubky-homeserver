use async_trait::async_trait;
use sqlx::Transaction;

use crate::persistence::sql::migration::MigrationTrait;

/// Independent session slots and a shared issuance budget per grant.
pub struct M20260921GrantSessionSlotsMigration;

#[async_trait]
impl MigrationTrait for M20260921GrantSessionSlotsMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        for statement in [
            "ALTER TABLE grant_sessions ADD COLUMN session_id VARCHAR(22)",
            // Preserve every existing bearer, including rows from concurrent legacy exchanges.
            "WITH ranked AS (
                 SELECT id, row_number() OVER (PARTITION BY grant_id ORDER BY id DESC) AS n
                 FROM grant_sessions
             )
             UPDATE grant_sessions SET session_id = 'migrated-' || grant_sessions.id
             FROM ranked WHERE grant_sessions.id = ranked.id AND ranked.n > 1",
            "CREATE UNIQUE INDEX idx_grant_session_slot
                 ON grant_sessions (grant_id, COALESCE(session_id, ''))",
            "CREATE INDEX idx_grant_sessions_expiry ON grant_sessions (expires_at)",
            "ALTER TABLE grants ADD COLUMN session_window_start BIGINT NOT NULL DEFAULT 0",
            "ALTER TABLE grants ADD COLUMN session_window_count BIGINT NOT NULL DEFAULT 0",
        ] {
            sqlx::query(statement).execute(&mut **tx).await?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "m20260921_grant_session_slots"
    }
}

#[cfg(test)]
mod tests {
    use crate::client_server::auth::grant::persistence::grant::{GrantRepository, NewGrant};
    use crate::persistence::sql::{migrations::*, migrator::Migrator, SqlDb};
    use crate::services::user_service::UserService;
    use pubky_common::{
        auth::jws::{ClientId, GrantId},
        capabilities::{Capabilities, Capability},
        crypto::Keypair,
    };

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn upgrade_preserves_existing_bearers_and_legacy_race_rows() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
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
            ])
            .await
            .unwrap();
        let key = Keypair::random().public_key();
        let user = UserService::new(db.clone()).create(&key).await.unwrap();
        let grant = NewGrant {
            id: GrantId::generate(),
            user_id: user.id,
            client_id: ClientId::new("upgrade.test").unwrap(),
            client_cnf_key: Keypair::random().public_key().z32(),
            capabilities: Capabilities::builder().cap(Capability::root()).finish(),
            issued_at: 1,
            expires_at: 4_000_000_000,
        };
        GrantRepository::create(&grant, &mut db.pool().into())
            .await
            .unwrap();
        for hash in [vec![1_u8; 32], vec![2_u8; 32]] {
            sqlx::query(
                "INSERT INTO grant_sessions(token_hash, grant_id, expires_at) VALUES ($1, $2, $3)",
            )
            .bind(hash)
            .bind(grant.id.to_string())
            .bind(4_000_000_000_i64)
            .execute(db.pool())
            .await
            .unwrap();
        }
        migrator.run().await.unwrap();
        migrator.run().await.unwrap();
        let hashes: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT token_hash FROM grant_sessions ORDER BY id")
                .fetch_all(db.pool())
                .await
                .unwrap();
        assert_eq!(hashes, vec![vec![1_u8; 32], vec![2_u8; 32]]);
        let slots: Vec<Option<String>> =
            sqlx::query_scalar("SELECT session_id FROM grant_sessions ORDER BY id")
                .fetch_all(db.pool())
                .await
                .unwrap();
        assert!(slots[0].is_some());
        assert!(
            slots[1].is_none(),
            "the latest bearer remains the legacy slot"
        );
        // The new uniqueness constraint also protects against accidental duplicate slots.
        assert!(sqlx::query(
            "INSERT INTO grant_sessions(token_hash, grant_id, expires_at) VALUES ($1, $2, $3)"
        )
        .bind(vec![3_u8; 32])
        .bind(grant.id.to_string())
        .bind(4_000_000_000_i64)
        .execute(db.pool())
        .await
        .is_err());
    }
}
