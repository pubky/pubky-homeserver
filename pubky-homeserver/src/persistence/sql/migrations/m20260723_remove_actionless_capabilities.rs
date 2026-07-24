use async_trait::async_trait;
use sqlx::Transaction;

use crate::persistence::sql::migration::MigrationTrait;

pub struct M20260723RemoveActionlessCapabilitiesMigration;

#[async_trait]
impl MigrationTrait for M20260723RemoveActionlessCapabilitiesMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        remove_actionless_capabilities(tx, "sessions").await?;
        remove_actionless_capabilities(tx, "grants").await?;
        Ok(())
    }

    fn name(&self) -> &str {
        "m20260723_remove_actionless_capabilities"
    }
}

async fn remove_actionless_capabilities(
    tx: &mut Transaction<'static, sqlx::Postgres>,
    table: &str,
) -> anyhow::Result<()> {
    let query = format!(
        r#"
        WITH cleaned AS (
            SELECT
                source.id,
                COALESCE(
                    string_agg(part.entry, ',' ORDER BY part.ordinality)
                        FILTER (WHERE part.entry !~ '^/[^:]*:$'),
                    ''
                ) AS capabilities
            FROM {table} AS source
            CROSS JOIN LATERAL
                unnest(string_to_array(source.capabilities, ','))
                WITH ORDINALITY AS part(entry, ordinality)
            WHERE source.capabilities ~ '(^|,)/[^,:]*:($|,)'
            GROUP BY source.id
        )
        UPDATE {table} AS target
        SET capabilities = cleaned.capabilities
        FROM cleaned
        WHERE target.id = cleaned.id
        "#
    );

    sqlx::query(&query).execute(&mut **tx).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use pubky_common::{capabilities::Capabilities, crypto::Keypair};

    use crate::persistence::sql::{
        migrations::{
            M20250806CreateUserMigration, M20250813CreateSessionMigration,
            M20260325CreateGrantSessionsMigration,
        },
        migrator::Migrator,
        SqlDb,
    };

    use super::*;

    const CASES: [(&str, &str); 7] = [
        ("/foo:", ""),
        ("/foo:,/bar:r", "/bar:r"),
        ("/bar:r,/foo:", "/bar:r"),
        ("/foo:,/bar:r,/baz:", "/bar:r"),
        ("/foo:r,/bar:rw", "/foo:r,/bar:rw"),
        ("", ""),
        ("/drop:,/b:w,/a:r", "/b:w,/a:r"),
    ];

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn removes_actionless_capabilities_without_removing_records() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250813CreateSessionMigration),
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

        for (index, (input, _)) in CASES.iter().enumerate() {
            sqlx::query(
                "INSERT INTO sessions (secret, \"user\", capabilities) VALUES ($1, $2, $3)",
            )
            .bind(format!("{index:026}"))
            .bind(user_id)
            .bind(input)
            .execute(db.pool())
            .await
            .unwrap();

            sqlx::query(
                "INSERT INTO grants (id, \"user\", client_id, client_cnf_key, capabilities, issued_at, expires_at) VALUES ($1, $2, $3, $4, $5, 1, 2)",
            )
            .bind(format!("{index:036}"))
            .bind(user_id)
            .bind(format!("client-{index}.test"))
            .bind("k".repeat(52))
            .bind(input)
            .execute(db.pool())
            .await
            .unwrap();
        }

        sqlx::query(
            "INSERT INTO grant_sessions (token_hash, grant_id, expires_at) VALUES ($1, $2, 2)",
        )
        .bind(vec![0_u8; 32])
        .bind(format!("{:036}", 0))
        .execute(db.pool())
        .await
        .unwrap();

        migrator
            .run_migrations(vec![Box::new(
                M20260723RemoveActionlessCapabilitiesMigration,
            )])
            .await
            .unwrap();

        let session_capabilities: Vec<String> =
            sqlx::query_scalar("SELECT capabilities FROM sessions ORDER BY secret")
                .fetch_all(db.pool())
                .await
                .unwrap();
        let grant_capabilities: Vec<String> =
            sqlx::query_scalar("SELECT capabilities FROM grants ORDER BY id")
                .fetch_all(db.pool())
                .await
                .unwrap();
        let expected: Vec<String> = CASES
            .iter()
            .map(|(_, expected)| expected.to_string())
            .collect();

        assert_eq!(session_capabilities, expected);
        assert_eq!(grant_capabilities, expected);
        for capabilities in session_capabilities.iter().chain(&grant_capabilities) {
            let _: Capabilities = capabilities.parse().unwrap();
        }

        let grant_session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM grant_sessions")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(grant_session_count, 1);
    }
}
