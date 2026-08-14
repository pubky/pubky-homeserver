use async_trait::async_trait;
use pubky_common::capabilities::Capabilities;
use sqlx::{Row, Transaction};

use crate::persistence::sql::migration::MigrationTrait;

const BATCH_SIZE: i64 = 1_000;

/// Deletes sessions with invalid capabilities and normalizes valid capabilities.
pub struct M20260723SanitizeCapabilitiesMigration;

#[async_trait]
impl MigrationTrait for M20260723SanitizeCapabilitiesMigration {
    async fn up(&self, tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
        sanitize_sessions(tx).await?;
        // No need to santize grants as they do not exist yet at the creation of this migration.
        Ok(())
    }

    fn name(&self) -> &str {
        "m20260723_sanitize_capabilities"
    }
}

async fn sanitize_sessions(tx: &mut Transaction<'static, sqlx::Postgres>) -> anyhow::Result<()> {
    let mut last_id = 0;

    loop {
        let rows =
            sqlx::query("SELECT id, capabilities FROM sessions WHERE id > $1 ORDER BY id LIMIT $2")
                .bind(last_id)
                .bind(BATCH_SIZE)
                .fetch_all(&mut **tx)
                .await?;
        if rows.is_empty() {
            break;
        }

        let mut ids = Vec::new();
        let mut values = Vec::new();
        let mut invalid_ids = Vec::new();
        for row in rows {
            let id: i32 = row.try_get("id")?;
            let original: String = row.try_get("capabilities")?;
            last_id = id;

            match normalize_capabilities(&original) {
                Some(normalized) if normalized != original => {
                    ids.push(id);
                    values.push(normalized);
                }
                Some(_) => {}
                None => invalid_ids.push(id),
            }
        }

        if !ids.is_empty() {
            sqlx::query(
                "UPDATE sessions AS target SET capabilities = source.capabilities FROM UNNEST($1::INTEGER[], $2::TEXT[]) AS source(id, capabilities) WHERE target.id = source.id",
            )
            .bind(ids)
            .bind(values)
            .execute(&mut **tx)
            .await?;
        }

        if !invalid_ids.is_empty() {
            sqlx::query("DELETE FROM sessions WHERE id = ANY($1::INTEGER[])")
                .bind(invalid_ids)
                .execute(&mut **tx)
                .await?;
        }
    }

    Ok(())
}

fn normalize_capabilities(value: &str) -> Option<String> {
    value
        .parse::<Capabilities>()
        .ok()
        .map(|capabilities| capabilities.normalize().to_string())
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Keypair;

    use crate::persistence::sql::{
        migrations::{M20250806CreateUserMigration, M20250813CreateSessionMigration},
        migrator::Migrator,
        SqlDb,
    };

    use super::*;

    const CASES: [(&str, Option<&str>); 13] = [
        ("/foo:r", Some("/foo:r")),
        ("/foo:r,/bar:wr", Some("/foo:r,/bar:rw")),
        ("/foo:r,/foo:w", Some("/foo:rw")),
        ("/pub/:rw,/pub/file:r", Some("/pub/:rw")),
        ("", Some("")),
        ("/foo:", None),
        ("/foo:,/bar:r", None),
        ("/pub//app/:w,/bar:r", None),
        ("/pub/a/../b/:w", None),
        ("/foo,/bar:w", None),
        ("/foo:r,,/bar:w", None),
        ("/priv/report :w", None),
        ("/priv/app\\..\\secret:w", None),
    ];

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn normalizes_valid_sessions_and_deletes_invalid_sessions() {
        let db = SqlDb::test_without_migrations().await;
        let migrator = Migrator::new(&db);
        migrator
            .run_migrations(vec![
                Box::new(M20250806CreateUserMigration),
                Box::new(M20250813CreateSessionMigration),
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
        }

        migrator
            .run_migrations(vec![Box::new(M20260723SanitizeCapabilitiesMigration)])
            .await
            .unwrap();

        let sessions: Vec<(String, String)> =
            sqlx::query_as("SELECT secret, capabilities FROM sessions ORDER BY secret")
                .fetch_all(db.pool())
                .await
                .unwrap();
        let expected: Vec<(String, String)> = CASES
            .iter()
            .enumerate()
            .filter_map(|(index, (_, expected))| {
                expected.map(|value| (format!("{index:026}"), value.to_string()))
            })
            .collect();
        assert_eq!(sessions, expected);
    }
}
