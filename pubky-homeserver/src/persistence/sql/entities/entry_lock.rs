//! Exclusive WebDAV write locks on storage paths.
//!
//! One row per locked path. A row whose `expires_at` has passed is dead: it is
//! ignored by every read and overwritten by the next acquisition. Nothing
//! removes dead rows eagerly; [`EntryLockRepository::delete_expired`] sweeps
//! them on each `LOCK` request.
//!
//! Every lifetime is measured on the database clock, inside the statement that
//! sets or checks it, so all instances behind one database agree on which locks
//! are live whatever their own clocks say.

use sea_query::{Expr, ExprTrait, Func, Iden, OnConflict, PostgresQueryBuilder, Query, SimpleExpr};
use sea_query_sqlx::SqlxBinder;
use sqlx::{postgres::PgRow, FromRow, Row};

use crate::{persistence::sql::UnifiedExecutor, shared::webdav::EntryPath};

pub const ENTRY_LOCK_TABLE: &str = "entry_locks";

#[derive(Iden)]
pub enum EntryLockIden {
    /// The [`EntryPath`] key: `<pubkey>/<path>`.
    Path,
    /// The opaque lock token (a UUID) that authorizes writes and unlock.
    Token,
    /// Unix seconds after which the lock no longer exists.
    ExpiresAt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryLockEntity {
    pub path: String,
    pub token: String,
    pub expires_at: i64,
}

impl FromRow<'_, PgRow> for EntryLockEntity {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            path: row.try_get(EntryLockIden::Path.to_string().as_str())?,
            token: row.try_get(EntryLockIden::Token.to_string().as_str())?,
            expires_at: row.try_get(EntryLockIden::ExpiresAt.to_string().as_str())?,
        })
    }
}

/// Unix seconds on the database clock. `now()` is fixed for the statement, so
/// one statement sees one instant.
fn db_now() -> SimpleExpr {
    Expr::cust("EXTRACT(EPOCH FROM NOW())::BIGINT")
}

/// The database clock `seconds` from now.
fn db_now_plus(seconds: i64) -> SimpleExpr {
    db_now().add(seconds)
}

pub struct EntryLockRepository;

impl EntryLockRepository {
    /// Take the lock on `path` with `token` for `lifetime_secs`, replacing an
    /// expired lock if one is there. Returns `None` when a live lock exists.
    ///
    /// A single `INSERT ... ON CONFLICT DO UPDATE ... WHERE expired` statement,
    /// so two racing acquisitions cannot both succeed.
    pub async fn acquire<'a>(
        path: &EntryPath,
        token: &str,
        lifetime_secs: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Option<EntryLockEntity>, sqlx::Error> {
        let statement = Query::insert()
            .into_table(ENTRY_LOCK_TABLE)
            .columns([
                EntryLockIden::Path,
                EntryLockIden::Token,
                EntryLockIden::ExpiresAt,
            ])
            .values(vec![
                SimpleExpr::Value(path.as_str().into()),
                SimpleExpr::Value(token.into()),
                db_now_plus(lifetime_secs),
            ])
            .expect("invariant: values count matches columns count")
            .on_conflict(
                OnConflict::column(EntryLockIden::Path)
                    .update_columns([EntryLockIden::Token, EntryLockIden::ExpiresAt])
                    .action_and_where(
                        Expr::col((ENTRY_LOCK_TABLE, EntryLockIden::ExpiresAt)).lte(db_now()),
                    )
                    .to_owned(),
            )
            .returning_all()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values)
            .fetch_optional(con)
            .await
    }

    /// The live lock on `path`, if any.
    pub async fn get_active<'a>(
        path: &EntryPath,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Option<EntryLockEntity>, sqlx::Error> {
        let statement = Query::select()
            .from(ENTRY_LOCK_TABLE)
            .columns([
                EntryLockIden::Path,
                EntryLockIden::Token,
                EntryLockIden::ExpiresAt,
            ])
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .and_where(Expr::col(EntryLockIden::ExpiresAt).gt(db_now()))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values)
            .fetch_optional(con)
            .await
    }

    /// Backdate the lock on `path` so it counts as expired.
    #[cfg(test)]
    pub async fn expire<'a>(
        path: &EntryPath,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let statement = Query::update()
            .table(ENTRY_LOCK_TABLE)
            .value(EntryLockIden::ExpiresAt, db_now().sub(1))
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_with(&query, values).execute(con).await?;
        Ok(())
    }

    /// Restart the lifetime of the live lock on `path` held with one of
    /// `tokens` to `lifetime_secs`. Returns `None` when no such lock exists.
    pub async fn refresh<'a>(
        path: &EntryPath,
        tokens: &[String],
        lifetime_secs: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Option<EntryLockEntity>, sqlx::Error> {
        Self::set_expiry_of_live_lock(path, tokens, db_now_plus(lifetime_secs), executor).await
    }

    /// Make the live lock on `path` held with one of `tokens` last at least
    /// `horizon_secs` more, never shortening it. Returns `None` when no such
    /// lock exists.
    pub async fn keep_alive<'a>(
        path: &EntryPath,
        tokens: &[String],
        horizon_secs: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Option<EntryLockEntity>, sqlx::Error> {
        let expires_at = Func::greatest([
            Expr::col(EntryLockIden::ExpiresAt),
            db_now_plus(horizon_secs),
        ]);
        Self::set_expiry_of_live_lock(path, tokens, expires_at.into(), executor).await
    }

    /// One statement that both finds the live lock by token and updates it, so
    /// a caller that gets a lock back holds it.
    async fn set_expiry_of_live_lock<'a>(
        path: &EntryPath,
        tokens: &[String],
        expires_at: SimpleExpr,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Option<EntryLockEntity>, sqlx::Error> {
        let statement = Query::update()
            .table(ENTRY_LOCK_TABLE)
            .value(EntryLockIden::ExpiresAt, expires_at)
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .and_where(Expr::col(EntryLockIden::Token).is_in(tokens))
            .and_where(Expr::col(EntryLockIden::ExpiresAt).gt(db_now()))
            .returning_all()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values)
            .fetch_optional(con)
            .await
    }

    /// Remove the lock held with `token` on `path`, expired or not. Returns
    /// whether a row was removed.
    pub async fn release<'a>(
        path: &EntryPath,
        token: &str,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<bool, sqlx::Error> {
        let statement = Query::delete()
            .from_table(ENTRY_LOCK_TABLE)
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .and_where(Expr::col(EntryLockIden::Token).eq(token))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let result = sqlx::query_with(&query, values).execute(con).await?;
        Ok(result.rows_affected() > 0)
    }

    /// Sweep every expired lock.
    pub async fn delete_expired<'a>(
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<u64, sqlx::Error> {
        let statement = Query::delete()
            .from_table(ENTRY_LOCK_TABLE)
            .and_where(Expr::col(EntryLockIden::ExpiresAt).lte(db_now()))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let result = sqlx::query_with(&query, values).execute(con).await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures_util::future::join_all;
    use pubky_common::crypto::Keypair;
    use tokio::sync::Barrier;

    use super::*;
    use crate::{persistence::sql::SqlDb, shared::webdav::StoragePath};

    fn path(name: &str) -> EntryPath {
        EntryPath::new(
            Keypair::random().public_key(),
            StoragePath::new(name).unwrap(),
        )
    }

    fn tokens(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| String::from(*name)).collect()
    }

    async fn live(db: &SqlDb, path: &EntryPath) -> Option<EntryLockEntity> {
        EntryLockRepository::get_active(path, &mut db.pool().into())
            .await
            .unwrap()
    }

    async fn expire(db: &SqlDb, path: &EntryPath) {
        EntryLockRepository::expire(path, &mut db.pool().into())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn acquire_refuses_live_lock_and_replaces_expired_lock() {
        let db = SqlDb::test().await;
        let path = path("/pub/a.txt");

        let first = EntryLockRepository::acquire(&path, "t1", 60, &mut db.pool().into())
            .await
            .unwrap()
            .expect("first lock should be granted");
        assert_eq!(first.token, "t1");
        assert_eq!(live(&db, &path).await.as_ref(), Some(&first));

        let second = EntryLockRepository::acquire(&path, "t2", 60, &mut db.pool().into())
            .await
            .unwrap();
        assert!(second.is_none(), "a live lock must not be replaced");

        expire(&db, &path).await;
        assert!(live(&db, &path).await.is_none());
        let third = EntryLockRepository::acquire(&path, "t3", 60, &mut db.pool().into())
            .await
            .unwrap()
            .expect("an expired lock is replaced");
        assert_eq!(third.token, "t3");
        assert_eq!(live(&db, &path).await, Some(third));
    }

    /// Acquisition is one atomic statement: of many acquirers racing for a
    /// path, exactly one gets the lock, whether the row is absent or expired.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn racing_acquisitions_grant_exactly_one_lock() {
        let db = SqlDb::test().await;
        let path = path("/pub/a.txt");
        let race = || {
            let (db, path) = (db.clone(), path.clone());
            async move {
                let racers = 8;
                let barrier = Arc::new(Barrier::new(racers));
                let acquisitions = (0..racers).map(|i| {
                    let (db, path, barrier) = (db.clone(), path.clone(), barrier.clone());
                    tokio::spawn(async move {
                        barrier.wait().await;
                        let token = format!("t{i}");
                        EntryLockRepository::acquire(&path, &token, 60, &mut db.pool().into())
                            .await
                            .unwrap()
                    })
                });
                let granted: Vec<EntryLockEntity> = join_all(acquisitions)
                    .await
                    .into_iter()
                    .filter_map(|joined| joined.unwrap())
                    .collect();
                granted
            }
        };

        let granted = race().await;
        assert_eq!(granted.len(), 1, "exactly one racer takes a free path");

        // With the lock expired, exactly one racer replaces it.
        expire(&db, &path).await;
        let granted = race().await;
        assert_eq!(
            granted.len(),
            1,
            "exactly one racer replaces an expired lock"
        );
        assert_eq!(live(&db, &path).await.as_ref(), granted.first());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn keep_alive_only_extends_the_live_lock_of_its_token() {
        let db = SqlDb::test().await;
        let path = path("/pub/a.txt");
        let expires_at = || async { live(&db, &path).await.map(|lock| lock.expires_at) };
        let first = EntryLockRepository::acquire(&path, "t1", 60, &mut db.pool().into())
            .await
            .unwrap()
            .unwrap();

        // Extends a lock that ends sooner, leaves one that ends later alone.
        let keep = |held: &[&str], horizon: i64| {
            let (db, path, held) = (db.clone(), path.clone(), tokens(held));
            async move {
                EntryLockRepository::keep_alive(&path, &held, horizon, &mut db.pool().into())
                    .await
                    .unwrap()
                    .is_some()
            }
        };
        assert!(keep(&["t1"], 90).await);
        let extended = expires_at().await.unwrap();
        assert!(extended > first.expires_at);
        assert!(keep(&["t1"], 30).await);
        assert_eq!(expires_at().await, Some(extended));

        // One of several presented tokens is enough.
        assert!(keep(&["other", "t1"], 120).await);
        assert!(expires_at().await > Some(extended));

        // Another token, or an expired lock, is not kept alive.
        assert!(!keep(&["other"], 600).await);
        expire(&db, &path).await;
        assert!(!keep(&["t1"], 600).await);
        assert_eq!(expires_at().await, None);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn refresh_release_and_sweep() {
        let db = SqlDb::test().await;
        let path = path("/pub/a.txt");
        let first = EntryLockRepository::acquire(&path, "t1", 60, &mut db.pool().into())
            .await
            .unwrap()
            .unwrap();

        let wrong =
            EntryLockRepository::refresh(&path, &tokens(&["other"]), 600, &mut db.pool().into())
                .await
                .unwrap();
        assert!(wrong.is_none());
        let refreshed =
            EntryLockRepository::refresh(&path, &tokens(&["t1"]), 600, &mut db.pool().into())
                .await
                .unwrap()
                .unwrap();
        // From 60 to 600 seconds, give or take a clock tick.
        assert!((539..=541).contains(&(refreshed.expires_at - first.expires_at)));

        // Expired locks are invisible to get_active and refuse a refresh, but
        // can still be released with their token.
        expire(&db, &path).await;
        assert!(live(&db, &path).await.is_none());
        assert!(
            EntryLockRepository::refresh(&path, &tokens(&["t1"]), 60, &mut db.pool().into())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !EntryLockRepository::release(&path, "other", &mut db.pool().into())
                .await
                .unwrap()
        );
        assert!(
            EntryLockRepository::release(&path, "t1", &mut db.pool().into())
                .await
                .unwrap()
        );

        // The sweep removes expired locks only.
        EntryLockRepository::acquire(&path, "t2", 60, &mut db.pool().into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            EntryLockRepository::delete_expired(&mut db.pool().into())
                .await
                .unwrap(),
            0
        );
        expire(&db, &path).await;
        assert_eq!(
            EntryLockRepository::delete_expired(&mut db.pool().into())
                .await
                .unwrap(),
            1
        );
    }
}
