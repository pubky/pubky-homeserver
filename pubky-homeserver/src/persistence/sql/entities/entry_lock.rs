//! Exclusive WebDAV write locks on storage paths.
//!
//! One row per locked path. A row whose `expires_at` has passed is dead: it is
//! ignored by every read and overwritten by the next acquisition. Nothing
//! removes dead rows eagerly; [`EntryLockRepository::delete_expired`] sweeps
//! them on each `LOCK` request.

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

/// Why a write may not proceed against the lock state of its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockViolation {
    /// A live lock exists and the request presented no token.
    Locked,
    /// The request presented tokens, none of which is the live lock.
    TokenMismatch,
}

/// The one decision shared by the route pre-check and the finalization
/// transaction: may a request holding `held` tokens write a path whose live
/// lock is `lock`?
pub fn check_held(lock: Option<&EntryLockEntity>, held: &[String]) -> Result<(), LockViolation> {
    match lock {
        None if held.is_empty() => Ok(()),
        // A token that names no live lock is stale: the client believes it
        // holds a lock it no longer has.
        None => Err(LockViolation::TokenMismatch),
        Some(lock) if held.iter().any(|token| token == &lock.token) => Ok(()),
        Some(_) if held.is_empty() => Err(LockViolation::Locked),
        Some(_) => Err(LockViolation::TokenMismatch),
    }
}

/// Unix seconds; the clock every lock lifetime is measured against.
pub fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub struct EntryLockRepository;

impl EntryLockRepository {
    /// Take the lock on `path` with `token`, replacing an expired lock if one is
    /// there. Returns `None` when a live lock exists.
    ///
    /// A single `INSERT ... ON CONFLICT DO UPDATE ... WHERE expired` statement,
    /// so two racing acquisitions cannot both succeed.
    pub async fn acquire<'a>(
        path: &EntryPath,
        token: &str,
        expires_at: i64,
        now: i64,
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
                SimpleExpr::Value(expires_at.into()),
            ])
            .expect("invariant: values count matches columns count")
            .on_conflict(
                OnConflict::column(EntryLockIden::Path)
                    .update_columns([EntryLockIden::Token, EntryLockIden::ExpiresAt])
                    .action_and_where(
                        Expr::col((ENTRY_LOCK_TABLE, EntryLockIden::ExpiresAt)).lte(now),
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
        now: i64,
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
            .and_where(Expr::col(EntryLockIden::ExpiresAt).gt(now))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values)
            .fetch_optional(con)
            .await
    }

    /// Extend the live lock held with `token` on `path`. Returns `None` when no
    /// such lock exists.
    pub async fn refresh<'a>(
        path: &EntryPath,
        token: &str,
        expires_at: i64,
        now: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Option<EntryLockEntity>, sqlx::Error> {
        let statement = Query::update()
            .table(ENTRY_LOCK_TABLE)
            .value(EntryLockIden::ExpiresAt, expires_at)
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .and_where(Expr::col(EntryLockIden::Token).eq(token))
            .and_where(Expr::col(EntryLockIden::ExpiresAt).gt(now))
            .returning_all()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values)
            .fetch_optional(con)
            .await
    }

    /// Make the live lock held with `token` on `path` last until at least
    /// `until`, never shortening it. Returns whether such a lock exists.
    pub async fn keep_alive<'a>(
        path: &EntryPath,
        token: &str,
        until: i64,
        now: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<bool, sqlx::Error> {
        let statement = Query::update()
            .table(ENTRY_LOCK_TABLE)
            .value(
                EntryLockIden::ExpiresAt,
                Func::greatest([Expr::col(EntryLockIden::ExpiresAt), Expr::val(until)]),
            )
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .and_where(Expr::col(EntryLockIden::Token).eq(token))
            .and_where(Expr::col(EntryLockIden::ExpiresAt).gt(now))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let result = sqlx::query_with(&query, values).execute(con).await?;
        Ok(result.rows_affected() > 0)
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
        now: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<u64, sqlx::Error> {
        let statement = Query::delete()
            .from_table(ENTRY_LOCK_TABLE)
            .and_where(Expr::col(EntryLockIden::ExpiresAt).lte(now))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let result = sqlx::query_with(&query, values).execute(con).await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Keypair;

    use super::*;
    use crate::{persistence::sql::SqlDb, shared::webdav::StoragePath};

    fn path(name: &str) -> EntryPath {
        EntryPath::new(
            Keypair::random().public_key(),
            StoragePath::new(name).unwrap(),
        )
    }

    #[test]
    fn check_held_decides_every_case() {
        let lock = EntryLockEntity {
            path: "p".into(),
            token: "t".into(),
            expires_at: 1,
        };
        let held = |tokens: &[&str]| tokens.iter().map(|t| String::from(*t)).collect::<Vec<_>>();
        assert_eq!(check_held(None, &held(&[])), Ok(()));
        assert_eq!(
            check_held(None, &held(&["t"])),
            Err(LockViolation::TokenMismatch)
        );
        assert_eq!(check_held(Some(&lock), &held(&["x", "t"])), Ok(()));
        assert_eq!(
            check_held(Some(&lock), &held(&[])),
            Err(LockViolation::Locked)
        );
        assert_eq!(
            check_held(Some(&lock), &held(&["x"])),
            Err(LockViolation::TokenMismatch)
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn acquire_refuses_live_lock_and_replaces_expired_lock() {
        let db = SqlDb::test().await;
        let path = path("/pub/a.txt");
        let now = 1_000;

        let first = EntryLockRepository::acquire(&path, "t1", now + 60, now, &mut db.pool().into())
            .await
            .unwrap()
            .expect("first lock should be granted");
        assert_eq!(first.token, "t1");

        let second =
            EntryLockRepository::acquire(&path, "t2", now + 60, now, &mut db.pool().into())
                .await
                .unwrap();
        assert!(second.is_none(), "a live lock must not be replaced");

        let later = now + 61;
        let third =
            EntryLockRepository::acquire(&path, "t3", later + 60, later, &mut db.pool().into())
                .await
                .unwrap()
                .expect("an expired lock is replaced");
        assert_eq!(third.token, "t3");
        assert_eq!(
            EntryLockRepository::get_active(&path, later, &mut db.pool().into())
                .await
                .unwrap(),
            Some(third)
        );
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn refresh_release_and_sweep() {
        let db = SqlDb::test().await;
        let path = path("/pub/a.txt");
        let now = 1_000;
        EntryLockRepository::acquire(&path, "t1", now + 60, now, &mut db.pool().into())
            .await
            .unwrap()
            .unwrap();

        let wrong =
            EntryLockRepository::refresh(&path, "other", now + 600, now, &mut db.pool().into())
                .await
                .unwrap();
        assert!(wrong.is_none());
        let refreshed =
            EntryLockRepository::refresh(&path, "t1", now + 600, now, &mut db.pool().into())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(refreshed.expires_at, now + 600);

        // Expired locks are invisible to get_active but still refuse a refresh.
        let expired = now + 601;
        assert!(
            EntryLockRepository::get_active(&path, expired, &mut db.pool().into())
                .await
                .unwrap()
                .is_none()
        );
        assert!(EntryLockRepository::refresh(
            &path,
            "t1",
            expired + 60,
            expired,
            &mut db.pool().into()
        )
        .await
        .unwrap()
        .is_none());

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

        EntryLockRepository::acquire(&path, "t2", now + 1, now, &mut db.pool().into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            EntryLockRepository::delete_expired(now + 1, &mut db.pool().into())
                .await
                .unwrap(),
            1
        );
    }
}
