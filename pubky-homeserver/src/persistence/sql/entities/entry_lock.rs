//! Exclusive WebDAV write locks on storage paths.
//!
//! One row per locked path. A row whose `expires_at` has passed is dead: it is
//! ignored by every read and overwritten by the next acquisition. Nothing
//! removes dead rows eagerly; [`EntryLockRepository::delete_expired`] sweeps
//! them on each `LOCK` request.
//!
//! A write or delete under a lock reserves it for the time its change may still
//! reach the storage backend, see [`EntryLockRepository::reserve_publish`].
//! `publishing_until` records that time. Until it has passed the lock can
//! neither be released nor reserved again, and it cannot run out either: the
//! reservation extends the lock to outlast it, and a refresh never shortens a
//! reserved lock. Nothing else can hand the path to another writer, so a
//! reserved change can never land on top of a later holder's.
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
    /// Unix seconds until which a change under the lock may still reach the
    /// storage backend. Zero when nothing is reserved. Never later than
    /// `expires_at`.
    PublishingUntil,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryLockEntity {
    pub path: String,
    pub token: String,
    pub expires_at: i64,
    pub publishing_until: i64,
}

impl FromRow<'_, PgRow> for EntryLockEntity {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            path: row.try_get(EntryLockIden::Path.to_string().as_str())?,
            token: row.try_get(EntryLockIden::Token.to_string().as_str())?,
            expires_at: row.try_get(EntryLockIden::ExpiresAt.to_string().as_str())?,
            publishing_until: row.try_get(EntryLockIden::PublishingUntil.to_string().as_str())?,
        })
    }
}

/// What an `UNLOCK` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseOutcome {
    Released,
    /// A change under the lock may still reach the backend for this many
    /// more seconds, at least one; the lock stays until then.
    Reserved {
        remaining_secs: i64,
    },
    /// No lock with that token on the path.
    NotHeld,
}

/// Unix seconds on the database clock. Fixed for the statement, so one
/// statement sees one instant. Not `now()`, which is fixed for the whole
/// transaction: a statement late in a long transaction would see a lock that
/// expired since the transaction began as still live.
fn db_now() -> SimpleExpr {
    Expr::cust("EXTRACT(EPOCH FROM STATEMENT_TIMESTAMP())::BIGINT")
}

/// The database clock `seconds` from now.
fn db_now_plus(seconds: i64) -> SimpleExpr {
    db_now().add(seconds)
}

fn all_columns() -> [EntryLockIden; 4] {
    [
        EntryLockIden::Path,
        EntryLockIden::Token,
        EntryLockIden::ExpiresAt,
        EntryLockIden::PublishingUntil,
    ]
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
            .columns(all_columns())
            .values(vec![
                SimpleExpr::Value(path.as_str().into()),
                SimpleExpr::Value(token.into()),
                db_now_plus(lifetime_secs),
                SimpleExpr::Value(0i64.into()),
            ])
            .expect("invariant: values count matches columns count")
            .on_conflict(
                OnConflict::column(EntryLockIden::Path)
                    .update_columns([
                        EntryLockIden::Token,
                        EntryLockIden::ExpiresAt,
                        EntryLockIden::PublishingUntil,
                    ])
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
            .columns(all_columns())
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .and_where(Expr::col(EntryLockIden::ExpiresAt).gt(db_now()))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values)
            .fetch_optional(con)
            .await
    }

    /// Reserve the live lock held with `token` for a change to the file that
    /// may reach the backend during the next `window_secs`. The lock is
    /// extended to last at least that long, and until the window has passed
    /// it can be neither released nor reserved again. Returns `None` when
    /// `token` holds no live lock on `path`, or when an earlier reservation
    /// is still running.
    ///
    /// One statement, outside any transaction of the caller: the reservation
    /// must survive whatever happens to the change's own transaction.
    pub async fn reserve_publish<'a>(
        path: &EntryPath,
        token: &str,
        window_secs: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Option<EntryLockEntity>, sqlx::Error> {
        let outlasts_window = Func::greatest([
            Expr::col(EntryLockIden::ExpiresAt),
            db_now_plus(window_secs),
        ]);
        let statement = Query::update()
            .table(ENTRY_LOCK_TABLE)
            .value(EntryLockIden::ExpiresAt, outlasts_window)
            .value(EntryLockIden::PublishingUntil, db_now_plus(window_secs))
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .and_where(Expr::col(EntryLockIden::Token).eq(token))
            .and_where(Expr::col(EntryLockIden::ExpiresAt).gt(db_now()))
            .and_where(Expr::col(EntryLockIden::PublishingUntil).lte(db_now()))
            .returning_all()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values)
            .fetch_optional(con)
            .await
    }

    /// Seconds the reservation on the live lock held with `token` still has.
    /// Zero or less when nothing is reserved. `None` when `token` holds no
    /// live lock on `path`.
    pub async fn publish_window_remaining<'a>(
        path: &EntryPath,
        token: &str,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Option<i64>, sqlx::Error> {
        let statement = Query::select()
            .from(ENTRY_LOCK_TABLE)
            .expr(Expr::col(EntryLockIden::PublishingUntil).sub(db_now()))
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .and_where(Expr::col(EntryLockIden::Token).eq(token))
            .and_where(Expr::col(EntryLockIden::ExpiresAt).gt(db_now()))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_scalar_with::<_, i64, _>(&query, values)
            .fetch_optional(con)
            .await
    }

    /// Push the reservation that ends at `publishing_until` on the lock held
    /// with `token` out to a full `window_secs` from now, while the change's
    /// backend request is still being waited for. Returns `None` when that
    /// reservation is no longer there: it ran out and another change took
    /// one, or the lock is gone.
    ///
    /// A reservation is told from a later one by when it ends: every
    /// reservation is taken after the one before it ran out, and extended
    /// only forward, so a later change's always ends later. One that ends
    /// no later than `publishing_until` is this change's.
    pub async fn extend_publish<'a>(
        path: &EntryPath,
        token: &str,
        publishing_until: i64,
        window_secs: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Option<EntryLockEntity>, sqlx::Error> {
        let outlasts_window = Func::greatest([
            Expr::col(EntryLockIden::ExpiresAt),
            db_now_plus(window_secs),
        ]);
        let statement = Query::update()
            .table(ENTRY_LOCK_TABLE)
            .value(EntryLockIden::ExpiresAt, outlasts_window)
            .value(EntryLockIden::PublishingUntil, db_now_plus(window_secs))
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .and_where(Expr::col(EntryLockIden::Token).eq(token))
            .and_where(Expr::col(EntryLockIden::PublishingUntil).lte(publishing_until))
            .and_where(Expr::col(EntryLockIden::ExpiresAt).gt(db_now()))
            .returning_all()
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_as_with(&query, values)
            .fetch_optional(con)
            .await
    }

    /// End the reservation that ends at `publishing_until` on the lock held
    /// with `token`. Only for a change that can no longer reach the backend:
    /// one that was published, or was refused before anything was sent. A
    /// change whose request is still out there leaves its reservation to run
    /// out on its own.
    ///
    /// Only that reservation, told from a later one as in
    /// [`Self::extend_publish`]: a change that outran its window must not end
    /// the reservation a later change has taken since.
    pub async fn end_publish<'a>(
        path: &EntryPath,
        token: &str,
        publishing_until: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let statement = Query::update()
            .table(ENTRY_LOCK_TABLE)
            .value(EntryLockIden::PublishingUntil, 0i64)
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .and_where(Expr::col(EntryLockIden::Token).eq(token))
            .and_where(Expr::col(EntryLockIden::PublishingUntil).lte(publishing_until))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_with(&query, values).execute(con).await?;
        Ok(())
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

    /// Make the reservation on `path` end `remaining_secs` from now, as if
    /// that much of its window had already been used up.
    #[cfg(test)]
    pub async fn set_publish_window<'a>(
        path: &EntryPath,
        remaining_secs: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<(), sqlx::Error> {
        let statement = Query::update()
            .table(ENTRY_LOCK_TABLE)
            .value(EntryLockIden::PublishingUntil, db_now_plus(remaining_secs))
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        sqlx::query_with(&query, values).execute(con).await?;
        Ok(())
    }

    /// Restart the lifetime of the live lock on `path` held with one of
    /// `tokens` to `lifetime_secs`, or to the end of its reservation if that
    /// is later. Returns `None` when no such lock exists.
    pub async fn refresh<'a>(
        path: &EntryPath,
        tokens: &[String],
        lifetime_secs: i64,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<Option<EntryLockEntity>, sqlx::Error> {
        let outlasts_reservation = Func::greatest([
            db_now_plus(lifetime_secs),
            Expr::col(EntryLockIden::PublishingUntil),
        ]);
        let statement = Query::update()
            .table(ENTRY_LOCK_TABLE)
            .value(EntryLockIden::ExpiresAt, outlasts_reservation)
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

    /// Remove the lock held with `token` on `path`, expired or not, unless a
    /// change under it is still reserved.
    ///
    /// The reservation check is part of the `DELETE` itself, so it cannot be
    /// interleaved with a reservation being taken.
    pub async fn release<'a>(
        path: &EntryPath,
        token: &str,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<ReleaseOutcome, sqlx::Error> {
        let statement = Query::delete()
            .from_table(ENTRY_LOCK_TABLE)
            .and_where(Expr::col(EntryLockIden::Path).eq(path.as_str()))
            .and_where(Expr::col(EntryLockIden::Token).eq(token))
            .and_where(Expr::col(EntryLockIden::PublishingUntil).lte(db_now()))
            .to_owned();
        let (query, values) = statement.build_sqlx(PostgresQueryBuilder);
        let con = executor.get_con().await?;
        let result = sqlx::query_with(&query, values).execute(con).await?;
        if result.rows_affected() > 0 {
            return Ok(ReleaseOutcome::Released);
        }
        Ok(
            match Self::publish_window_remaining(path, token, executor).await? {
                Some(remaining_secs) if remaining_secs > 0 => {
                    ReleaseOutcome::Reserved { remaining_secs }
                }
                _ => ReleaseOutcome::NotHeld,
            },
        )
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
    use std::{sync::Arc, time::Duration};

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

    async fn release(db: &SqlDb, path: &EntryPath, token: &str) -> ReleaseOutcome {
        EntryLockRepository::release(path, token, &mut db.pool().into())
            .await
            .unwrap()
    }

    async fn remaining(db: &SqlDb, path: &EntryPath, token: &str) -> Option<i64> {
        EntryLockRepository::publish_window_remaining(path, token, &mut db.pool().into())
            .await
            .unwrap()
    }

    async fn end_publish(db: &SqlDb, path: &EntryPath, token: &str, publishing_until: i64) {
        EntryLockRepository::end_publish(path, token, publishing_until, &mut db.pool().into())
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
        assert_eq!(first.publishing_until, 0);
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

    /// A reserved lock outlasts its window and cannot change hands before the
    /// window has passed: not by running out, not by `UNLOCK`, not by a
    /// refresh asking for less, and not by a second reservation.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn reserved_lock_cannot_change_hands_until_its_window_ends() {
        let db = SqlDb::test().await;
        let path = path("/pub/a.txt");
        // Lifetimes are whole seconds, so a one-second lock can be dead
        // almost at once; two is the shortest that surely outlives the next
        // statement.
        let granted = EntryLockRepository::acquire(&path, "t1", 2, &mut db.pool().into())
            .await
            .unwrap()
            .expect("the lock should be free");
        assert!(remaining(&db, &path, "t1").await.unwrap() <= 0);

        let reserved = EntryLockRepository::reserve_publish(&path, "t1", 60, &mut db.pool().into())
            .await
            .unwrap()
            .expect("the live lock can be reserved");
        assert!(reserved.expires_at >= granted.expires_at + 58);
        assert_eq!(reserved.expires_at, reserved.publishing_until);
        let window = remaining(&db, &path, "t1").await.unwrap();
        assert!((59..=60).contains(&window));

        // The granted seconds have passed; the reservation keeps the lock.
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(live(&db, &path).await.is_some());
        assert!(
            EntryLockRepository::acquire(&path, "t2", 60, &mut db.pool().into())
                .await
                .unwrap()
                .is_none(),
            "a reserved lock must not be replaced"
        );
        assert!(matches!(
            release(&db, &path, "t1").await,
            ReleaseOutcome::Reserved { remaining_secs } if (1..=60).contains(&remaining_secs)
        ));
        assert!(
            EntryLockRepository::reserve_publish(&path, "t1", 60, &mut db.pool().into())
                .await
                .unwrap()
                .is_none(),
            "a reserved lock must not be reserved again"
        );
        let refreshed =
            EntryLockRepository::refresh(&path, &tokens(&["t1"]), 1, &mut db.pool().into())
                .await
                .unwrap()
                .expect("the holder can still refresh");
        assert_eq!(refreshed.expires_at, reserved.publishing_until);

        // Over: the lock is back to the holder's, and ends when told to.
        end_publish(&db, &path, "t1", reserved.publishing_until).await;
        assert!(remaining(&db, &path, "t1").await.unwrap() <= 0);
        let again = EntryLockRepository::reserve_publish(&path, "t1", 60, &mut db.pool().into())
            .await
            .unwrap()
            .expect("an ended reservation can be taken again");
        end_publish(&db, &path, "t1", again.publishing_until).await;
        assert_eq!(release(&db, &path, "t1").await, ReleaseOutcome::Released);
        assert_eq!(remaining(&db, &path, "t1").await, None);
    }

    /// Only the token of the live lock can reserve it. A refresh asking for
    /// more than the reservation gets it.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn reservation_needs_the_live_lock_and_refresh_can_still_lengthen_it() {
        let db = SqlDb::test().await;
        let path = path("/pub/a.txt");
        let reserve = |token: &'static str| {
            let (db, path) = (db.clone(), path.clone());
            async move {
                EntryLockRepository::reserve_publish(&path, token, 60, &mut db.pool().into())
                    .await
                    .unwrap()
            }
        };

        assert!(reserve("t1").await.is_none(), "no lock, nothing to reserve");
        EntryLockRepository::acquire(&path, "t1", 60, &mut db.pool().into())
            .await
            .unwrap()
            .unwrap();
        assert!(reserve("other").await.is_none());
        let reserved = reserve("t1").await.unwrap();
        let lengthened =
            EntryLockRepository::refresh(&path, &tokens(&["t1"]), 600, &mut db.pool().into())
                .await
                .unwrap()
                .unwrap();
        assert!(lengthened.expires_at >= reserved.publishing_until + 539);
        assert_eq!(lengthened.publishing_until, reserved.publishing_until);

        expire(&db, &path).await;
        assert!(
            reserve("t1").await.is_none(),
            "an expired lock cannot be reserved"
        );
        assert_eq!(remaining(&db, &path, "t1").await, None);
    }

    /// A reservation is extended, and ended, by when it ends. A change that
    /// outran its window neither prolongs nor ends the reservation a later
    /// change has taken since, which ends later.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn reservation_is_extended_and_ended_by_its_own_value_only() {
        let db = SqlDb::test().await;
        let path = path("/pub/a.txt");
        EntryLockRepository::acquire(&path, "t1", 60, &mut db.pool().into())
            .await
            .unwrap()
            .unwrap();
        let first = EntryLockRepository::reserve_publish(&path, "t1", 60, &mut db.pool().into())
            .await
            .unwrap()
            .unwrap();

        let extended = EntryLockRepository::extend_publish(
            &path,
            "t1",
            first.publishing_until,
            600,
            &mut db.pool().into(),
        )
        .await
        .unwrap()
        .expect("the running reservation can be extended");
        assert!(extended.publishing_until >= first.publishing_until + 539);
        assert_eq!(extended.expires_at, extended.publishing_until);
        assert!(
            EntryLockRepository::extend_publish(
                &path,
                "t1",
                first.publishing_until,
                600,
                &mut db.pool().into()
            )
            .await
            .unwrap()
            .is_none(),
            "a stale value extends nothing"
        );

        // The first change's window runs out and a second change reserves.
        EntryLockRepository::set_publish_window(&path, 0, &mut db.pool().into())
            .await
            .unwrap();
        let second = EntryLockRepository::reserve_publish(&path, "t1", 900, &mut db.pool().into())
            .await
            .unwrap()
            .expect("a used-up reservation can be replaced");
        assert!(second.publishing_until > extended.publishing_until);

        // The first change, settling late, must leave the second's alone.
        end_publish(&db, &path, "t1", extended.publishing_until).await;
        assert!(matches!(
            release(&db, &path, "t1").await,
            ReleaseOutcome::Reserved { .. }
        ));
        end_publish(&db, &path, "t1", second.publishing_until).await;
        assert_eq!(release(&db, &path, "t1").await, ReleaseOutcome::Released);
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
        // One of several presented tokens is enough.
        let refreshed = EntryLockRepository::refresh(
            &path,
            &tokens(&["other", "t1"]),
            600,
            &mut db.pool().into(),
        )
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
        assert_eq!(release(&db, &path, "other").await, ReleaseOutcome::NotHeld);
        assert_eq!(release(&db, &path, "t1").await, ReleaseOutcome::Released);
        assert_eq!(release(&db, &path, "t1").await, ReleaseOutcome::NotHeld);

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
