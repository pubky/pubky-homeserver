//! Service layer for the write locks on storage paths.
//!
//! Grants, refreshes and releases locks, and runs writes under them. The
//! WebDAV side (`LOCK`, `UNLOCK`, the `If` header) lives in the lock route
//! module, which also describes the protocol.

use std::{future::Future, time::Duration};

use tokio::task::JoinHandle;

use crate::persistence::files::write_finalization_layer::write_lock;
use crate::persistence::sql::entry_lock::{EntryLockEntity, EntryLockRepository};
use crate::persistence::sql::{SqlDb, UnifiedExecutor};
use crate::shared::webdav::EntryPath;

/// Lock lifetime granted when the request carries no usable `Timeout`.
pub(crate) const DEFAULT_LOCK_TIMEOUT_SECS: i64 = 30;
/// Longest lock lifetime granted, whatever the client asks for.
pub(crate) const MAX_LOCK_TIMEOUT_SECS: i64 = 60;
/// How far ahead a write in flight keeps its lock alive.
const WRITE_LOCK_HORIZON_SECS: i64 = 30;
/// How often a write in flight extends its lock. Three chances per horizon.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(WRITE_LOCK_HORIZON_SECS as u64 / 3);

/// Domain errors from lock operations.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LockError {
    /// The path is locked and the caller does not hold the lock.
    #[error("Resource is locked")]
    Locked,

    /// The presented tokens name no live lock on the path.
    #[error("No presented token names the live lock on this path")]
    TokenMismatch,

    /// Database error.
    #[error("Database error: {0}")]
    Db(#[from] sqlx::Error),
}

/// Owns the write locks on storage paths.
#[derive(Clone, Debug)]
pub(crate) struct LockService {
    sql_db: SqlDb,
}

impl LockService {
    pub(crate) fn new(sql_db: SqlDb) -> Self {
        Self { sql_db }
    }

    /// Run `write` on `entry_path` if the path's lock allows it.
    ///
    /// - No token and no live lock: the write runs, holding nothing.
    /// - No token and a live lock: [`LockError::Locked`].
    /// - A held token names the live lock: the write runs under that lock,
    ///   which is kept alive until the write ends. Checking and extending the
    ///   lock is one statement, so it cannot expire between the two. The token
    ///   is also handed to the write itself, which is refused if the lock is
    ///   gone by the time it comes to change the file.
    /// - Tokens that name no live lock on this path:
    ///   [`LockError::TokenMismatch`]. A client whose lock expired learns that
    ///   instead of silently writing unlocked.
    pub(crate) async fn run_write<T>(
        &self,
        entry_path: &EntryPath,
        held_tokens: &[String],
        write: impl Future<Output = T>,
    ) -> Result<T, LockError> {
        let (lock_token, _keepalive) = self.check(entry_path, held_tokens).await?.unzip();
        Ok(write_lock::run_under(lock_token, write).await)
    }

    /// The check of [`Self::run_write`], returning the token and keep-alive of
    /// a write under a held lock. A separate function so its pool connection
    /// is returned before the write runs: an upload can take a long time, and
    /// holding a connection for its duration would starve the write itself of
    /// one.
    async fn check(
        &self,
        entry_path: &EntryPath,
        held_tokens: &[String],
    ) -> Result<Option<(String, KeepAlive)>, LockError> {
        let mut executor: UnifiedExecutor = self.sql_db.pool().into();
        if held_tokens.is_empty() {
            return match EntryLockRepository::get_active(entry_path, &mut executor).await? {
                None => Ok(None),
                Some(_) => Err(LockError::Locked),
            };
        }

        let live = EntryLockRepository::keep_alive(
            entry_path,
            held_tokens,
            WRITE_LOCK_HORIZON_SECS,
            &mut executor,
        )
        .await?
        .ok_or(LockError::TokenMismatch)?;
        let keepalive = KeepAlive::spawn(
            self.sql_db.clone(),
            entry_path.clone(),
            live.token.clone(),
            KEEPALIVE_INTERVAL,
        );
        Ok(Some((live.token, keepalive)))
    }

    /// Grant a new lock, sweeping expired ones first.
    pub(crate) async fn create(
        &self,
        entry_path: &EntryPath,
        lifetime_secs: i64,
    ) -> Result<EntryLockEntity, LockError> {
        let token = uuid::Uuid::new_v4().to_string();
        let mut executor: UnifiedExecutor = self.sql_db.pool().into();
        EntryLockRepository::delete_expired(&mut executor).await?;
        EntryLockRepository::acquire(entry_path, &token, lifetime_secs, &mut executor)
            .await?
            .ok_or(LockError::Locked)
    }

    /// Restart the lifetime of the live lock that one of `tokens` names.
    pub(crate) async fn refresh(
        &self,
        entry_path: &EntryPath,
        tokens: &[String],
        lifetime_secs: i64,
    ) -> Result<EntryLockEntity, LockError> {
        EntryLockRepository::refresh(
            entry_path,
            tokens,
            lifetime_secs,
            &mut self.sql_db.pool().into(),
        )
        .await?
        .ok_or(LockError::TokenMismatch)
    }

    /// Release the lock held with `token`. `false` if there was none.
    pub(crate) async fn release(
        &self,
        entry_path: &EntryPath,
        token: &str,
    ) -> Result<bool, LockError> {
        Ok(EntryLockRepository::release(entry_path, token, &mut self.sql_db.pool().into()).await?)
    }
}

/// Pushes a lock's expiry out every `interval` for as long as it is held.
/// Dropping it, on completion or because the client went away, stops that.
struct KeepAlive(JoinHandle<()>);

impl KeepAlive {
    fn spawn(sql_db: SqlDb, entry_path: EntryPath, token: String, interval: Duration) -> Self {
        Self(tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let extended = EntryLockRepository::keep_alive(
                    &entry_path,
                    std::slice::from_ref(&token),
                    WRITE_LOCK_HORIZON_SECS,
                    &mut sql_db.pool().into(),
                )
                .await;
                match extended {
                    Ok(Some(_)) => {}
                    // Expired through failed keep-alives, or the holder unlocked
                    // it. The write is not stopped here: its finalization
                    // refuses it once it finds the lock gone.
                    Ok(None) => {
                        tracing::warn!(path = %entry_path, "Lock lost while its write is in flight");
                        return;
                    }
                    // Try again on the next tick.
                    Err(error) => {
                        tracing::warn!(path = %entry_path, %error, "Failed to keep lock alive")
                    }
                }
            }
        }))
    }
}

impl Drop for KeepAlive {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Keypair;

    use super::*;
    use crate::shared::webdav::StoragePath;

    fn tokens(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|token| token.to_string()).collect()
    }

    fn random_path() -> EntryPath {
        EntryPath::new(
            Keypair::random().public_key(),
            StoragePath::new("/pub/state.bin").unwrap(),
        )
    }

    async fn expires_at(db: &SqlDb, path: &EntryPath) -> Option<i64> {
        EntryLockRepository::get_active(path, &mut db.pool().into())
            .await
            .unwrap()
            .map(|lock| lock.expires_at)
    }

    /// An unlocked write holds nothing, a write under the client's own lock
    /// keeps that lock alive over the write's horizon and leaves it in place,
    /// and everything else is refused before the write starts.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn write_runs_only_when_the_lock_allows_it() {
        // One connection: a write that needs the database while the lock
        // check still holds its connection would time out. Uploads are long,
        // so the check must give its connection back before the write runs.
        let db = SqlDb::test_with_pool_options(1, Duration::from_secs(2)).await;
        let service = LockService::new(db.clone());
        let path = random_path();
        let write = |held: &[&str], body: Result<(), &'static str>| {
            let (db, service, path, held) =
                (db.clone(), service.clone(), path.clone(), tokens(held));
            async move {
                service
                    .run_write(&path, &held, async {
                        db.pool()
                            .acquire()
                            .await
                            .expect("the lock check must not hold a connection over the write");
                        body
                    })
                    .await
            }
        };

        // Free path: the write runs, and a failure changes nothing.
        assert!(matches!(write(&[], Ok(())).await, Ok(Ok(()))));
        let failed = write(&[], Err("failed")).await;
        assert!(matches!(failed, Ok(Err("failed"))));
        assert_eq!(expires_at(&db, &path).await, None);
        let stale = write(&["stale"], Ok(())).await;
        assert!(matches!(stale, Err(LockError::TokenMismatch)));

        // Locked path.
        let granted = EntryLockRepository::acquire(&path, "t", 5, &mut db.pool().into())
            .await
            .unwrap()
            .unwrap();
        let unlocked = write(&[], Ok(())).await;
        assert!(matches!(unlocked, Err(LockError::Locked)));
        let wrong = write(&["other"], Ok(())).await;
        assert!(matches!(wrong, Err(LockError::TokenMismatch)));
        assert!(matches!(write(&["t"], Ok(())).await, Ok(Ok(()))));
        // Granted 5 seconds, now at least the full horizon, and still held.
        let extended = expires_at(&db, &path).await.unwrap();
        assert!(extended >= granted.expires_at + WRITE_LOCK_HORIZON_SECS - 5);
        let unlocked = write(&[], Ok(())).await;
        assert!(matches!(unlocked, Err(LockError::Locked)));
    }

    /// A token is only good on the path it was granted for: presenting it on
    /// another path of the same user, or the same path of another user, is a
    /// mismatch, and the lock it names is neither extended nor released.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn token_is_refused_on_any_other_path() {
        let db = SqlDb::test().await;
        let service = LockService::new(db.clone());
        let path = random_path();
        let granted = EntryLockRepository::acquire(&path, "t", 5, &mut db.pool().into())
            .await
            .unwrap()
            .unwrap();

        let sibling = EntryPath::new(
            path.pubkey().clone(),
            StoragePath::new("/pub/other.bin").unwrap(),
        );
        let same_path_other_user =
            EntryPath::new(Keypair::random().public_key(), path.path().clone());
        for other in [&sibling, &same_path_other_user] {
            let result = service.run_write(other, &tokens(&["t"]), async {}).await;
            assert!(
                matches!(result, Err(LockError::TokenMismatch)),
                "token for {path} must be refused on {other}"
            );
            assert_eq!(expires_at(&db, other).await, None);
        }
        assert_eq!(expires_at(&db, &path).await, Some(granted.expires_at));
    }

    /// A write in flight pushes its lock's expiry out, and stops doing so once
    /// its keep-alive is dropped.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn keepalive_extends_a_lock_that_is_running_out() {
        let db = SqlDb::test().await;
        let path = random_path();
        let granted = EntryLockRepository::acquire(&path, "t", 5, &mut db.pool().into())
            .await
            .unwrap()
            .unwrap();

        let keepalive = KeepAlive::spawn(
            db.clone(),
            path.clone(),
            "t".to_string(),
            Duration::from_millis(20),
        );
        let mut extended = None;
        for _ in 0..100 {
            // Granted 5 seconds, extended to the full horizon.
            extended = expires_at(&db, &path)
                .await
                .filter(|at| *at >= granted.expires_at + WRITE_LOCK_HORIZON_SECS - 5);
            if extended.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(extended.is_some(), "the keep-alive never extended the lock");

        drop(keepalive);
        EntryLockRepository::expire(&path, &mut db.pool().into())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(expires_at(&db, &path).await, None);
    }
}
