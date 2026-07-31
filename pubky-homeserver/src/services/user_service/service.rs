//! Service layer for user operations.
//!
//! Pure user CRUD + quota cache. No config — callers that need
//! default quotas (storage, bandwidth) own them directly.

use pubky_common::crypto::PublicKey;

use crate::persistence::sql::user::{UserEntity, UserRepository};
use crate::persistence::sql::{uexecutor, SqlDb, UnifiedExecutor};
use crate::shared::user_quota::{UserQuota, UserQuotaPatch};
use crate::shared::{HttpError, HttpResult};

use super::quota_cache::{CachedEntry, QuotaCache};

/// A rough estimate of the size of the file metadata stored alongside every file.
/// Added to quota accounting so that zero-byte files still count against the quota.
pub const FILE_METADATA_SIZE: u64 = 256;

/// Coordinates user lookups, creation, and quota caching.
///
/// Wraps the database and quota cache. Does not hold any config —
/// callers that need default quota values own them directly.
#[derive(Clone, Debug)]
pub struct UserService {
    /// Database connection pool.
    sql_db: SqlDb,
    /// In-memory TTL cache for resolved per-user quotas.
    quota_cache: QuotaCache,
}

impl UserService {
    /// Create a new service with its own quota cache.
    pub fn new(sql_db: SqlDb) -> Self {
        let quota_cache = QuotaCache::new();
        Self {
            sql_db,
            quota_cache,
        }
    }

    /// Access the underlying connection pool.
    pub fn pool(&self) -> &sqlx::PgPool {
        self.sql_db.pool()
    }

    /// Fetch a user with a `FOR UPDATE` row lock within an existing transaction.
    pub async fn get_for_update<'a>(
        &self,
        pubkey: &PublicKey,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<UserEntity, sqlx::Error> {
        UserRepository::get_for_update(pubkey, executor).await
    }

    /// Fetch a user with a `FOR NO KEY UPDATE` row lock within an existing transaction.
    pub async fn get_for_no_key_update<'a>(
        &self,
        pubkey: &PublicKey,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<UserEntity, sqlx::Error> {
        UserRepository::get_for_no_key_update(pubkey, executor).await
    }

    /// Persist an updated user entity within an existing transaction.
    pub async fn update<'a>(
        &self,
        user: &UserEntity,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<UserEntity, sqlx::Error> {
        UserRepository::update(user, executor).await
    }

    /// Look up a user by public key, returning HTTP-appropriate errors.
    /// - User not found → 404
    /// - User disabled (when `err_if_disabled` is true) → 403
    pub async fn get_or_http_error(
        &self,
        pubkey: &PublicKey,
        err_if_disabled: bool,
    ) -> HttpResult<UserEntity> {
        let user = match UserRepository::get(pubkey, &mut self.sql_db.pool().into()).await {
            Ok(user) => user,
            Err(sqlx::Error::RowNotFound) => {
                tracing::warn!("User {} not found. Forbid access.", pubkey);
                return Err(HttpError::not_found());
            }
            Err(e) => return Err(e.into()),
        };

        if err_if_disabled && user.disabled {
            tracing::warn!("User {} is disabled. Forbid access.", pubkey);
            return Err(HttpError::forbidden_with_message("User is disabled"));
        }

        Ok(user)
    }

    /// Resolve the effective quota for a user, checking the cache first and
    /// falling back to the database on a miss.
    ///
    /// Returns `Ok(Some(config))` for known users, `Ok(None)` for unknown users,
    /// or `Err` if the DB query fails.
    pub async fn resolve_quota(
        &self,
        pubkey: &PublicKey,
    ) -> Result<Option<UserQuota>, sqlx::Error> {
        if let Some(cached) = self.quota_cache.get(pubkey) {
            return Ok(cached);
        }

        // Cache miss or expired — remove stale entry and query DB.
        self.quota_cache.remove(pubkey);
        self.quota_cache.make_room();

        match UserRepository::get(pubkey, &mut self.sql_db.pool().into()).await {
            Ok(user) => {
                let resolved = user.quota();
                self.quota_cache
                    .insert(pubkey.clone(), CachedEntry::found(resolved.clone()));
                Ok(Some(resolved))
            }
            Err(sqlx::Error::RowNotFound) => {
                self.quota_cache
                    .insert(pubkey.clone(), CachedEntry::not_found());
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Populate the quota cache after a user has been committed.
    pub(crate) fn cache_user_quota(&self, user: &UserEntity) {
        self.quota_cache
            .insert(user.public_key.clone(), CachedEntry::found(user.quota()));
    }

    /// Apply a partial quota update.
    ///
    /// The cached entry is actively invalidated after commit so downstream
    /// layers (rate limiter, etc.) pick up the new values on their next request.
    pub async fn patch_quota(
        &self,
        pubkey: &PublicKey,
        patch: &UserQuotaPatch,
    ) -> HttpResult<UserEntity> {
        let mut tx = self.sql_db.pool().begin().await?;

        let user = match self.get_for_update(pubkey, uexecutor!(tx)).await {
            Ok(user) => user,
            Err(sqlx::Error::RowNotFound) => return Err(HttpError::not_found()),
            Err(e) => return Err(e.into()),
        };

        let mut config = user.quota();
        config.merge(patch);

        // Validate the merged config (e.g. burst requires a corresponding rate Value).
        config.validate().map_err(|e| {
            HttpError::new_with_message(axum::http::StatusCode::UNPROCESSABLE_ENTITY, e)
        })?;

        let updated = UserRepository::set_quota(user.id, &config, uexecutor!(tx)).await?;
        tx.commit().await?;

        // Evict cached entry so the rate limiter sees the change immediately.
        self.quota_cache.remove(pubkey);

        Ok(updated)
    }
}
