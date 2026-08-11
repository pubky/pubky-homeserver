//! Service layer for user operations.
//!
//! Pure user CRUD + quota cache. No config — callers that need
//! default quotas (storage, bandwidth) own them directly.

use pubky_common::crypto::PublicKey;

use crate::persistence::sql::user::{UserEntity, UserOverview, UserRepository};
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

    // ── Reads (use internal pool) ──────────────────────────────────

    /// Get a user by their public key.
    pub async fn get(&self, pubkey: &PublicKey) -> Result<UserEntity, sqlx::Error> {
        UserRepository::get(pubkey, &mut self.sql_db.pool().into()).await
    }

    /// Look up a user by public key, returning HTTP-appropriate errors.
    /// - User not found → 404
    /// - User disabled (when `err_if_disabled` is true) → 403
    // TODO: Replace HttpError return with a domain error enum and map to HTTP in route handlers.
    pub async fn get_or_http_error(
        &self,
        pubkey: &PublicKey,
        err_if_disabled: bool,
    ) -> HttpResult<UserEntity> {
        let user = match self.get(pubkey).await {
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

    /// Get the id of a user by their public key.
    pub async fn get_id(&self, pubkey: &PublicKey) -> Result<i32, sqlx::Error> {
        UserRepository::get_id(pubkey, &mut self.sql_db.pool().into()).await
    }

    /// Get all user entities.
    pub async fn get_all(&self) -> Result<Vec<UserEntity>, sqlx::Error> {
        UserRepository::get_all(&mut self.sql_db.pool().into()).await
    }

    /// Get an overview of all users (counts, total disk usage).
    pub async fn get_overview(&self) -> Result<UserOverview, sqlx::Error> {
        UserRepository::get_overview(&mut self.sql_db.pool().into()).await
    }

    // ── Reads (caller-owned transaction) ──────────────────────────

    /// Get a user by public key inside an existing transaction (no row lock).
    pub async fn get_in_tx<'a>(
        &self,
        pubkey: &PublicKey,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<UserEntity, sqlx::Error> {
        UserRepository::get(pubkey, executor).await
    }

    /// Fetch a user with a `FOR NO KEY UPDATE` row lock within an existing transaction.
    pub async fn get_for_no_key_update<'a>(
        &self,
        pubkey: &PublicKey,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<UserEntity, sqlx::Error> {
        UserRepository::get_for_no_key_update(pubkey, executor).await
    }

    // ── Writes ─────────────────────────────────────────────────────

    /// Create a new user inside an existing transaction.
    pub async fn create_in_tx<'a>(
        &self,
        pubkey: &PublicKey,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<UserEntity, sqlx::Error> {
        UserRepository::create(pubkey, executor).await
    }

    /// Persist an updated user entity within an existing transaction.
    pub async fn update_in_tx<'a>(
        &self,
        user: &UserEntity,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<UserEntity, sqlx::Error> {
        UserRepository::update(user, executor).await
    }

    /// Set per-user quota inside an existing transaction.
    pub async fn set_quota_in_tx<'a>(
        &self,
        user_id: i32,
        config: &UserQuota,
        executor: &mut UnifiedExecutor<'a>,
    ) -> Result<UserEntity, sqlx::Error> {
        UserRepository::set_quota(user_id, config, executor).await
    }

    // ── Admin operations ─────────────────────────────────────────

    /// Disable a user account.
    pub async fn admin_disable(&self, pubkey: &PublicKey) -> HttpResult<()> {
        self.set_disabled(pubkey, true).await
    }

    /// Enable a user account.
    pub async fn admin_enable(&self, pubkey: &PublicKey) -> HttpResult<()> {
        self.set_disabled(pubkey, false).await
    }

    async fn set_disabled(&self, pubkey: &PublicKey, disabled: bool) -> HttpResult<()> {
        let mut tx = self.sql_db.pool().begin().await?;
        let mut user = match UserRepository::get_for_update(pubkey, uexecutor!(tx)).await {
            Ok(user) => user,
            Err(sqlx::Error::RowNotFound) => return Err(HttpError::not_found()),
            Err(e) => return Err(e.into()),
        };
        user.disabled = disabled;
        UserRepository::update(&user, uexecutor!(tx)).await?;
        tx.commit().await?;
        Ok(())
    }

    // ── Quota ──────────────────────────────────────────────────────

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

        match self.get(pubkey).await {
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

        let user = match UserRepository::get_for_update(pubkey, uexecutor!(tx)).await {
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

#[cfg(test)]
impl UserService {
    /// Create a new user using the internal pool.
    ///
    /// Test-only: production signup must go through [`SignupService::create_new_user`]
    /// to enforce token validation and assign initial quota from the signup code.
    pub async fn create(&self, pubkey: &PublicKey) -> Result<UserEntity, sqlx::Error> {
        UserRepository::create(pubkey, &mut self.sql_db.pool().into()).await
    }

    /// Test helper: create a user with a storage quota in MB.
    pub async fn create_with_quota_mb(&self, pubkey: &PublicKey, quota_mb: u64) -> UserEntity {
        use crate::shared::user_quota::QuotaOverride;
        let user = self.create(pubkey).await.unwrap();
        let config = UserQuota {
            storage_quota_mb: QuotaOverride::Value(quota_mb),
            ..Default::default()
        };
        self.set_quota_in_tx(user.id, &config, &mut self.sql_db.pool().into())
            .await
            .unwrap();
        self.get(pubkey).await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::SqlDb;
    use pubky_common::crypto::Keypair;

    async fn service() -> UserService {
        UserService::new(SqlDb::test().await)
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_create_and_get() {
        let svc = service().await;
        let pubkey = Keypair::random().public_key();

        let created = svc.create(&pubkey).await.unwrap();
        assert_eq!(created.public_key, pubkey);
        assert!(!created.disabled);

        let fetched = svc.get(&pubkey).await.unwrap();
        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.public_key, pubkey);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_nonexistent_returns_row_not_found() {
        let svc = service().await;
        let pubkey = Keypair::random().public_key();

        let err = svc.get(&pubkey).await.unwrap_err();
        assert!(matches!(err, sqlx::Error::RowNotFound));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_id() {
        let svc = service().await;
        let pubkey = Keypair::random().public_key();

        let created = svc.create(&pubkey).await.unwrap();
        let id = svc.get_id(&pubkey).await.unwrap();
        assert_eq!(id, created.id);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_or_http_error_not_found() {
        let svc = service().await;
        let pubkey = Keypair::random().public_key();

        assert!(svc.get_or_http_error(&pubkey, false).await.is_err());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_or_http_error_disabled() {
        let svc = service().await;
        let pubkey = Keypair::random().public_key();
        svc.create(&pubkey).await.unwrap();
        svc.admin_disable(&pubkey).await.unwrap();

        // err_if_disabled = false → still returns the user
        let user = svc.get_or_http_error(&pubkey, false).await.unwrap();
        assert!(user.disabled);

        // err_if_disabled = true → error
        assert!(svc.get_or_http_error(&pubkey, true).await.is_err());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_disable_and_enable() {
        let svc = service().await;
        let pubkey = Keypair::random().public_key();
        svc.create(&pubkey).await.unwrap();

        svc.admin_disable(&pubkey).await.unwrap();
        assert!(svc.get(&pubkey).await.unwrap().disabled);

        svc.admin_enable(&pubkey).await.unwrap();
        assert!(!svc.get(&pubkey).await.unwrap().disabled);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_admin_disable_nonexistent_returns_error() {
        let svc = service().await;
        let pubkey = Keypair::random().public_key();

        assert!(svc.admin_disable(&pubkey).await.is_err());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_get_all_and_get_overview() {
        let svc = service().await;

        // Empty initially
        let all = svc.get_all().await.unwrap();
        assert!(all.is_empty());
        let overview = svc.get_overview().await.unwrap();
        assert_eq!(overview.count, 0);

        // Create two users, disable one
        let pk1 = Keypair::random().public_key();
        let pk2 = Keypair::random().public_key();
        svc.create(&pk1).await.unwrap();
        svc.create(&pk2).await.unwrap();
        svc.admin_disable(&pk2).await.unwrap();

        let all = svc.get_all().await.unwrap();
        assert_eq!(all.len(), 2);

        let overview = svc.get_overview().await.unwrap();
        assert_eq!(overview.count, 2);
        assert_eq!(overview.disabled_count, 1);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_resolve_quota_unknown_user_returns_none() {
        let svc = service().await;
        let pubkey = Keypair::random().public_key();

        let quota = svc.resolve_quota(&pubkey).await.unwrap();
        assert!(quota.is_none());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_resolve_quota_known_user_returns_some() {
        let svc = service().await;
        let pubkey = Keypair::random().public_key();
        svc.create(&pubkey).await.unwrap();

        let quota = svc.resolve_quota(&pubkey).await.unwrap();
        assert!(quota.is_some());

        // Second call should hit cache and still return Some
        let quota2 = svc.resolve_quota(&pubkey).await.unwrap();
        assert!(quota2.is_some());
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_patch_quota_invalidates_cache() {
        use crate::shared::user_quota::{QuotaOverride, UserQuotaPatch};

        let svc = service().await;
        let pubkey = Keypair::random().public_key();
        svc.create(&pubkey).await.unwrap();

        // Populate cache
        let before = svc.resolve_quota(&pubkey).await.unwrap().unwrap();
        assert!(before.storage_quota_mb.is_default());

        // Patch quota
        let patch = UserQuotaPatch {
            storage_quota_mb: Some(QuotaOverride::Value(42)),
            ..Default::default()
        };
        svc.patch_quota(&pubkey, &patch).await.unwrap();

        // Cache should be invalidated — next resolve must return the new value
        let after = svc.resolve_quota(&pubkey).await.unwrap().unwrap();
        assert_eq!(after.storage_quota_mb, QuotaOverride::Value(42));
    }
}
