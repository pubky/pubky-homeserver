//! Simple TTL cache for resolved per-user quota overrides.
//!
//! This is a dumb data structure — it stores, retrieves, and expires entries.
//! All DB resolution logic lives in [`super::UserService`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use pubky_common::crypto::PublicKey;

use crate::shared::quota::UserQuota;

/// How long a cached limit entry is considered fresh before re-resolving from DB.
///
/// Quota changes made via the admin API are **not** actively invalidated in the
/// cache — they take effect once this TTL expires.
/// In an emergency there exists the option to use /users/{pubkey}/disable.
const CACHE_TTL: Duration = Duration::from_secs(120); // 2 minutes

/// How long a negative (user-not-found) cache entry lives before re-checking the DB.
/// Short TTL so that a subsequent signup populates limits promptly.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);

/// Maximum number of entries in the cache. Prevents unbounded memory growth.
const MAX_ENTRIES: usize = 100_000;

/// How often the background task runs to evict expired cache entries.
const CLEANUP_INTERVAL_SECS: u64 = 60;

/// A cached user quota config with an expiry timestamp.
#[derive(Debug, Clone)]
pub(super) struct CachedEntry {
    /// The resolved quota, or `None` for a negative (user-not-found) entry.
    pub config: Option<UserQuota>,
    cached_at: Instant,
    ttl: Duration,
}

impl CachedEntry {
    /// Wrap a resolved config with a fresh timestamp.
    pub fn found(config: UserQuota) -> Self {
        Self {
            config: Some(config),
            cached_at: Instant::now(),
            ttl: CACHE_TTL,
        }
    }

    /// Create a negative cache entry (user not found) with a shorter TTL.
    pub fn not_found() -> Self {
        Self {
            config: None,
            cached_at: Instant::now(),
            ttl: NEGATIVE_CACHE_TTL,
        }
    }

    fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}

/// TTL cache for per-user quota overrides.
///
/// Stores resolved quotas with automatic expiry and background cleanup.
/// Does not access the database — cache miss resolution is handled by
/// [`super::UserService::resolve_quota`].
#[derive(Debug, Clone)]
pub(super) struct QuotaCache {
    entries: Arc<DashMap<PublicKey, CachedEntry>>,
}

impl QuotaCache {
    /// Create a new cache and spawn a background cleanup task.
    /// The cleanup task self-terminates when the cache is dropped (Weak::upgrade fails).
    pub fn new() -> Self {
        let entries: Arc<DashMap<PublicKey, CachedEntry>> = Arc::new(DashMap::new());

        let weak = Arc::downgrade(&entries);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                let Some(map) = weak.upgrade() else {
                    break;
                };
                map.retain(|_, entry| !entry.is_expired());
            }
        });

        Self { entries }
    }

    /// Get a non-expired cached entry.
    pub fn get(&self, pubkey: &PublicKey) -> Option<Option<UserQuota>> {
        self.entries
            .get(pubkey)
            .filter(|entry| !entry.is_expired())
            .map(|entry| entry.config.clone())
    }

    /// Insert or replace a cache entry.
    pub fn insert(&self, pubkey: PublicKey, entry: CachedEntry) {
        self.entries.insert(pubkey, entry);
    }

    /// Evict a specific user's entry.
    pub fn remove(&self, pubkey: &PublicKey) {
        self.entries.remove(pubkey);
    }

    /// Ensure there's room for a new entry, evicting expired and overflow entries as needed.
    pub fn make_room(&self) {
        if self.entries.len() < MAX_ENTRIES {
            return;
        }

        self.entries.retain(|_, entry| !entry.is_expired());

        if self.entries.len() >= MAX_ENTRIES {
            let to_evict = MAX_ENTRIES / 10;
            let keys: Vec<_> = self
                .entries
                .iter()
                .take(to_evict.max(1))
                .map(|entry| entry.key().clone())
                .collect();
            for key in keys {
                self.entries.remove(&key);
            }
        }
    }
}
