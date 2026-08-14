//! Pooled keyed rate limiters for per-user bandwidth throttling.
//!
//! Users with the same configured (rate, burst) share a single governor
//! instance, keyed by their public key. This avoids creating one governor
//! per user while still allowing per-user tracking.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use governor::clock::QuantaClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};

use crate::data_directory::quota_config::BandwidthQuota;
use crate::quota_config::{LimitKey, LimitKeyType, PathLimit};

use super::extract_ip::extract_ip;
use super::CLEANUP_INTERVAL_SECS;
use crate::client_server::middleware::request_tenant::RequestTenant;
use axum::body::Body;
use axum::http::Request;

pub(super) type KeyedRateLimiter = RateLimiter<LimitKey, DashMapStateStore<LimitKey>, QuantaClock>;

/// Pool key for per-user speed limiters: rate + optional burst override.
/// Users with the same (rate, burst) share a limiter instance.
type SpeedLimitKey = (BandwidthQuota, Option<NonZeroU32>);

/// Shared pool of keyed rate limiters, grouped by (rate, burst).
///
/// Users with the same configured rate and burst share a single governor
/// instance, keyed by their public key.
#[derive(Debug, Clone)]
pub(super) struct LimiterPool(Arc<DashMap<SpeedLimitKey, Arc<KeyedRateLimiter>>>);

impl LimiterPool {
    /// Create a new empty pool and spawn a background cleanup task.
    /// The cleanup task self-terminates when the Arc is dropped (Weak::upgrade fails).
    pub fn new() -> Self {
        let inner: Arc<DashMap<SpeedLimitKey, Arc<KeyedRateLimiter>>> = Arc::new(DashMap::new());

        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                let Some(pool) = weak.upgrade() else {
                    break;
                };
                pool.retain(|_, limiter| {
                    limiter.retain_recent();
                    limiter.shrink_to_fit();
                    !limiter.is_empty()
                });
            }
        });

        Self(inner)
    }

    /// Get or create a keyed rate limiter for a specific bandwidth rate + burst.
    pub fn get_or_create(
        &self,
        rate: &BandwidthQuota,
        burst: Option<NonZeroU32>,
    ) -> Arc<KeyedRateLimiter> {
        self.0
            .entry((rate.clone(), burst))
            .or_insert_with(|| {
                let quota: Quota = rate.to_governor_quota(burst);
                Arc::new(RateLimiter::keyed(quota))
            })
            .clone()
    }
}

/// A path limit paired with its governor rate limiter instance.
#[derive(Debug, Clone)]
pub(super) struct LimitTuple {
    pub limit: PathLimit,
    pub limiter: Arc<KeyedRateLimiter>,
}

impl LimitTuple {
    pub fn new(path_limit: PathLimit) -> Result<Self, String> {
        let quota = Quota::try_from(path_limit.clone())?;
        let limiter = Arc::new(RateLimiter::keyed(quota));

        // Forget keys that are not used anymore. This is to prevent memory leaks.
        // Uses a Weak reference so the task self-terminates when the limiter is dropped.
        let weak = Arc::downgrade(&limiter);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(limiter) = weak.upgrade() else {
                    break;
                };
                limiter.retain_recent();
                limiter.shrink_to_fit();
            }
        });

        Ok(Self {
            limit: path_limit,
            limiter,
        })
    }

    /// Extract the key from the request.
    ///
    /// The key is either the ip address of the client
    /// or the user pubkey.
    pub fn extract_key(&self, req: &Request<Body>) -> anyhow::Result<LimitKey> {
        match self.limit.key {
            LimitKeyType::Ip => extract_ip(req).map(LimitKey::Ip),
            LimitKeyType::User => {
                // Extract the user pubkey from the request.
                req.extensions()
                    .get::<RequestTenant>()
                    .map(|pk| LimitKey::User(pk.public_key().clone()))
                    .ok_or(anyhow::anyhow!("Failed to extract user pubkey."))
            }
        }
    }

    /// Check if the request matches the limit.
    pub fn is_match(&self, req: &Request<Body>) -> bool {
        let path = req
            .extensions()
            .get::<RequestTenant>()
            .and_then(RequestTenant::storage_path)
            .map_or(req.uri().path(), |path| path.as_str());
        let glob_match = self.limit.path.is_match(path);
        let method_match = self.limit.method.0 == req.method();
        glob_match && method_match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pool_same_rate_shares_limiter() {
        let pool = LimiterPool::new();

        let rate: BandwidthQuota = "5mb/s".parse().unwrap();
        let limiter1 = pool.get_or_create(&rate, None);
        let limiter2 = pool.get_or_create(&rate, None);

        // Same rate + burst should return the same limiter instance
        assert!(Arc::ptr_eq(&limiter1, &limiter2));
    }

    #[tokio::test]
    async fn test_pool_different_rate_different_limiter() {
        let pool = LimiterPool::new();

        let rate: BandwidthQuota = "5mb/s".parse().unwrap();
        let limiter1 = pool.get_or_create(&rate, None);

        let other_rate: BandwidthQuota = "10mb/s".parse().unwrap();
        let limiter2 = pool.get_or_create(&other_rate, None);
        assert!(!Arc::ptr_eq(&limiter1, &limiter2));
    }

    #[tokio::test]
    async fn test_pool_different_burst_different_limiter() {
        let pool = LimiterPool::new();

        let rate: BandwidthQuota = "5mb/s".parse().unwrap();
        let limiter1 = pool.get_or_create(&rate, None);
        let burst = NonZeroU32::new(50).unwrap();
        let limiter2 = pool.get_or_create(&rate, Some(burst));
        assert!(!Arc::ptr_eq(&limiter1, &limiter2));

        // Same rate + same burst should share
        let limiter3 = pool.get_or_create(&rate, Some(burst));
        assert!(Arc::ptr_eq(&limiter2, &limiter3));
    }
}
