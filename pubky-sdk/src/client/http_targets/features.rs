use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use lru::LruCache;
use reqwest::StatusCode;
use serde::Deserialize;
use tokio::sync::Mutex as AsyncMutex;
use web_time::Instant;

use crate::util::read_response_body;
use crate::{PubkyHttpClient, PublicKey};

const MAX_INFO_BYTES: usize = 16 * 1024;
const INFO_TIMEOUT: Duration = Duration::from_secs(5);
const INFO_CACHE_TTL: Duration = Duration::from_secs(60);
/// A failed fetch is retried after a short TTL: long enough that back-to-back requests to a
/// homeserver without `/info` do not each re-probe it, short enough that a homeserver first seen
/// during a transient error is not treated as featureless for the full success TTL.
const INFO_FAILURE_CACHE_TTL: Duration = Duration::from_secs(5);
const INFO_CACHE_CAPACITY: usize = 256;
type FeatureCell = Arc<AsyncMutex<Option<CachedFeatures>>>;

/// Whether a homeserver supports a feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureSupport {
    /// The homeserver advertises the feature.
    Supported,
    /// The homeserver answered without advertising the feature, so it needs an upgrade.
    Unsupported,
    /// The homeserver gave no usable answer, so the check can be retried.
    Unknown,
}

/// What a homeserver answered when asked for its features.
enum InfoFetch {
    /// The homeserver listed its features.
    Listed(Vec<String>),
    /// The homeserver has no `/info` endpoint, so it predates feature discovery.
    Missing,
    /// No usable answer: a connection failure, a server error or a malformed body.
    Failed,
}

#[derive(Debug, Clone)]
pub(crate) struct HomeserverFeatures {
    servers: Arc<Mutex<LruCache<PublicKey, FeatureCell>>>,
    request_timeout: Duration,
}

#[derive(Deserialize)]
struct InfoResponse {
    features: Vec<String>,
}

#[derive(Debug)]
struct CachedFeatures {
    features: Vec<String>,
    /// Whether the last fetch got an answer, rather than falling back after a failure.
    answered: bool,
    expires_at: Instant,
}

impl CachedFeatures {
    fn is_current(&self) -> bool {
        Instant::now() < self.expires_at
    }

    fn support(&self, feature: &str) -> FeatureSupport {
        if self.features.iter().any(|candidate| candidate == feature) {
            FeatureSupport::Supported
        } else if self.answered {
            FeatureSupport::Unsupported
        } else {
            FeatureSupport::Unknown
        }
    }
}

impl Default for HomeserverFeatures {
    fn default() -> Self {
        Self::new(None)
    }
}

impl HomeserverFeatures {
    pub(crate) fn new(request_timeout: Option<Duration>) -> Self {
        Self {
            servers: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(INFO_CACHE_CAPACITY)
                    .expect("homeserver feature cache capacity is non-zero"),
            ))),
            request_timeout: request_timeout
                .map_or(INFO_TIMEOUT, |timeout| timeout.min(INFO_TIMEOUT)),
        }
    }

    pub(crate) async fn supports(
        &self,
        client: &PubkyHttpClient,
        homeserver: &PublicKey,
        feature: &str,
    ) -> bool {
        self.supports_for(homeserver, feature, || self.fetch(client, homeserver))
            .await
    }

    /// Like [`Self::supports`], but tells a missing feature apart from a failed check.
    pub(crate) async fn support(
        &self,
        client: &PubkyHttpClient,
        homeserver: &PublicKey,
        feature: &str,
    ) -> FeatureSupport {
        self.support_for(homeserver, feature, || self.fetch(client, homeserver))
            .await
    }

    fn cell(&self, homeserver: &PublicKey) -> FeatureCell {
        let mut servers = self.servers.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(cell) = servers.get(homeserver) {
            return Arc::clone(cell);
        }

        let cell = FeatureCell::default();
        servers.put(homeserver.clone(), Arc::clone(&cell));
        cell
    }

    async fn supports_for<F, Fut>(&self, homeserver: &PublicKey, feature: &str, fetch: F) -> bool
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = InfoFetch>,
    {
        self.support_for(homeserver, feature, fetch).await == FeatureSupport::Supported
    }

    async fn support_for<F, Fut>(
        &self,
        homeserver: &PublicKey,
        feature: &str,
        fetch: F,
    ) -> FeatureSupport
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = InfoFetch>,
    {
        let cell = self.cell(homeserver);
        let mut cached = cell.lock().await;
        if let Some(current) = cached.as_ref().filter(|cached| cached.is_current()) {
            return current.support(feature);
        }

        let (features, answered, ttl) = match fetch().await {
            InfoFetch::Listed(features) => (features, true, INFO_CACHE_TTL),
            // An answer too: a homeserver without `/info` has none of the features.
            InfoFetch::Missing => (Vec::new(), true, INFO_FAILURE_CACHE_TTL),
            // Keep the last known features through a transient failure.
            InfoFetch::Failed => (
                cached.take().map_or_else(Vec::new, |stale| stale.features),
                false,
                INFO_FAILURE_CACHE_TTL,
            ),
        };
        let refreshed = CachedFeatures {
            features,
            answered,
            expires_at: Instant::now() + ttl,
        };
        let support = refreshed.support(feature);
        *cached = Some(refreshed);
        support
    }

    async fn fetch(&self, client: &PubkyHttpClient, homeserver: &PublicKey) -> InfoFetch {
        let Ok(request) = client.homeserver_info_request(homeserver).await else {
            return InfoFetch::Failed;
        };
        let Ok(response) = request.timeout(self.request_timeout).send().await else {
            return InfoFetch::Failed;
        };
        if response.status() == StatusCode::NOT_FOUND {
            return InfoFetch::Missing;
        }
        if !response.status().is_success() {
            return InfoFetch::Failed;
        }

        let Ok(body) = read_response_body(response, MAX_INFO_BYTES).await else {
            return InfoFetch::Failed;
        };
        Self::decode(&body).map_or(InfoFetch::Failed, InfoFetch::Listed)
    }

    fn decode(body: &[u8]) -> Option<Vec<String>> {
        serde_json::from_slice::<InfoResponse>(body)
            .map(|response| response.features)
            .ok()
    }

    #[cfg(test)]
    pub(crate) fn insert(&self, homeserver: &PublicKey, features: &[&str]) {
        let cell = self.cell(homeserver);
        let mut cached = cell
            .try_lock()
            .expect("homeserver features are not being initialized");
        assert!(
            cached.is_none(),
            "homeserver features were already initialized"
        );
        *cached = Some(CachedFeatures {
            features: features.iter().map(ToString::to_string).collect(),
            answered: true,
            expires_at: Instant::now() + INFO_CACHE_TTL,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::FeatureSupport::{Supported, Unknown, Unsupported};
    use super::*;
    use pubky_common::constants::features::PATH_ADDRESSED_STORAGE;

    #[test]
    fn decodes_only_valid_feature_lists() {
        let cases = [
            (
                br#"{"features":["path-addressed-storage","unknown"]}"#.as_slice(),
                Some(true),
            ),
            (br#"{"features":[]}"#, Some(false)),
            (br#"{"features":["unknown"]}"#, Some(false)),
            (br#"{"features":{}}"#, None),
            (br"{}", None),
            (b"not json", None),
        ];

        for (body, expected) in cases {
            assert_eq!(
                HomeserverFeatures::decode(body).map(|features| features
                    .iter()
                    .any(|candidate| candidate == PATH_ADDRESSED_STORAGE)),
                expected,
                "body={}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn limits_info_response_body() {
        for size in [MAX_INFO_BYTES - 1, MAX_INFO_BYTES, MAX_INFO_BYTES + 1] {
            let body = vec![b'x'; size];
            let (response, _connection) = crate::util::tests::serve_response(
                200,
                &format!("Content-Length: {size}\r\n"),
                &body,
            )
            .await;
            let result = read_response_body(response, MAX_INFO_BYTES).await;
            if size <= MAX_INFO_BYTES {
                assert_eq!(result.unwrap(), body);
            } else {
                assert!(matches!(
                    result.unwrap_err(),
                    crate::util::ResponseBodyError::TooLarge
                ));
            }
        }
    }

    #[test]
    fn info_timeout_respects_a_shorter_client_timeout() {
        assert_eq!(
            HomeserverFeatures::new(Some(Duration::from_millis(100))).request_timeout,
            Duration::from_millis(100)
        );
        assert_eq!(
            HomeserverFeatures::new(Some(Duration::from_secs(10))).request_timeout,
            INFO_TIMEOUT
        );
    }

    #[test]
    fn evicts_the_least_recently_used_homeserver() {
        let discovery = HomeserverFeatures::default();
        let homeservers = (0..=INFO_CACHE_CAPACITY)
            .map(|_| crate::Keypair::random().public_key())
            .collect::<Vec<_>>();

        for homeserver in &homeservers[..INFO_CACHE_CAPACITY] {
            drop(discovery.cell(homeserver));
        }
        drop(discovery.cell(&homeservers[0]));
        drop(discovery.cell(&homeservers[INFO_CACHE_CAPACITY]));

        let servers = discovery
            .servers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert_eq!(servers.len(), INFO_CACHE_CAPACITY);
        assert!(servers.contains(&homeservers[0]));
        assert!(!servers.contains(&homeservers[1]));
        assert!(servers.contains(&homeservers[INFO_CACHE_CAPACITY]));
    }

    #[tokio::test]
    async fn temporarily_stores_failures_and_coalesces_feature_fetches() {
        let discovery = HomeserverFeatures::default();
        let homeserver = crate::Keypair::random().public_key();
        let calls = Arc::new(AtomicUsize::new(0));

        let first_calls = Arc::clone(&calls);
        let first = discovery.supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async move {
            first_calls.fetch_add(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
            InfoFetch::Failed
        });
        let second_calls = Arc::clone(&calls);
        let second = discovery.supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async move {
            second_calls.fetch_add(1, Ordering::Relaxed);
            InfoFetch::Listed(vec![PATH_ADDRESSED_STORAGE.to_string()])
        });

        let (first, second) = tokio::join!(first, second);

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(!first);
        assert!(!second);

        let cached = discovery
            .supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async {
                calls.fetch_add(1, Ordering::Relaxed);
                InfoFetch::Listed(Vec::new())
            })
            .await;
        assert!(!cached);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn caches_failures_briefly_and_successes_for_the_full_ttl() {
        let discovery = HomeserverFeatures::default();
        let homeserver = crate::Keypair::random().public_key();
        let cell = discovery.cell(&homeserver);

        let failed_at = Instant::now();
        discovery
            .supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async {
                InfoFetch::Failed
            })
            .await;
        let failure_expiry = cell.lock().await.as_ref().unwrap().expires_at;
        assert!(failure_expiry >= failed_at + INFO_FAILURE_CACHE_TTL);
        assert!(failure_expiry < failed_at + INFO_CACHE_TTL);

        *cell.lock().await = None;
        let succeeded_at = Instant::now();
        discovery
            .supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async {
                InfoFetch::Listed(vec![PATH_ADDRESSED_STORAGE.to_string()])
            })
            .await;
        let success_expiry = cell.lock().await.as_ref().unwrap().expires_at;
        assert!(success_expiry >= succeeded_at + INFO_CACHE_TTL);
    }

    #[tokio::test]
    async fn keeps_stale_features_when_a_refresh_fails() {
        let discovery = HomeserverFeatures::default();
        let homeserver = crate::Keypair::random().public_key();
        let cell = discovery.cell(&homeserver);
        *cell.lock().await = Some(CachedFeatures {
            features: vec![PATH_ADDRESSED_STORAGE.to_string()],
            answered: true,
            expires_at: Instant::now(),
        });

        let failed_at = Instant::now();
        let supported = discovery
            .supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async {
                InfoFetch::Failed
            })
            .await;

        assert!(supported);
        let cached = cell.lock().await;
        let cached = cached.as_ref().unwrap();
        assert_eq!(cached.features, [PATH_ADDRESSED_STORAGE]);
        assert!(cached.expires_at >= failed_at + INFO_FAILURE_CACHE_TTL);
        assert!(cached.expires_at < failed_at + INFO_CACHE_TTL);
    }

    #[tokio::test]
    async fn refreshes_expired_features() {
        let discovery = HomeserverFeatures::default();
        let homeserver = crate::Keypair::random().public_key();
        let cell = discovery.cell(&homeserver);
        *cell.lock().await = Some(CachedFeatures {
            features: vec![PATH_ADDRESSED_STORAGE.to_string()],
            answered: true,
            expires_at: Instant::now(),
        });

        let supported = discovery
            .supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async {
                InfoFetch::Listed(Vec::new())
            })
            .await;

        assert!(!supported);
    }

    #[tokio::test]
    async fn tells_a_missing_feature_from_a_failed_check() {
        let feature = PATH_ADDRESSED_STORAGE;
        let listed = || vec![feature.to_string()];
        let cases: [(Option<Vec<String>>, InfoFetch, FeatureSupport); 7] = [
            (None, InfoFetch::Listed(listed()), Supported),
            (None, InfoFetch::Listed(Vec::new()), Unsupported),
            (None, InfoFetch::Missing, Unsupported),
            (None, InfoFetch::Failed, Unknown),
            // A homeserver that lost `/info` no longer has a feature it once listed.
            (Some(listed()), InfoFetch::Missing, Unsupported),
            // A failure can't turn a known feature off, or confirm a missing one.
            (Some(listed()), InfoFetch::Failed, Supported),
            (Some(Vec::new()), InfoFetch::Failed, Unknown),
        ];

        for (stale, fetched, expected) in cases {
            let discovery = HomeserverFeatures::default();
            let homeserver = crate::Keypair::random().public_key();
            if let Some(features) = stale {
                *discovery.cell(&homeserver).lock().await = Some(CachedFeatures {
                    features,
                    answered: true,
                    expires_at: Instant::now(),
                });
            }
            let support = discovery
                .support_for(&homeserver, feature, || async { fetched })
                .await;
            assert_eq!(support, expected);
        }
    }
}
