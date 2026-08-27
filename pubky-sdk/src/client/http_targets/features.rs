use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use futures_util::StreamExt;
use lru::LruCache;
use reqwest::StatusCode;
use serde::Deserialize;
use tokio::sync::Mutex as AsyncMutex;
use web_time::Instant;

use crate::{PubkyHttpClient, PublicKey, Result, errors::RequestError};

const MAX_INFO_BYTES: usize = 16 * 1024;
const INFO_TIMEOUT: Duration = Duration::from_secs(5);
const INFO_CACHE_TTL: Duration = Duration::from_secs(60);
const INFO_CACHE_CAPACITY: usize = 256;
type FeatureCell = Arc<AsyncMutex<Option<CachedFeatures>>>;

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
    expires_at: Instant,
}

impl CachedFeatures {
    fn current(&self) -> Option<&[String]> {
        (Instant::now() < self.expires_at).then_some(self.features.as_slice())
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

    pub(super) async fn supports(
        &self,
        client: &PubkyHttpClient,
        homeserver: &PublicKey,
        feature: &str,
    ) -> bool {
        self.supports_for(homeserver, feature, || self.fetch(client, homeserver))
            .await
            .unwrap_or(false)
    }

    pub(super) async fn require(
        &self,
        client: &PubkyHttpClient,
        homeserver: &PublicKey,
        feature: &str,
    ) -> Result<()> {
        if self
            .supports_for(homeserver, feature, || self.fetch(client, homeserver))
            .await?
        {
            return Ok(());
        }

        Err(RequestError::UnsupportedFeature {
            feature: feature.to_string(),
        }
        .into())
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

    async fn supports_for<F, Fut>(
        &self,
        homeserver: &PublicKey,
        feature: &str,
        fetch: F,
    ) -> Result<bool>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<String>>>,
    {
        let cell = self.cell(homeserver);
        let mut cached = cell.lock().await;
        if let Some(features) = cached.as_ref().and_then(CachedFeatures::current) {
            return Ok(features.iter().any(|candidate| candidate == feature));
        }

        let features = fetch().await?;
        let supports = features.iter().any(|candidate| candidate == feature);
        *cached = Some(CachedFeatures {
            features,
            expires_at: Instant::now() + INFO_CACHE_TTL,
        });
        Ok(supports)
    }

    async fn fetch(&self, client: &PubkyHttpClient, homeserver: &PublicKey) -> Result<Vec<String>> {
        let request = client.homeserver_info_request(homeserver).await?;
        let response = request.timeout(self.request_timeout).send().await?;
        if info_endpoint_missing(response.status()) {
            return Ok(Vec::new());
        }
        let status = response.status();
        let body = Self::read_body(response).await?;
        if !status.is_success() {
            return Err(RequestError::Server {
                status,
                message: String::from_utf8_lossy(&body).into_owned(),
            }
            .into());
        }

        Self::decode(&body).ok_or_else(|| {
            RequestError::DecodeJson {
                message: "homeserver /info response is not a valid feature list".to_string(),
            }
            .into()
        })
    }

    async fn read_body(response: reqwest::Response) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk?;
            if !Self::append_chunk(&mut body, &chunk) {
                return Err(RequestError::DecodeJson {
                    message: format!("homeserver /info response exceeds {MAX_INFO_BYTES} bytes"),
                }
                .into());
            }
        }

        Ok(body)
    }

    fn append_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> bool {
        if body.len().saturating_add(chunk.len()) > MAX_INFO_BYTES {
            return false;
        }

        body.extend_from_slice(chunk);
        true
    }

    fn decode(body: &[u8]) -> Option<Vec<String>> {
        serde_json::from_slice::<InfoResponse>(body)
            .map(|response| response.features)
            .ok()
    }

    #[cfg(test)]
    pub(super) fn insert(&self, homeserver: &PublicKey, features: &[&str]) {
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
            expires_at: Instant::now() + INFO_CACHE_TTL,
        });
    }
}

fn info_endpoint_missing(status: StatusCode) -> bool {
    matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    #[test]
    fn limits_info_response_body() {
        let mut body = vec![b'x'; MAX_INFO_BYTES - 1];

        assert!(HomeserverFeatures::append_chunk(&mut body, b"x"));
        assert!(!HomeserverFeatures::append_chunk(&mut body, b"x"));
        assert_eq!(body.len(), MAX_INFO_BYTES);
    }

    #[test]
    fn missing_info_endpoint_is_treated_as_no_features() {
        assert!(info_endpoint_missing(StatusCode::NOT_FOUND));
        assert!(info_endpoint_missing(StatusCode::GONE));
        assert!(!info_endpoint_missing(StatusCode::INTERNAL_SERVER_ERROR));
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
    async fn coalesces_successful_feature_fetches() {
        let discovery = HomeserverFeatures::default();
        let homeserver = crate::Keypair::random().public_key();
        let calls = Arc::new(AtomicUsize::new(0));

        let first_calls = Arc::clone(&calls);
        let first = discovery.supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async move {
            first_calls.fetch_add(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
            Ok(vec![PATH_ADDRESSED_STORAGE.to_string()])
        });
        let second_calls = Arc::clone(&calls);
        let second = discovery.supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async move {
            second_calls.fetch_add(1, Ordering::Relaxed);
            Ok(Vec::new())
        });

        let (first, second) = tokio::join!(first, second);

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(first.unwrap());
        assert!(second.unwrap());

        let cached = discovery
            .supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(Vec::new())
            })
            .await
            .unwrap();
        assert!(cached);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn retries_feature_fetch_failures() {
        let discovery = HomeserverFeatures::default();
        let homeserver = crate::Keypair::random().public_key();
        let calls = AtomicUsize::new(0);

        let error = discovery
            .supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async {
                calls.fetch_add(1, Ordering::Relaxed);
                Err(RequestError::DecodeJson {
                    message: "invalid feature response".to_string(),
                }
                .into())
            })
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::Error::Request(RequestError::DecodeJson { .. })
        ));

        let supported = discovery
            .supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(vec![PATH_ADDRESSED_STORAGE.to_string()])
            })
            .await
            .unwrap();
        assert!(supported);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn refreshes_expired_features() {
        let discovery = HomeserverFeatures::default();
        let homeserver = crate::Keypair::random().public_key();
        let cell = discovery.cell(&homeserver);
        *cell.lock().await = Some(CachedFeatures {
            features: vec![PATH_ADDRESSED_STORAGE.to_string()],
            expires_at: Instant::now(),
        });

        let supported = discovery
            .supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async {
                Ok(Vec::new())
            })
            .await
            .unwrap();

        assert!(!supported);
    }
}
