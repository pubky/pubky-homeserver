use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::Mutex as AsyncMutex;
use web_time::Instant;

use crate::{PubkyHttpClient, PublicKey};

const MAX_INFO_BYTES: usize = 16 * 1024;
const INFO_TIMEOUT: Duration = Duration::from_secs(5);
const FAILED_INFO_RETRY_INTERVAL: Duration = Duration::from_secs(60);
type FeatureCell = Arc<AsyncMutex<Option<CachedFeatures>>>;

#[derive(Debug, Clone, Default)]
pub(crate) struct HomeserverFeatures {
    servers: Arc<Mutex<HashMap<PublicKey, FeatureCell>>>,
}

#[derive(Deserialize)]
struct InfoResponse {
    features: Vec<String>,
}

#[derive(Debug)]
enum CachedFeatures {
    Available(Vec<String>),
    UnavailableUntil(Instant),
}

impl CachedFeatures {
    fn current(&self) -> Option<&[String]> {
        match self {
            Self::Available(features) => Some(features),
            Self::UnavailableUntil(retry_at) if Instant::now() < *retry_at => Some(&[]),
            Self::UnavailableUntil(_) => None,
        }
    }
}

impl HomeserverFeatures {
    pub(super) async fn supports(
        &self,
        client: &PubkyHttpClient,
        homeserver: &PublicKey,
        feature: &str,
    ) -> bool {
        self.supports_for(homeserver, feature, || Self::fetch(client, homeserver))
            .await
    }

    fn cell(&self, homeserver: &PublicKey) -> FeatureCell {
        let mut servers = self.servers.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(servers.entry(homeserver.clone()).or_default())
    }

    async fn supports_for<F, Fut>(&self, homeserver: &PublicKey, feature: &str, fetch: F) -> bool
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Option<Vec<String>>>,
    {
        let cell = self.cell(homeserver);
        let mut cached = cell.lock().await;
        if let Some(features) = cached.as_ref().and_then(CachedFeatures::current) {
            return features.iter().any(|candidate| candidate == feature);
        }

        let Some(features) = fetch().await else {
            *cached = Some(CachedFeatures::UnavailableUntil(
                Instant::now() + FAILED_INFO_RETRY_INTERVAL,
            ));
            return false;
        };
        let supports = features.iter().any(|candidate| candidate == feature);
        *cached = Some(CachedFeatures::Available(features));
        supports
    }

    async fn fetch(client: &PubkyHttpClient, homeserver: &PublicKey) -> Option<Vec<String>> {
        let Ok(request) = client.homeserver_info_request(homeserver).await else {
            return None;
        };
        let Ok(response) = request.timeout(INFO_TIMEOUT).send().await else {
            return None;
        };
        if !response.status().is_success() {
            return None;
        }

        let mut body = Vec::new();
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let Ok(chunk) = chunk else {
                return None;
            };
            if !Self::append_chunk(&mut body, &chunk) {
                return None;
            }
        }

        Self::decode(&body)
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
        *cached = Some(CachedFeatures::Available(
            features.iter().map(ToString::to_string).collect(),
        ));
    }
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

    #[tokio::test]
    async fn temporarily_stores_failures_and_coalesces_feature_fetches() {
        let discovery = HomeserverFeatures::default();
        let homeserver = crate::Keypair::random().public_key();
        let calls = Arc::new(AtomicUsize::new(0));

        let first_calls = Arc::clone(&calls);
        let first = discovery.supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async move {
            first_calls.fetch_add(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
            None
        });
        let second_calls = Arc::clone(&calls);
        let second = discovery.supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async move {
            second_calls.fetch_add(1, Ordering::Relaxed);
            Some(vec![PATH_ADDRESSED_STORAGE.to_string()])
        });

        let (first, second) = tokio::join!(first, second);

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(!first);
        assert!(!second);

        let cached = discovery
            .supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async {
                calls.fetch_add(1, Ordering::Relaxed);
                Some(Vec::new())
            })
            .await;
        assert!(!cached);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn retries_expired_failures() {
        let discovery = HomeserverFeatures::default();
        let homeserver = crate::Keypair::random().public_key();
        let cell = discovery.cell(&homeserver);
        *cell.lock().await = Some(CachedFeatures::UnavailableUntil(Instant::now()));

        let supported = discovery
            .supports_for(&homeserver, PATH_ADDRESSED_STORAGE, || async {
                Some(vec![PATH_ADDRESSED_STORAGE.to_string()])
            })
            .await;

        assert!(supported);
    }
}
