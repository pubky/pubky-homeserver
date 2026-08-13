use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
};

use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::OnceCell;

use crate::{Pkdns, PubkyHttpClient, PublicKey};

const MAX_INFO_BYTES: usize = 16 * 1024;
type FeatureCell = Arc<OnceCell<Vec<String>>>;

#[derive(Debug, Clone, Default)]
pub(crate) struct HomeserverFeatures {
    servers: Arc<Mutex<HashMap<PublicKey, FeatureCell>>>,
}

#[derive(Deserialize)]
struct InfoResponse {
    features: Vec<String>,
}

impl HomeserverFeatures {
    pub(super) async fn supports(
        &self,
        client: &PubkyHttpClient,
        owner: &PublicKey,
        homeserver: Option<&PublicKey>,
        feature: &str,
    ) -> bool {
        let homeserver = if let Some(homeserver) = homeserver {
            homeserver.clone()
        } else {
            let Ok(Some(homeserver)) = Pkdns::with_client(client.clone())
                .get_homeserver_of(owner)
                .await
            else {
                return false;
            };
            homeserver
        };
        let cell = self.cell(&homeserver);
        let features = cell.get_or_init(|| Self::fetch(client, &homeserver)).await;

        features.iter().any(|candidate| candidate == feature)
    }

    fn cell(&self, homeserver: &PublicKey) -> FeatureCell {
        let mut servers = self.servers.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(servers.entry(homeserver.clone()).or_default())
    }

    async fn fetch(client: &PubkyHttpClient, homeserver: &PublicKey) -> Vec<String> {
        let Ok(request) = client.homeserver_info_request(homeserver).await else {
            return Vec::new();
        };
        let Ok(response) = request.send().await else {
            return Vec::new();
        };
        if !response.status().is_success() {
            return Vec::new();
        }

        let mut body = Vec::new();
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let Ok(chunk) = chunk else {
                return Vec::new();
            };
            if !Self::append_chunk(&mut body, &chunk) {
                return Vec::new();
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

    fn decode(body: &[u8]) -> Vec<String> {
        serde_json::from_slice::<InfoResponse>(body)
            .map_or_else(|_error| Vec::new(), |response| response.features)
    }

    #[cfg(test)]
    pub(super) fn insert(&self, homeserver: &PublicKey, features: &[&str]) {
        self.cell(homeserver)
            .set(features.iter().map(ToString::to_string).collect())
            .expect("homeserver features were already initialized");
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
                true,
            ),
            (br#"{"features":[]}"#, false),
            (br#"{"features":["unknown"]}"#, false),
            (br#"{"features":{}}"#, false),
            (br"{}", false),
            (b"not json", false),
        ];

        for (body, expected) in cases {
            assert_eq!(
                HomeserverFeatures::decode(body)
                    .iter()
                    .any(|candidate| candidate == PATH_ADDRESSED_STORAGE),
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
    async fn stores_negative_results_and_coalesces_feature_fetches() {
        let discovery = HomeserverFeatures::default();
        let homeserver = crate::Keypair::random().public_key();
        let cell = discovery.cell(&homeserver);
        let calls = Arc::new(AtomicUsize::new(0));

        let first_calls = Arc::clone(&calls);
        let first = cell.get_or_init(|| async move {
            first_calls.fetch_add(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
            Vec::new()
        });
        let second_calls = Arc::clone(&calls);
        let second = cell.get_or_init(|| async move {
            second_calls.fetch_add(1, Ordering::Relaxed);
            vec![PATH_ADDRESSED_STORAGE.to_string()]
        });

        let (first, second) = tokio::join!(first, second);

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(first.is_empty());
        assert!(second.is_empty());

        let cached = cell
            .get_or_init(|| async {
                calls.fetch_add(1, Ordering::Relaxed);
                Vec::new()
            })
            .await;
        assert!(cached.is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
