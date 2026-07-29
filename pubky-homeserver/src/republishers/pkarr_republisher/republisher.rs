//! Republishes a single public key using a cache-first state machine.
//!
//! Each attempt performs one cache lookup for state-machine decisions. Cache
//! misses and failures fall through to the network. If a cached packet cannot
//! be published, the same snapshot is compared with the network result so the
//! newest known valid packet is checked and published.
//! Packets returned by Pkarr resolution are assumed to belong to the requested
//! public key; enforcing that invariant belongs to Pkarr and its cache.
use pkarr::{
    errors::{PublishError, ResolveError},
    PublicKey, ResolvePolicy, SignedPacket, StoredNodeCount,
};
use std::{num::NonZeroU8, sync::Arc};

#[derive(thiserror::Error, Debug)]
pub(super) enum RepublishError {
    #[error("packet was published to only {published_nodes_count} nodes")]
    InsufficientlyPublished {
        published_nodes_count: StoredNodeCount,
    },
    #[error(transparent)]
    Publish(#[from] PublishError),
    #[error(transparent)]
    Resolve(#[from] ResolveError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RepublishOutcome {
    Published,
    Skipped,
    Missing,
    InvalidSignedPacket,
}

pub(super) type RepublishCondition = dyn Fn(&SignedPacket) -> bool + Send + Sync;

/// Settings for creating a republisher.
#[derive(Clone)]
pub(super) struct RepublisherSettings {
    pub(super) min_sufficient_node_publish_count: NonZeroU8,
    pub(super) republish_condition: Option<Arc<RepublishCondition>>,
}

impl std::fmt::Debug for RepublisherSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepublisherSettings")
            .field(
                "min_sufficient_node_publish_count",
                &self.min_sufficient_node_publish_count,
            )
            .field(
                "has_republish_condition",
                &self.republish_condition.is_some(),
            )
            .finish()
    }
}

impl Default for RepublisherSettings {
    fn default() -> Self {
        Self {
            min_sufficient_node_publish_count: NonZeroU8::new(10)
                .expect("default publish threshold is non-zero"),
            republish_condition: None,
        }
    }
}

/// Tries to republish a single key once.
#[derive(Debug)]
pub(super) struct Republisher {
    client: pkarr::Client,
    settings: RepublisherSettings,
}

impl Republisher {
    pub(super) fn new(client: pkarr::Client, settings: RepublisherSettings) -> Self {
        Self { client, settings }
    }

    /// Republish a single public key.
    pub(super) async fn republish(
        &self,
        public_key: &PublicKey,
    ) -> Result<RepublishOutcome, RepublishError> {
        let cached_packet = self.resolve_cached(public_key).await;

        if let Some(packet) = cached_packet.as_ref() {
            if self.try_publish_cached(packet).await? {
                return Ok(RepublishOutcome::Published);
            }
        }

        self.republish_latest(public_key, cached_packet).await
    }

    async fn resolve_cached(&self, public_key: &PublicKey) -> Option<SignedPacket> {
        match self
            .client
            .resolve(public_key, ResolvePolicy::CacheOnly)
            .await
        {
            Ok(packet) => Some(packet),
            Err(error) => {
                tracing::debug!(
                    %public_key,
                    %error,
                    "Cached PKARR resolution failed; falling back to network"
                );
                None
            }
        }
    }

    async fn try_publish_cached(&self, packet: &SignedPacket) -> Result<bool, RepublishError> {
        if !self.should_republish(packet) {
            return Ok(false);
        }

        // Mainline reports `NotMostRecent` only when concurrency rejections
        // form a *majority*. If newer state has reached only a minority of
        // queried nodes, this publish can succeed and propagate a stale cached
        // packet. Until partial conflicts are exposed, this fast path cannot
        // detect that case. See https://github.com/pubky/mainline/issues/113.

        // While the mainline issue is not resolve we do not try to publish.
        // match self.publish(packet).await {
        //     Ok(()) => Ok(true),
        //     Err(RepublishError::Publish(PublishError::NotMostRecent)) => Ok(false),
        //     Err(error) => Err(error),
        // }
        Ok(false)
    }

    async fn republish_latest(
        &self,
        public_key: &PublicKey,
        cached_packet: Option<SignedPacket>,
    ) -> Result<RepublishOutcome, RepublishError> {
        let network_packet = match self
            .client
            .resolve(public_key, ResolvePolicy::NetworkOnly)
            .await
        {
            Ok(packet) => Some(packet),
            Err(ResolveError::NotFound) => None,
            Err(ResolveError::InvalidSignedPacket { seq })
                if cached_packet
                    .as_ref()
                    .is_some_and(|packet| packet.timestamp().as_u64() as i64 >= seq) =>
            {
                None
            }
            Err(ResolveError::InvalidSignedPacket { .. }) => {
                return Ok(RepublishOutcome::InvalidSignedPacket);
            }
            Err(error) => return Err(error.into()),
        };

        let packet = match (network_packet, cached_packet) {
            (Some(network), Some(cached)) if cached.more_recent_than(&network) => cached,
            (Some(network), _) => network,
            (None, Some(cached)) => cached,
            (None, None) => return Ok(RepublishOutcome::Missing),
        };

        if !self.should_republish(&packet) {
            return Ok(RepublishOutcome::Skipped);
        }

        self.publish(&packet).await?;
        Ok(RepublishOutcome::Published)
    }

    fn should_republish(&self, packet: &SignedPacket) -> bool {
        self.settings
            .republish_condition
            .as_ref()
            .is_none_or(|condition| condition(packet))
    }

    async fn publish(&self, packet: &SignedPacket) -> Result<(), RepublishError> {
        let published_nodes_count = self.client.publish(packet).await?;
        if published_nodes_count
            < StoredNodeCount::from(self.settings.min_sufficient_node_publish_count.get())
        {
            return Err(RepublishError::InsufficientlyPublished {
                published_nodes_count,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_client_builder;
    use super::*;
    use pkarr::{dns::Name, Cache, CacheKey, InMemoryCache, Keypair, Timestamp};
    use std::{
        num::NonZeroUsize,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[derive(Clone, Debug)]
    struct CountingCache {
        inner: InMemoryCache,
        reads: Arc<AtomicUsize>,
    }

    impl CountingCache {
        fn new() -> Self {
            Self {
                inner: InMemoryCache::new(NonZeroUsize::MIN),
                reads: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::Relaxed)
        }
    }

    impl Cache for CountingCache {
        fn capacity(&self) -> usize {
            self.inner.capacity()
        }

        fn len(&self) -> usize {
            self.inner.len()
        }

        fn put(&self, key: &CacheKey, signed_packet: &SignedPacket) {
            self.inner.put(key, signed_packet);
        }

        fn get(&self, key: &CacheKey) -> Option<SignedPacket> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.inner.get(key)
        }

        fn get_read_only(&self, key: &CacheKey) -> Option<SignedPacket> {
            self.inner.get_read_only(key)
        }
    }

    fn sample_packet(key: &Keypair, timestamp: Timestamp) -> SignedPacket {
        pkarr::SignedPacketBuilder::default()
            .cname(Name::new("test").unwrap(), Name::new("test2").unwrap(), 600)
            .timestamp(timestamp)
            .build(key)
            .unwrap()
    }

    async fn publish_invalid_signed_packet(
        testnet: &pkarr::mainline::Testnet,
        key: &Keypair,
        seq: i64,
    ) {
        let item = pkarr::mainline::MutableItem::new(
            key.secret_key().into(),
            b"invalid signed packet",
            seq,
            None,
        );
        testnet.nodes[0]
            .clone()
            .as_async()
            .put_mutable(item, None)
            .await
            .unwrap();
    }

    async fn publish_sample_packet(client: &pkarr::Client) -> PublicKey {
        let key = Keypair::random();
        let packet = sample_packet(&key, Timestamp::now());
        client
            .publish(&packet)
            .await
            .expect("sample packet should publish");

        key.public_key()
    }

    fn test_settings() -> RepublisherSettings {
        RepublisherSettings {
            min_sufficient_node_publish_count: NonZeroU8::MIN,
            ..RepublisherSettings::default()
        }
    }

    #[tokio::test]
    async fn republish_returns_published_for_resolved_packet() {
        let dht = pkarr::mainline::Testnet::builder(1).build().unwrap();
        let pkarr_builder = test_client_builder(&dht);
        let pkarr_client = pkarr_builder.build().unwrap();
        let public_key = publish_sample_packet(&pkarr_client).await;

        let settings = test_settings();
        let republisher = Republisher::new(pkarr_client, settings);
        let outcome = republisher.republish(&public_key).await.unwrap();

        assert_eq!(outcome, RepublishOutcome::Published);
    }

    #[tokio::test]
    async fn cache_miss_resolves_and_publishes_packet_from_network() {
        let dht = pkarr::mainline::Testnet::builder(1).build().unwrap();
        let pkarr_builder = test_client_builder(&dht);
        let publishing_client = pkarr_builder.clone().build().unwrap();
        let public_key = publish_sample_packet(&publishing_client).await;
        let republishing_client = pkarr_builder.build().unwrap();
        let settings = test_settings();
        let republisher = Republisher::new(republishing_client, settings);

        let outcome = republisher.republish(&public_key).await.unwrap();

        assert_eq!(outcome, RepublishOutcome::Published);
    }

    #[tokio::test]
    async fn relay_cache_failure_falls_back_to_dht() {
        let dht = pkarr::mainline::Testnet::builder(1).build().unwrap();
        let pkarr_builder = test_client_builder(&dht);
        let publishing_client = pkarr_builder.clone().build().unwrap();
        let public_key = publish_sample_packet(&publishing_client).await;

        let mut combined_builder = pkarr_builder;
        combined_builder
            .relays(&["http://127.0.0.1:1"])
            .unwrap()
            .request_timeout(Duration::from_millis(100));
        let combined_client = combined_builder.build().unwrap();

        assert_eq!(
            combined_client
                .resolve(&public_key, ResolvePolicy::CacheOnly)
                .await,
            Err(ResolveError::NoResponses)
        );

        let republisher = Republisher::new(combined_client, test_settings());
        let outcome = republisher.republish(&public_key).await.unwrap();

        assert_eq!(outcome, RepublishOutcome::Published);
    }

    #[tokio::test]
    async fn republish_returns_missing_for_unknown_key() {
        let dht = pkarr::mainline::Testnet::builder(1).build().unwrap();
        let pkarr_builder = test_client_builder(&dht);
        let pkarr_client = pkarr_builder.build().unwrap();
        let public_key = Keypair::random().public_key();

        let settings = test_settings();
        let republisher = Republisher::new(pkarr_client, settings);
        let outcome = republisher.republish(&public_key).await.unwrap();

        assert_eq!(outcome, RepublishOutcome::Missing);
    }

    #[tokio::test]
    async fn republish_returns_skipped_when_condition_rejects_packet() {
        let dht = pkarr::mainline::Testnet::builder(1).build().unwrap();
        let pkarr_builder = test_client_builder(&dht);
        let pkarr_client = pkarr_builder.build().unwrap();
        let public_key = publish_sample_packet(&pkarr_client).await;

        let condition_calls = Arc::new(AtomicUsize::new(0));
        let calls = condition_calls.clone();
        let settings = RepublisherSettings {
            republish_condition: Some(Arc::new(move |_| {
                calls.fetch_add(1, Ordering::Relaxed);
                false
            })),
            ..test_settings()
        };

        let republisher = Republisher::new(pkarr_client, settings);
        let outcome = republisher.republish(&public_key).await.unwrap();

        assert_eq!(outcome, RepublishOutcome::Skipped);
        assert_eq!(condition_calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn network_fallback_does_not_resolve_cached_packet_again() {
        let dht = pkarr::mainline::Testnet::builder(1).build().unwrap();
        let mut pkarr_builder = test_client_builder(&dht);
        let publishing_client = pkarr_builder.clone().build().unwrap();
        let key = Keypair::random();
        let packet = sample_packet(&key, Timestamp::now());
        publishing_client.publish(&packet).await.unwrap();

        let cache = Arc::new(CountingCache::new());
        cache.put(&CacheKey::from(key.public_key()), &packet);
        pkarr_builder.cache(cache.clone());
        let republishing_client = pkarr_builder.build().unwrap();
        let settings = RepublisherSettings {
            republish_condition: Some(Arc::new(|_| false)),
            ..test_settings()
        };
        let republisher = Republisher::new(republishing_client, settings);

        let outcome = republisher.republish(&key.public_key()).await.unwrap();

        assert_eq!(outcome, RepublishOutcome::Skipped);
        assert_eq!(cache.reads(), 1);
    }

    #[tokio::test]
    async fn latest_resolution_prefers_newer_cached_packet_over_network_packet() {
        let dht = pkarr::mainline::Testnet::builder(1).build().unwrap();
        let mut pkarr_builder = test_client_builder(&dht);
        let publishing_client = pkarr_builder.clone().build().unwrap();
        let key = Keypair::random();
        let network_packet = sample_packet(&key, Timestamp::from(10));
        publishing_client.publish(&network_packet).await.unwrap();

        let cached_packet = sample_packet(&key, Timestamp::from(11));
        let cache = Arc::new(InMemoryCache::new(NonZeroUsize::MIN));
        cache.put(&CacheKey::from(key.public_key()), &cached_packet);
        pkarr_builder.cache(cache);
        let republishing_client = pkarr_builder.build().unwrap();
        let network_timestamp = network_packet.timestamp();
        let settings = RepublisherSettings {
            republish_condition: Some(Arc::new(move |packet| {
                packet.timestamp() == network_timestamp
            })),
            ..test_settings()
        };
        let republisher = Republisher::new(republishing_client, settings);

        let outcome = republisher.republish(&key.public_key()).await.unwrap();

        assert_eq!(outcome, RepublishOutcome::Skipped);
    }

    #[tokio::test]
    async fn latest_resolution_prefers_cached_packet_over_covered_invalid_sequence() {
        let dht = pkarr::mainline::Testnet::builder(3).build().unwrap();
        let mut pkarr_builder = test_client_builder(&dht);
        let key = Keypair::random();
        let cached_packet = sample_packet(&key, Timestamp::from(10));
        let cache = Arc::new(InMemoryCache::new(NonZeroUsize::MIN));
        cache.put(&CacheKey::from(key.public_key()), &cached_packet);
        pkarr_builder.cache(cache);
        publish_invalid_signed_packet(&dht, &key, 10).await;

        let republisher = Republisher::new(
            pkarr_builder.build().unwrap(),
            RepublisherSettings {
                republish_condition: Some(Arc::new(|_| false)),
                ..test_settings()
            },
        );

        let outcome = republisher.republish(&key.public_key()).await.unwrap();

        assert_eq!(outcome, RepublishOutcome::Skipped);
    }

    #[tokio::test]
    async fn latest_resolution_reports_invalid_sequence_newer_than_cached_packet() {
        let dht = pkarr::mainline::Testnet::builder(3).build().unwrap();
        let mut pkarr_builder = test_client_builder(&dht);
        let key = Keypair::random();
        let cached_packet = sample_packet(&key, Timestamp::from(10));
        let cache = Arc::new(InMemoryCache::new(NonZeroUsize::MIN));
        cache.put(&CacheKey::from(key.public_key()), &cached_packet);
        pkarr_builder.cache(cache);
        publish_invalid_signed_packet(&dht, &key, 11).await;

        let republisher = Republisher::new(
            pkarr_builder.build().unwrap(),
            RepublisherSettings {
                republish_condition: Some(Arc::new(|_| false)),
                ..test_settings()
            },
        );

        let outcome = republisher.republish(&key.public_key()).await.unwrap();

        assert_eq!(outcome, RepublishOutcome::InvalidSignedPacket);
    }

    #[tokio::test]
    async fn cached_publish_conflict_resolves_and_publishes_newer_packet() {
        let dht = pkarr::mainline::Testnet::builder(1).build().unwrap();
        let mut pkarr_builder = test_client_builder(&dht);
        let publishing_client = pkarr_builder.clone().build().unwrap();
        let key = Keypair::random();
        let stale_packet = sample_packet(&key, Timestamp::from(10));
        let latest_packet = sample_packet(&key, Timestamp::from(11));
        publishing_client.publish(&latest_packet).await.unwrap();

        let cache = Arc::new(InMemoryCache::new(NonZeroUsize::MIN));
        cache.put(&CacheKey::from(key.public_key()), &stale_packet);
        pkarr_builder.cache(cache);
        let republishing_client = pkarr_builder.build().unwrap();
        let settings = RepublisherSettings {
            republish_condition: Some(Arc::new(|_| true)),
            ..test_settings()
        };
        let republisher = Republisher::new(republishing_client, settings);

        let outcome = republisher.republish(&key.public_key()).await.unwrap();

        assert_eq!(outcome, RepublishOutcome::Published);
    }

    #[tokio::test]
    async fn republish_returns_published_when_condition_accepts_packet() {
        let dht = pkarr::mainline::Testnet::builder(1).build().unwrap();
        let pkarr_builder = test_client_builder(&dht);
        let pkarr_client = pkarr_builder.build().unwrap();
        let public_key = publish_sample_packet(&pkarr_client).await;

        let settings = RepublisherSettings {
            republish_condition: Some(Arc::new(|_| true)),
            ..test_settings()
        };

        let republisher = Republisher::new(pkarr_client, settings);
        let outcome = republisher.republish(&public_key).await.unwrap();

        assert_eq!(outcome, RepublishOutcome::Published);
    }

    #[tokio::test]
    async fn republish_returns_publish_error_when_insufficiently_published() {
        let dht = pkarr::mainline::Testnet::builder(1).build().unwrap();
        let pkarr_builder = test_client_builder(&dht);
        let pkarr_client = pkarr_builder.build().unwrap();
        let public_key = publish_sample_packet(&pkarr_client).await;

        let settings = RepublisherSettings {
            min_sufficient_node_publish_count: NonZeroU8::new(2).unwrap(),
            ..RepublisherSettings::default()
        };
        let republisher = Republisher::new(pkarr_client, settings);
        let result = republisher.republish(&public_key).await;

        assert!(matches!(
            result,
            Err(RepublishError::InsufficientlyPublished {
                published_nodes_count: 1
            })
        ));
    }
}
