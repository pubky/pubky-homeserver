use super::republish_summary::{RepublishResult, RepublishSummary};
use super::republisher::{RepublishOutcome, Republisher, RepublisherSettings};
use super::retrying_republisher::{RetrySettings, RetryingRepublisher};
use futures_util::{stream::FuturesUnordered, TryStreamExt};
use pkarr::{errors::BuildError, ClientBuilder, PublicKey, SignedPacket};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

type PublicKeyQueue = Mutex<Vec<PublicKey>>;

/// Settings for republishing a batch of keys.
#[derive(Debug, Clone)]
pub struct BatchRepublisherSettings {
    republisher: RepublisherSettings,
    retry: RetrySettings,
    max_concurrent_workers: NonZeroUsize,
}

impl Default for BatchRepublisherSettings {
    fn default() -> Self {
        Self {
            republisher: RepublisherSettings::default(),
            retry: RetrySettings::default(),
            max_concurrent_workers: NonZeroUsize::new(12).expect("worker count should be non-zero"),
        }
    }
}

impl BatchRepublisherSettings {
    /// Set a condition that packets must satisfy before they are republished.
    #[must_use]
    pub(crate) fn with_republish_condition<F>(mut self, condition: F) -> Self
    where
        F: Fn(&SignedPacket) -> bool + Send + Sync + 'static,
    {
        self.republisher.republish_condition = Some(Arc::new(condition));
        self
    }
}

/// Republish multiple keys serially or concurrently.
#[derive(Debug, Clone, Default)]
pub struct BatchRepublisher {
    settings: BatchRepublisherSettings,
    client_builder: ClientBuilder,
}

impl BatchRepublisher {
    /// Create a batch republisher with the provided settings.
    pub fn new(settings: BatchRepublisherSettings, client_builder: ClientBuilder) -> Self {
        Self {
            settings,
            client_builder,
        }
    }

    /// Republish keys concurrently with at most the configured number of active clients.
    ///
    /// # Errors
    ///
    /// Returns an error if a worker cannot build a pkarr client.
    pub async fn run(&self, public_keys: Vec<PublicKey>) -> Result<RepublishSummary, BuildError> {
        let worker_count = self
            .settings
            .max_concurrent_workers
            .get()
            .min(public_keys.len());
        let public_keys = Mutex::new(public_keys);

        (0..worker_count)
            .map(|_| self.run_worker(&public_keys))
            .collect::<FuturesUnordered<_>>()
            .try_fold(RepublishSummary::default(), merge_summaries)
            .await
    }

    async fn run_worker(
        &self,
        public_keys: &PublicKeyQueue,
    ) -> Result<RepublishSummary, BuildError> {
        let client = self.client_builder.build()?;
        let republisher = Republisher::new(client, self.settings.republisher.clone());
        let republisher = RetryingRepublisher::new(republisher, &self.settings.retry);

        let mut summary = RepublishSummary::default();
        while let Some(public_key) = pop(public_keys) {
            summary.record(republish_key(&republisher, &public_key).await);
        }
        Ok(summary)
    }
}

async fn republish_key(
    republisher: &RetryingRepublisher,
    public_key: &PublicKey,
) -> RepublishResult {
    let start = Instant::now();
    let result = republisher.republish(public_key).await;
    let elapsed = start.elapsed().as_millis();

    match &result {
        Ok(info) => match info.outcome {
            RepublishOutcome::Published => {
                tracing::info!(%public_key, ?info, %elapsed, "Republished successfully")
            }
            _ => tracing::debug!(%public_key, ?info, %elapsed, "Did not republish"),
        },
        Err(error) => tracing::warn!(%public_key, %error, %elapsed, "Republishing failed"),
    }
    result
}

async fn merge_summaries(
    summary: RepublishSummary,
    worker_summary: RepublishSummary,
) -> Result<RepublishSummary, BuildError> {
    Ok(summary.merge(worker_summary))
}

fn pop(public_keys: &PublicKeyQueue) -> Option<PublicKey> {
    public_keys
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pop()
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU8, NonZeroUsize};

    use pkarr::{dns::Name, Keypair, PublicKey};

    use super::super::test_client_builder;
    use super::{
        BatchRepublisher, BatchRepublisherSettings, RepublishSummary, RepublisherSettings,
    };

    async fn publish_sample_packets(client: &pkarr::Client, count: usize) -> Vec<PublicKey> {
        let keys: Vec<Keypair> = (0..count).map(|_| Keypair::random()).collect();
        for key in &keys {
            let packet = pkarr::SignedPacketBuilder::default()
                .cname(Name::new("test").unwrap(), Name::new("test2").unwrap(), 600)
                .build(key)
                .unwrap();
            client
                .publish(&packet)
                .await
                .expect("sample packet should publish");
        }

        keys.into_iter().map(|key| key.public_key()).collect()
    }

    async fn republish_keys(
        key_count: usize,
        max_concurrent_workers: NonZeroUsize,
        min_sufficient_node_publish_count: NonZeroU8,
    ) -> RepublishSummary {
        let dht = pkarr::mainline::Testnet::builder(3)
            .seeded(false)
            .build()
            .unwrap();
        let pkarr_builder = test_client_builder(&dht);
        let pkarr_client = pkarr_builder.clone().build().unwrap();
        let public_keys = publish_sample_packets(&pkarr_client, key_count).await;

        let settings = BatchRepublisherSettings {
            republisher: RepublisherSettings {
                min_sufficient_node_publish_count,
                ..RepublisherSettings::default()
            },
            max_concurrent_workers,
            ..BatchRepublisherSettings::default()
        };

        BatchRepublisher::new(settings, pkarr_builder)
            .run(public_keys)
            .await
            .unwrap()
    }

    async fn republish_single_key(
        min_sufficient_node_publish_count: NonZeroU8,
    ) -> RepublishSummary {
        republish_keys(1, NonZeroUsize::MIN, min_sufficient_node_publish_count).await
    }

    #[tokio::test]
    async fn single_key_republish_success() {
        let summary = republish_single_key(NonZeroU8::new(3).unwrap()).await;

        assert_eq!(summary.len(), 1);
        assert_eq!(summary.success_count(), 1);
    }

    #[tokio::test]
    async fn single_key_republish_insufficient() {
        let summary = republish_single_key(NonZeroU8::new(4).unwrap()).await;

        assert_eq!(summary.len(), 1);
        assert_eq!(summary.failed_count(), 1);
    }

    #[tokio::test]
    async fn multiple_keys_republish_with_multiple_workers() {
        let summary =
            republish_keys(5, NonZeroUsize::new(2).unwrap(), NonZeroU8::new(3).unwrap()).await;

        assert_eq!(summary.len(), 5);
        assert_eq!(summary.success_count(), 5);
        assert_eq!(summary.failed_count(), 0);
        assert_eq!(summary.missing_count(), 0);
        assert_eq!(summary.skipped_count(), 0);
        assert_eq!(summary.invalid_signed_packet_count(), 0);
        assert_eq!(
            summary.success_count()
                + summary.skipped_count()
                + summary.failed_count()
                + summary.missing_count()
                + summary.invalid_signed_packet_count(),
            summary.len()
        );
    }
}
