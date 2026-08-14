use std::{future::Future, num::NonZeroU8, time::Duration};

use backon::{ExponentialBuilder, Retryable};
use pkarr::PublicKey;

use super::republisher::{RepublishError, RepublishOutcome, Republisher};

#[derive(Debug, Clone)]
pub(super) struct RepublishInfo {
    /// Result of the republish attempt.
    pub(super) outcome: RepublishOutcome,
    /// Number of republish attempts needed to finish processing the key.
    #[allow(dead_code)]
    pub(super) attempts_needed: usize,
}

impl RepublishInfo {
    pub(super) fn new(outcome: RepublishOutcome, attempts_needed: usize) -> Self {
        Self {
            outcome,
            attempts_needed,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct RetrySettings {
    /// Maximum number of republish attempts before giving up.
    max_attempts: NonZeroU8,
    /// First retry delay used to calculate the exponential backoff.
    /// Example: 100ms first, then 200ms, 400ms, 800ms and so on.
    initial_retry_delay: Duration,
    /// Cap on the retry delay so the exponential backoff doesn't get out of hand.
    max_retry_delay: Duration,
}

impl RetrySettings {
    fn backoff(&self) -> ExponentialBuilder {
        ExponentialBuilder::default()
            .with_factor(2.0)
            .with_jitter()
            .with_min_delay(self.initial_retry_delay.min(self.max_retry_delay))
            .with_max_delay(self.max_retry_delay)
            // BackON counts delayed retries; our setting counts the initial attempt too.
            .with_max_times(usize::from(self.max_attempts.get() - 1))
    }
}

impl Default for RetrySettings {
    fn default() -> Self {
        Self {
            max_attempts: NonZeroU8::new(4).expect("should always be > 0"),
            initial_retry_delay: Duration::from_millis(200),
            max_retry_delay: Duration::from_secs(5),
        }
    }
}

/// Adds retry behavior to a [`Republisher`].
#[derive(Debug)]
pub(super) struct RetryingRepublisher {
    republisher: Republisher,
    backoff: ExponentialBuilder,
    max_retry_delay: Duration,
}

impl RetryingRepublisher {
    pub(super) fn new(republisher: Republisher, settings: &RetrySettings) -> Self {
        Self {
            republisher,
            backoff: settings.backoff(),
            max_retry_delay: settings.max_retry_delay,
        }
    }

    /// Republishes a pkarr packet with retries.
    pub(super) async fn republish(
        &self,
        public_key: &PublicKey,
    ) -> Result<RepublishInfo, RepublishError> {
        republish_with_retry(public_key, self.backoff, self.max_retry_delay, || {
            self.republisher.republish(public_key)
        })
        .await
    }
}

async fn republish_with_retry<F, Fut>(
    public_key: &PublicKey,
    backoff: ExponentialBuilder,
    max_retry_delay: Duration,
    republish: F,
) -> Result<RepublishInfo, RepublishError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<RepublishOutcome, RepublishError>>,
{
    let mut attempts_count = 1;

    republish
        .retry(backoff)
        // BackON adds jitter after applying its maximum delay.
        .adjust(|_, delay| delay.map(|delay| delay.min(max_retry_delay)))
        .notify(|error, delay| {
            tracing::debug!(
                %public_key,
                %error,
                %attempts_count,
                ?delay,
                "retrying republish"
            );
            attempts_count += 1;
        })
        .await
        .map(|outcome| RepublishInfo::new(outcome, attempts_count))
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, future::ready, num::NonZeroU8, time::Duration};

    use backon::BackoffBuilder;
    use pkarr::Keypair;

    use super::{republish_with_retry, RepublishError, RepublishOutcome, RetrySettings};

    fn retry_settings(max_attempts: u8) -> RetrySettings {
        RetrySettings {
            max_attempts: NonZeroU8::new(max_attempts).unwrap(),
            initial_retry_delay: Duration::ZERO,
            ..RetrySettings::default()
        }
    }

    fn publish_error() -> RepublishError {
        RepublishError::InsufficientlyPublished {
            published_nodes_count: 0,
        }
    }

    fn resolve_error() -> RepublishError {
        RepublishError::Resolve(pkarr::errors::ResolveError::NoResponses)
    }

    #[test]
    fn retry_backoff_is_jittered_and_exponential() {
        let mut settings = retry_settings(10);
        settings.initial_retry_delay = Duration::from_millis(100);
        settings.max_retry_delay = Duration::from_secs(10);

        let delays: Vec<_> = settings.backoff().with_jitter_seed(0).build().collect();
        let base_delays = [
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(400),
            Duration::from_millis(800),
            Duration::from_millis(1_600),
            Duration::from_millis(3_200),
            Duration::from_millis(6_400),
            Duration::from_secs(10),
            Duration::from_secs(10),
        ];

        assert_eq!(delays.len(), base_delays.len());
        for (delay, base_delay) in delays.into_iter().zip(base_delays) {
            assert!(delay >= base_delay);
            assert!(delay < base_delay.saturating_mul(2));
        }
    }

    #[test]
    fn retry_backoff_excludes_initial_attempt() {
        assert_eq!(retry_settings(10).backoff().build().count(), 9);
        assert!(retry_settings(1).backoff().build().next().is_none());
    }

    #[tokio::test]
    async fn retries_publish_errors_until_success() {
        let public_key = Keypair::random().public_key();
        let settings = retry_settings(3);
        let attempts = Cell::new(0);

        let info = republish_with_retry(
            &public_key,
            settings.backoff(),
            settings.max_retry_delay,
            || {
                let attempt = attempts.get() + 1;
                attempts.set(attempt);
                ready(if attempt < 3 {
                    Err(publish_error())
                } else {
                    Ok(RepublishOutcome::Published)
                })
            },
        )
        .await
        .unwrap();

        assert_eq!(attempts.get(), 3);
        assert_eq!(info.attempts_needed, 3);
        assert_eq!(info.outcome, RepublishOutcome::Published);
    }

    #[tokio::test]
    async fn retries_resolve_errors_until_success() {
        let public_key = Keypair::random().public_key();
        let settings = retry_settings(2);
        let attempts = Cell::new(0);

        let info = republish_with_retry(
            &public_key,
            settings.backoff(),
            settings.max_retry_delay,
            || {
                let attempt = attempts.get() + 1;
                attempts.set(attempt);
                ready(if attempt == 1 {
                    Err(resolve_error())
                } else {
                    Ok(RepublishOutcome::Published)
                })
            },
        )
        .await
        .unwrap();

        assert_eq!(attempts.get(), 2);
        assert_eq!(info.attempts_needed, 2);
        assert_eq!(info.outcome, RepublishOutcome::Published);
    }

    #[tokio::test]
    async fn returns_missing_outcome_without_retrying() {
        let public_key = Keypair::random().public_key();
        let settings = retry_settings(3);
        let attempts = Cell::new(0);

        let result = republish_with_retry(
            &public_key,
            settings.backoff(),
            settings.max_retry_delay,
            || {
                attempts.set(attempts.get() + 1);
                ready(Ok(RepublishOutcome::Missing))
            },
        )
        .await
        .unwrap();

        assert_eq!(result.outcome, RepublishOutcome::Missing);
        assert_eq!(result.attempts_needed, 1);
        assert_eq!(attempts.get(), 1);
    }

    #[tokio::test]
    async fn stops_after_maximum_attempts() {
        let public_key = Keypair::random().public_key();
        let settings = retry_settings(3);
        let attempts = Cell::new(0);

        let result = republish_with_retry(
            &public_key,
            settings.backoff(),
            settings.max_retry_delay,
            || {
                attempts.set(attempts.get() + 1);
                ready(Err(publish_error()))
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(RepublishError::InsufficientlyPublished { .. })
        ));
        assert_eq!(attempts.get(), 3);
    }
}
