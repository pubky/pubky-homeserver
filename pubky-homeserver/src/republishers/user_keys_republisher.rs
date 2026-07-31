use std::time::Duration;

use pkarr::{dns::rdata::RData, errors::BuildError, SignedPacket};
use pubky_common::crypto::PublicKey;
use tokio::{
    task::JoinHandle,
    time::{interval, Instant},
};

use super::pkarr_republisher::{BatchRepublisher, BatchRepublisherSettings, RepublishSummary};
use crate::persistence::sql::{user::UserRepository, SqlDb};

const MIN_REPUBLISH_INTERVAL: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, thiserror::Error)]
pub(crate) enum UserKeysRepublisherError {
    #[error(transparent)]
    DB(#[from] sqlx::Error),
    #[error(transparent)]
    Pkarr(#[from] BuildError),
}

/// Publishes the pkarr keys of all users to the Mainline DHT.
pub(crate) struct UserKeysRepublisherJob {
    handle: JoinHandle<()>,
}

impl UserKeysRepublisherJob {
    const INITIAL_DELAY_BEFORE_REPUBLISH: Duration = Duration::from_secs(60);

    /// Run the user keys republisher with an initial delay.
    pub fn start(
        db: SqlDb,
        pkarr_builder: pkarr::ClientBuilder,
        homeserver_public_key: PublicKey,
        mut republish_interval: Duration,
    ) -> Option<Self> {
        if republish_interval.is_zero() {
            tracing::info!("User keys republisher is disabled.");
            return None;
        }
        if republish_interval < MIN_REPUBLISH_INTERVAL {
            tracing::warn!(
                "The configured user keys republisher interval is less than {}s. To avoid spamming the Mainline DHT, the value is set to {}s.",
                MIN_REPUBLISH_INTERVAL.as_secs(),
                MIN_REPUBLISH_INTERVAL.as_secs()
            );
            republish_interval = MIN_REPUBLISH_INTERVAL;
        }
        tracing::info!(
            "Initialize user keys republisher with an interval of {:?} and an initial delay of {:?}",
            republish_interval,
            Self::INITIAL_DELAY_BEFORE_REPUBLISH
        );

        if republish_interval < Duration::from_secs(60 * 60) {
            tracing::warn!(
                "User keys republisher interval is less than 60min. This is strongly discouraged "
            );
        }

        let republisher = UserKeysRepublisher {
            db,
            pkarr_builder,
            homeserver_public_key,
        };
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Self::INITIAL_DELAY_BEFORE_REPUBLISH).await;
            let mut interval = interval(republish_interval);
            loop {
                interval.tick().await;
                republisher.republish().await;
            }
        });
        Some(Self { handle })
    }
}

impl Drop for UserKeysRepublisherJob {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

struct UserKeysRepublisher {
    db: SqlDb,
    pkarr_builder: pkarr::ClientBuilder,
    homeserver_public_key: PublicKey,
}

impl UserKeysRepublisher {
    async fn republish(&self) {
        let start = Instant::now();
        tracing::debug!("Republishing user keys...");
        let summary = match self.republish_impl().await {
            Ok(summary) if summary.is_empty() => return,
            Ok(summary) => summary,
            Err(e) => {
                tracing::error!("Error republishing user keys: {e:?}");
                return;
            }
        };
        let elapsed = start.elapsed();
        if summary.has_issues() {
            tracing::warn!(?summary, ?elapsed, "Processed user keys");
        } else {
            tracing::debug!(?summary, ?elapsed, "Processed user keys");
        }
    }

    async fn republish_impl(&self) -> Result<RepublishSummary, UserKeysRepublisherError> {
        let keys = self.get_all_user_keys().await?;
        if keys.is_empty() {
            tracing::debug!("No user keys to republish.");
            return Ok(RepublishSummary::default());
        }
        let homeserver_public_key = self.homeserver_public_key.clone();
        let settings =
            BatchRepublisherSettings::default().with_republish_condition(move |packet| {
                packet_points_to_homeserver(packet, &homeserver_public_key)
            });
        let republisher = BatchRepublisher::new(settings, self.pkarr_builder.clone());
        let pkarr_keys = keys.into_iter().map(Into::into).collect();
        Ok(republisher.run(pkarr_keys).await?)
    }

    async fn get_all_user_keys(&self) -> Result<Vec<PublicKey>, sqlx::Error> {
        let users = UserRepository::get_all(&mut self.db.pool().into()).await?;
        Ok(users.into_iter().map(|user| user.public_key).collect())
    }
}

fn packet_points_to_homeserver(packet: &SignedPacket, homeserver_public_key: &PublicKey) -> bool {
    packet
        .resource_records("_pubky")
        .find_map(|record| match &record.rdata {
            RData::SVCB(svcb) => Some(svcb.target.to_string()),
            RData::HTTPS(https) => Some(https.0.target.to_string()),
            _ => None,
        })
        .and_then(|target| PublicKey::try_from_z32(&target).ok())
        .is_some_and(|target| target == *homeserver_public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::sql::user::UserRepository;
    use crate::persistence::sql::SqlDb;
    use crate::republishers::pkarr_republisher::test_client_builder;
    use pkarr::dns::rdata::SVCB;
    use pubky_common::crypto::Keypair;

    fn packet_with_https_homeserver(user: &Keypair, homeserver: &str) -> SignedPacket {
        SignedPacket::builder()
            .https(
                "_pubky".try_into().unwrap(),
                SVCB::new(0, homeserver.try_into().unwrap()),
                3600,
            )
            .sign(user)
            .unwrap()
    }

    fn packet_with_svcb_homeserver(user: &Keypair, homeserver: &str) -> SignedPacket {
        SignedPacket::builder()
            .svcb(
                "_pubky".try_into().unwrap(),
                SVCB::new(0, homeserver.try_into().unwrap()),
                3600,
            )
            .sign(user)
            .unwrap()
    }

    async fn init_db_with_users(count: usize) -> SqlDb {
        let db = SqlDb::test().await;
        for _ in 0..count {
            let public_key = Keypair::random().public_key();
            UserRepository::create(&public_key, &mut db.pool().into())
                .await
                .unwrap();
        }
        db
    }

    /// Test that the republisher tries to republish all keys passed.
    #[tokio::test]
    #[pubky_test_utils::test]
    async fn test_republish_keys_once() {
        let db = init_db_with_users(10).await;
        let dht = pkarr::mainline::Testnet::builder(1).build().unwrap();
        let pkarr_builder = test_client_builder(&dht);
        let worker = UserKeysRepublisher {
            db,
            pkarr_builder,
            homeserver_public_key: Keypair::random().public_key(),
        };
        let summary = worker.republish_impl().await.unwrap();
        assert_eq!(summary.len(), 10);
        assert_eq!(summary.success_count(), 0);
        assert_eq!(summary.missing_count(), 10);
        assert_eq!(summary.failed_count(), 0);
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn user_pointing_to_another_homeserver_is_skipped() {
        let db = SqlDb::test().await;
        let dht = pkarr::mainline::Testnet::builder(1).build().unwrap();
        let pkarr_builder = test_client_builder(&dht);
        let pkarr_client = pkarr_builder.clone().build().unwrap();
        let user = Keypair::random();
        UserRepository::create(&user.public_key(), &mut db.pool().into())
            .await
            .unwrap();

        let current_homeserver = Keypair::random().public_key();
        let other_homeserver = Keypair::random().public_key();
        let packet = packet_with_https_homeserver(&user, &other_homeserver.z32());
        pkarr_client.publish(&packet).await.unwrap();

        let worker = UserKeysRepublisher {
            db,
            pkarr_builder,
            homeserver_public_key: current_homeserver,
        };
        let summary = worker.republish_impl().await.unwrap();

        assert_eq!(summary.len(), 1);
        assert_eq!(summary.skipped_count(), 1);
        assert_eq!(summary.success_count(), 0);
        assert_eq!(summary.failed_count(), 0);
    }

    #[test]
    fn https_packet_pointing_to_current_homeserver_is_accepted() {
        let user = Keypair::random();
        let homeserver = Keypair::random().public_key();
        let packet = packet_with_https_homeserver(&user, &homeserver.z32());

        assert!(packet_points_to_homeserver(&packet, &homeserver));
    }

    #[test]
    fn svcb_packet_pointing_to_current_homeserver_is_accepted() {
        let user = Keypair::random();
        let homeserver = Keypair::random().public_key();
        let packet = packet_with_svcb_homeserver(&user, &homeserver.z32());

        assert!(packet_points_to_homeserver(&packet, &homeserver));
    }

    #[test]
    fn packet_pointing_to_another_homeserver_is_rejected() {
        let user = Keypair::random();
        let current_homeserver = Keypair::random().public_key();
        let other_homeserver = Keypair::random().public_key();
        let packet = packet_with_https_homeserver(&user, &other_homeserver.z32());

        assert!(!packet_points_to_homeserver(&packet, &current_homeserver));
    }

    #[test]
    fn packet_without_a_public_key_homeserver_is_rejected() {
        let user = Keypair::random();
        let homeserver = Keypair::random().public_key();
        let domain_packet = packet_with_https_homeserver(&user, "example.com");
        let missing_packet = SignedPacket::builder().sign(&user).unwrap();

        assert!(!packet_points_to_homeserver(&domain_packet, &homeserver));
        assert!(!packet_points_to_homeserver(&missing_packet, &homeserver));
    }
}
