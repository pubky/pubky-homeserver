use url::Url;

use super::{TransportHost, classify_transport_host};
use crate::{Pkdns, PubkyHttpClient, PublicKey, Result, errors::RequestError};
use pubky_common::constants::features::PATH_ADDRESSED_STORAGE;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum StorageAddressing {
    Standard,
    PathAddressedStorage,
    LegacyStorage { owner: String },
}

impl StorageAddressing {
    pub(super) fn into_pubky_host(self, standard: Option<String>) -> Option<String> {
        match self {
            Self::Standard => standard,
            Self::PathAddressedStorage => None,
            Self::LegacyStorage { owner } => Some(owner),
        }
    }
}

impl PubkyHttpClient {
    pub(super) async fn prepare_storage_addressing(
        &self,
        url: &mut Url,
    ) -> Result<StorageAddressing> {
        let Some(path) = url.path().strip_prefix("/storage/") else {
            return Ok(StorageAddressing::Standard);
        };
        let transport_host = classify_transport_host(url.host_str().unwrap_or_default())?;
        if transport_host == TransportHost::Other {
            return Ok(StorageAddressing::Standard);
        }
        let (owner, path) = path
            .split_once('/')
            .ok_or_else(|| RequestError::Validation {
                message: "path-addressed storage URL is missing a resource path".to_string(),
            })?;
        let owner = PublicKey::try_from_z32(owner).map_err(|_error| RequestError::Validation {
            message: "path-addressed storage URL contains an invalid owner".to_string(),
        })?;
        let legacy_path = format!("/{path}");
        let homeserver = match transport_host {
            TransportHost::BarePublicKey(homeserver) => Some(homeserver),
            TransportHost::PubkyQname(_) => Pkdns::with_client(self.clone())
                .get_homeserver_of(&owner)
                .await
                .ok()
                .flatten(),
            TransportHost::Other => None,
        };

        if let Some(homeserver) = homeserver
            && self
                .features
                .supports(self, &homeserver, PATH_ADDRESSED_STORAGE)
                .await
        {
            return Ok(StorageAddressing::PathAddressedStorage);
        }

        // Choose compatibility before sending storage; response errors never trigger a retry.
        url.set_path(&legacy_path);
        Ok(StorageAddressing::LegacyStorage { owner: owner.z32() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keypair;

    #[tokio::test]
    async fn advertised_feature_keeps_the_storage_path() {
        let client = PubkyHttpClient::builder()
            .isolated_pkarr_test()
            .build()
            .unwrap();
        let homeserver = Keypair::random().public_key();
        let owner = Keypair::random().public_key();
        client
            .features
            .insert(&homeserver, &[PATH_ADDRESSED_STORAGE]);
        let mut url = Url::parse(&format!(
            "https://{}/storage/{}/pub/file.txt",
            homeserver.z32(),
            owner.z32()
        ))
        .unwrap();

        let addressing = client.prepare_storage_addressing(&mut url).await.unwrap();

        assert_eq!(addressing, StorageAddressing::PathAddressedStorage);
        assert_eq!(url.path(), format!("/storage/{}/pub/file.txt", owner.z32()));
    }

    #[tokio::test]
    async fn missing_feature_uses_legacy_path_and_preserves_the_url() {
        let client = PubkyHttpClient::builder()
            .isolated_pkarr_test()
            .build()
            .unwrap();
        let homeserver = Keypair::random().public_key();
        let owner = Keypair::random().public_key();
        client.features.insert(&homeserver, &[]);
        let mut url = Url::parse(&format!(
            "https://{}/storage/{}/pub/My%20File%252FName/?cursor=hello%20world",
            homeserver.z32(),
            owner.z32()
        ))
        .unwrap();

        let addressing = client.prepare_storage_addressing(&mut url).await.unwrap();

        assert_eq!(
            addressing,
            StorageAddressing::LegacyStorage { owner: owner.z32() }
        );
        assert_eq!(url.path(), "/pub/My%20File%252FName/");
        assert_eq!(url.query(), Some("cursor=hello%20world"));
    }

    #[tokio::test]
    async fn ignores_storage_paths_on_regular_hosts() {
        let client = PubkyHttpClient::builder()
            .isolated_pkarr_test()
            .build()
            .unwrap();
        let owner = Keypair::random().public_key();

        for url in [
            "https://example.com/storage/not-a-key/pub/file.txt",
            &format!("https://example.com/storage/{}/pub/file.txt", owner.z32()),
        ] {
            let mut url = Url::parse(url).unwrap();
            let original = url.clone();

            let addressing = client.prepare_storage_addressing(&mut url).await.unwrap();

            assert_eq!(addressing, StorageAddressing::Standard);
            assert_eq!(url, original);
        }
    }

    #[tokio::test]
    async fn validates_storage_owner_and_resource_path_on_pubky_hosts() {
        let client = PubkyHttpClient::builder()
            .isolated_pkarr_test()
            .build()
            .unwrap();
        let homeserver = Keypair::random().public_key();

        for url in [
            format!(
                "https://{}/storage/not-a-key/pub/file.txt",
                homeserver.z32()
            ),
            format!("https://{}/storage/missing-path", homeserver.z32()),
        ] {
            client
                .prepare_storage_addressing(&mut Url::parse(&url).unwrap())
                .await
                .unwrap_err();
        }
    }

    #[tokio::test]
    async fn unresolved_owner_uses_legacy_storage() {
        let client = PubkyHttpClient::builder()
            .isolated_pkarr_test()
            .build()
            .unwrap();
        let owner = Keypair::random().public_key();
        let mut url = Url::parse(&format!(
            "https://_pubky.{}/storage/{}/pub/file.txt",
            owner.z32(),
            owner.z32()
        ))
        .unwrap();

        let addressing = client.prepare_storage_addressing(&mut url).await.unwrap();

        assert_eq!(
            addressing,
            StorageAddressing::LegacyStorage { owner: owner.z32() }
        );
        assert_eq!(url.path(), "/pub/file.txt");
    }

    #[test]
    fn addressing_selects_the_pubky_host_header() {
        let fallback = || Some("transport".to_string());

        assert_eq!(
            StorageAddressing::Standard.into_pubky_host(fallback()),
            fallback()
        );
        assert_eq!(StorageAddressing::Standard.into_pubky_host(None), None);
        assert_eq!(
            StorageAddressing::PathAddressedStorage.into_pubky_host(fallback()),
            None
        );
        assert_eq!(
            StorageAddressing::PathAddressedStorage.into_pubky_host(None),
            None
        );
        assert_eq!(
            StorageAddressing::LegacyStorage {
                owner: "owner".to_string()
            }
            .into_pubky_host(fallback()),
            Some("owner".to_string())
        );
        assert_eq!(
            StorageAddressing::LegacyStorage {
                owner: "owner".to_string()
            }
            .into_pubky_host(None),
            Some("owner".to_string())
        );
    }
}
