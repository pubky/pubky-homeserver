use url::Url;

use super::RequestAddressing;
use crate::{PubkyHttpClient, PublicKey, Result, errors::RequestError};
use pubky_common::constants::features::PATH_ADDRESSED_STORAGE;

impl PubkyHttpClient {
    pub(super) async fn prepare_request_addressing(
        &self,
        url: &mut Url,
    ) -> Result<RequestAddressing> {
        let Some(path) = url.path().strip_prefix("/storage/") else {
            return Ok(RequestAddressing::Standard);
        };
        let Some(host) = url.host_str() else {
            return Ok(RequestAddressing::Standard);
        };
        let transport_host = host.strip_prefix("_pubky.").unwrap_or(host);
        if PublicKey::try_from_z32(transport_host).is_err() {
            return Ok(RequestAddressing::Standard);
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
        let homeserver = url
            .host_str()
            .filter(|host| !host.starts_with("_pubky."))
            .and_then(|host| PublicKey::try_from_z32(host).ok());

        if self
            .features
            .supports(self, &owner, homeserver.as_ref(), PATH_ADDRESSED_STORAGE)
            .await
        {
            return Ok(RequestAddressing::PathAddressedStorage);
        }

        // Choose compatibility before sending storage; response errors never trigger a retry.
        url.set_path(&legacy_path);
        Ok(RequestAddressing::LegacyStorage { owner: owner.z32() })
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

        let addressing = client.prepare_request_addressing(&mut url).await.unwrap();

        assert_eq!(addressing, RequestAddressing::PathAddressedStorage);
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

        let addressing = client.prepare_request_addressing(&mut url).await.unwrap();

        assert_eq!(
            addressing,
            RequestAddressing::LegacyStorage { owner: owner.z32() }
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

            let addressing = client.prepare_request_addressing(&mut url).await.unwrap();

            assert_eq!(addressing, RequestAddressing::Standard);
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
                .prepare_request_addressing(&mut Url::parse(&url).unwrap())
                .await
                .unwrap_err();
        }
    }
}
