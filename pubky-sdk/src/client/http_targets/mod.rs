use crate::{PubkyHttpClient, PublicKey, Result, errors::RequestError};
use url::Url;

mod features;
pub(crate) use features::HomeserverFeatures;
mod storage;
use storage::StorageAddressing;

#[cfg(not(target_arch = "wasm32"))]
pub mod native;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransportHost {
    PubkyQname(PublicKey),
    BarePublicKey(PublicKey),
    Other,
}

fn classify_transport_host(host: &str) -> Result<TransportHost> {
    let (host, is_pubky_qname) = host
        .strip_prefix("_pubky.")
        .map_or((host, false), |host| (host, true));

    if PublicKey::is_pubky_prefixed(host) {
        return Err(RequestError::Validation {
            message: "pubky prefix is not allowed in transport hosts; use raw z32".to_string(),
        }
        .into());
    }

    let Ok(public_key) = PublicKey::try_from_z32(host) else {
        return Ok(TransportHost::Other);
    };

    if is_pubky_qname {
        Ok(TransportHost::PubkyQname(public_key))
    } else {
        Ok(TransportHost::BarePublicKey(public_key))
    }
}

impl PubkyHttpClient {
    async fn prepare_request_parts(
        &self,
        url: &mut Url,
    ) -> Result<(StorageAddressing, Option<String>)> {
        // Storage addressing must inspect the canonical URL before WASM transport rewrites it.
        let addressing = self.prepare_storage_addressing(url).await?;
        let pubky_host = self.prepare_transport_request(url).await?;
        Ok((addressing, pubky_host))
    }

    /// Prepare a URL for transport and return its `pubky-host` value when applicable.
    ///
    /// # Errors
    /// Returns a validation or resolution error if the URL cannot be prepared.
    pub async fn prepare_request(&self, url: &mut Url) -> Result<Option<String>> {
        let (addressing, pubky_host) = self.prepare_request_parts(url).await?;

        Ok(match addressing {
            StorageAddressing::LegacyStorage { owner } => Some(owner),
            StorageAddressing::Standard | StorageAddressing::PathAddressedStorage => pubky_host,
        })
    }

    /// Prepare a URL and browser-fetch metadata for the JavaScript bindings.
    ///
    /// # Errors
    /// Returns a validation or resolution error if the URL cannot be prepared.
    #[doc(hidden)]
    pub async fn prepare_fetch(&self, url: &mut Url) -> Result<crate::client::core::PreparedFetch> {
        let (addressing, pubky_host) = self.prepare_request_parts(url).await?;
        let is_pubky_target = pubky_host.is_some();

        Ok(crate::client::core::PreparedFetch {
            pubky_host_header: addressing.into_pubky_host(pubky_host),
            is_pubky_target,
        })
    }
}

fn homeserver_url(homeserver: &PublicKey, path: &str) -> Result<Url> {
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Ok(Url::parse(&format!(
        "https://{}{}",
        homeserver.z32(),
        path
    ))?)
}

pub(crate) fn user_endpoint_url(user: &PublicKey, path: &str) -> Result<Url> {
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Ok(Url::parse(&format!(
        "https://_pubky.{}{}",
        user.z32(),
        path
    ))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_transport_hosts() {
        let public_key = crate::Keypair::random().public_key();
        let z32 = public_key.z32();

        assert_eq!(
            classify_transport_host(&format!("_pubky.{z32}")).unwrap(),
            TransportHost::PubkyQname(public_key.clone())
        );
        assert_eq!(
            classify_transport_host(&z32).unwrap(),
            TransportHost::BarePublicKey(public_key)
        );
        assert_eq!(
            classify_transport_host("example.com").unwrap(),
            TransportHost::Other
        );
        assert_eq!(
            classify_transport_host("_pubky.example.com").unwrap(),
            TransportHost::Other
        );
    }

    #[test]
    fn rejects_pubky_prefixed_transport_hosts() {
        let prefixed = crate::Keypair::random().public_key().to_string();

        for host in [prefixed.clone(), format!("_pubky.{prefixed}")] {
            let error = classify_transport_host(&host).unwrap_err();
            assert!(error.to_string().contains("use raw z32"));
        }
    }

    #[test]
    fn user_endpoints_keep_authority_addressing() {
        let user = crate::Keypair::random().public_key();
        let url = user_endpoint_url(&user, "/auth/grant/session").unwrap();
        let expected_host = format!("_pubky.{}", user.z32());

        assert_eq!(url.host_str(), Some(expected_host.as_str()));
        assert_eq!(url.path(), "/auth/grant/session");
    }

    #[tokio::test]
    async fn path_addressed_fetch_is_a_pubky_target_without_a_header() {
        let client = PubkyHttpClient::builder()
            .isolated_pkarr_test()
            .build()
            .unwrap();
        let homeserver = crate::Keypair::random().public_key();
        let owner = crate::Keypair::random().public_key();
        client.features.insert(
            &homeserver,
            &[pubky_common::constants::features::PATH_ADDRESSED_STORAGE],
        );
        let mut url = Url::parse(&format!(
            "https://{}/storage/{}/pub/file.txt",
            homeserver.z32(),
            owner.z32()
        ))
        .unwrap();

        let prepared = client.prepare_fetch(&mut url).await.unwrap();

        assert!(prepared.is_pubky_target);
        assert_eq!(prepared.pubky_host_header, None);
    }
}
