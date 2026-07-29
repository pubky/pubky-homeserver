/// HTTP relay link channel implementation. Internal struct.
/// This is the old version of the channel used for auth flows.
/// By default, it is already replaced by the inbox channel.
/// Therefore, it can be removed in the future in a breaking change.
use std::{fmt::Display, str::FromStr, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::crypto::hash;
use reqwest::Method;
use url::Url;

use crate::{PubkyHttpClient, cross_log, util::check_http_status};

/// Default HTTP relay base when none is supplied.
#[deprecated(note = "Use `DEFAULT_HTTP_RELAY_INBOX` with `HttpRelayInboxChannel` instead")]
pub const DEFAULT_HTTP_RELAY: &str = "https://httprelay.pubky.app/link";

/// Internal poll error.
#[derive(Debug)]
enum PollError {
    Timeout,
    Failure(crate::errors::Error),
}

/// A HTTP relay link channel is a URL that is used to subscribe to a channel
/// or produce a message to a channel. Internal struct.
/// <https://httprelay.io/features/link>/
/// Deprecated, use `HttpRelayInboxChannel` instead.
#[deprecated(note = "Use `HttpRelayInboxChannel` instead")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRelayLinkChannel {
    /// The base URL of the relay.
    /// This variable is guaranteed to be a valid url with a base.
    base_url: Url,
    channel_id: String,
}

#[allow(deprecated, reason = "Internal use of deprecated public API")]
impl HttpRelayLinkChannel {
    /// Create a new HTTP relay link channel.
    pub fn new(base_url: Url, channel_id: String) -> crate::errors::Result<Self> {
        if base_url.cannot_be_a_base() {
            return Err(crate::errors::Error::Parse(
                url::ParseError::RelativeUrlWithCannotBeABaseBase,
            ));
        }
        if channel_id.is_empty() {
            // Note: Not the best error message, but it's a valid error.
            return Err(crate::errors::Error::Parse(
                url::ParseError::RelativeUrlWithCannotBeABaseBase,
            ));
        }
        Ok(Self {
            base_url,
            channel_id,
        })
    }

    /// The full URL of the relay channel.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error`] if the base URL is invalid.
    pub fn to_url(&self) -> Url {
        let mut url = self.base_url.clone();
        let mut segs = url
            .path_segments_mut()
            .expect("Always valid base url because it's been checked in new");
        segs.pop_if_empty(); // normalize trailing slash
        segs.push(&self.channel_id);
        drop(segs);
        url
    }

    /// Poll the channel for a message.
    /// This poll can be resumed after the timeout if the timeout is provided.
    ///
    /// # Errors
    /// - Returns [`PollError::Timeout`] if the request times out.
    /// - Returns [`PollError::Failure`] if the request fails.
    async fn poll_once(
        &self,
        client: &PubkyHttpClient,
        timeout: Option<Duration>,
    ) -> std::result::Result<reqwest::Response, PollError> {
        let request = client
            .cross_request(Method::GET, self.to_url())
            .await
            .map_err(PollError::Failure)?;
        let request = match timeout {
            Some(timeout) => request.timeout(timeout),
            None => request,
        };
        let response = match request.send().await {
            Ok(response) => response,
            Err(err) if err.is_timeout() => return Err(PollError::Timeout),
            Err(err) => return Err(PollError::Failure(err.into())),
        };

        let response = match check_http_status(response).await {
            Ok(response) => response,
            Err(e) => return Err(PollError::Failure(e)),
        };
        Ok(response)
    }

    /// This poll will retry until a message is received or the timeout is reached.
    /// If the timeout is reached, Ok(None) is returned.
    /// Any underlying network errors will be retried.
    pub async fn poll(
        &self,
        client: &PubkyHttpClient,
        timeout: Option<Duration>,
    ) -> crate::errors::Result<Option<Vec<u8>>> {
        const MAX_FAILURES: usize = 3;
        let start = web_time::Instant::now();
        let mut attempt = 0;
        let mut consecutive_failures = 0;
        loop {
            attempt += 1;
            if let Some(timeout) = timeout
                && start.elapsed() >= timeout
            {
                return Ok(None);
            }
            let poll_timeout = timeout.map(|t| t.checked_sub(start.elapsed()).unwrap_or_default());
            match self.poll_once(client, poll_timeout).await {
                Ok(response) => {
                    cross_log!(
                        debug,
                        "Received response for http relay channel polling attempt {attempt}: status {}",
                        response.status()
                    );
                    return Ok(Some(response.bytes().await?.to_vec()));
                }
                Err(e) => match e {
                    PollError::Timeout => {}
                    PollError::Failure(e) => {
                        consecutive_failures += 1;
                        cross_log!(
                            error,
                            "Http relay channel polling attempt {attempt} failed at {}: {e}",
                            self
                        );
                        if consecutive_failures >= MAX_FAILURES {
                            return Err(e);
                        }
                    }
                },
            }
        }
    }

    /// Produce a message to the channel.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error`] if the request fails.
    /// - Returns [`HttpRelayChannelError::Timeout`] if the request times out.
    /// - Returns [`HttpRelayChannelError::RequestError`] if the request fails.
    #[cfg(test)]
    pub async fn produce(
        &self,
        client: &PubkyHttpClient,
        body: &[u8],
    ) -> std::result::Result<(), crate::errors::Error> {
        let request = client.cross_request(Method::POST, self.to_url()).await?;
        let request = request.body(body.to_vec());
        let response = request.send().await?;
        response.error_for_status()?;
        Ok(())
    }
}

#[allow(deprecated, reason = "Internal use of deprecated public API")]
impl Display for HttpRelayLinkChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_url())
    }
}

#[allow(deprecated, reason = "Internal use of deprecated public API")]
impl FromStr for HttpRelayLinkChannel {
    type Err = crate::errors::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut url = Url::parse(s).map_err(crate::errors::Error::Parse)?;
        let mut segments = url.path_segments().ok_or(crate::errors::Error::Parse(
            url::ParseError::RelativeUrlWithCannotBeABaseBase,
        ))?;
        let channel_id = segments
            .next_back()
            .ok_or(crate::errors::Error::Parse(
                url::ParseError::RelativeUrlWithCannotBeABaseBase,
            ))?
            .to_string();

        if channel_id.is_empty() {
            return Err(crate::errors::Error::Parse(
                url::ParseError::RelativeUrlWithCannotBeABaseBase,
            ));
        }

        url.path_segments_mut()
            .expect("Always valid url because it's been checked in parse")
            .pop();

        Self::new(url, channel_id)
    }
}

/// A encrypted HTTP relay channel that can produce and consume an encrypted message.
/// Deprecated, use `EncryptedHttpRelayInboxChannel` instead.
#[deprecated(note = "Use `EncryptedHttpRelayInboxChannel` instead")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(deprecated, reason = "Internal use of deprecated public API")]
pub struct EncryptedHttpRelayLinkChannel {
    channel: HttpRelayLinkChannel,
    secret: [u8; 32],
}

#[allow(dead_code, deprecated, reason = "Internal use only")]
impl EncryptedHttpRelayLinkChannel {
    pub fn new(relay_base_url: Url, secret: [u8; 32]) -> crate::errors::Result<Self> {
        let channel_id = URL_SAFE_NO_PAD.encode(hash(&secret).as_bytes());
        let channel = HttpRelayLinkChannel::new(relay_base_url, channel_id)?;
        Ok(Self { channel, secret })
    }

    #[cfg(test)]
    pub fn random_secret(relay_base_url: Url) -> crate::errors::Result<Self> {
        use pubky_common::crypto::random_bytes;

        let secret = random_bytes::<32>();
        Self::new(relay_base_url, secret)
    }

    pub fn channel(&self) -> &HttpRelayLinkChannel {
        &self.channel
    }

    #[cfg(test)]
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    #[cfg(test)]
    pub async fn produce(
        &self,
        client: &PubkyHttpClient,
        body: &[u8],
    ) -> std::result::Result<(), crate::errors::Error> {
        let encrypted = pubky_common::crypto::encrypt(body, &self.secret);
        self.channel.produce(client, &encrypted).await
    }

    /// Poll the channel for a message.
    /// This poll can be resumed after the timeout if the timeout is provided.
    /// Returns Ok(None) if the request times out.
    ///
    /// # Errors
    /// - Returns [`crate::errors::Error`] if the request fails.
    pub async fn poll(
        &self,
        client: &PubkyHttpClient,
        timeout: Option<Duration>,
    ) -> std::result::Result<Option<Vec<u8>>, crate::errors::Error> {
        let Some(response) = self.channel.poll(client, timeout).await? else {
            return Ok(None);
        };
        let decrypted = pubky_common::crypto::decrypt(&response, &self.secret)?;
        Ok(Some(decrypted))
    }
}

#[allow(deprecated, reason = "Internal use of deprecated public API")]
impl Display for EncryptedHttpRelayLinkChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.channel.to_url())
    }
}

#[cfg(test)]
#[allow(deprecated, reason = "Internal use of deprecated public API")]
mod tests {
    use pubky_common::crypto::random_bytes;

    use super::*;

    #[test]
    fn test_new() {
        let base_url = Url::parse(DEFAULT_HTTP_RELAY).unwrap();
        let channel = HttpRelayLinkChannel::new(base_url, "1234567890".to_string()).unwrap();
        assert_eq!(
            channel.to_url().as_str(),
            "https://httprelay.pubky.app/link/1234567890"
        );
    }

    #[test]
    fn test_from_str() {
        let channel = "https://httprelay.pubky.app/link/1234567890"
            .parse::<HttpRelayLinkChannel>()
            .unwrap();
        assert_eq!(channel.base_url.as_str(), DEFAULT_HTTP_RELAY);
        assert_eq!(channel.channel_id, "1234567890");
    }

    #[test]
    fn test_from_str_missing_channel_id() {
        match "https://httprelay.pubky.app/".parse::<HttpRelayLinkChannel>() {
            Ok(_) => {
                panic!("Should error because missing channel id");
            }
            Err(e) => {
                assert!(
                    matches!(
                        e,
                        crate::errors::Error::Parse(
                            url::ParseError::RelativeUrlWithCannotBeABaseBase
                        )
                    ),
                    "Expected MissingChannelId error, got {e:?}"
                );
            }
        }
    }

    async fn start_relay() -> (http_relay::HttpRelay, Url) {
        let relay = http_relay::HttpRelay::builder()
            .http_port(0)
            .run()
            .await
            .unwrap();
        let link_base = relay.local_link_url();
        (relay, link_base)
    }

    fn random_channel(link_base: &Url) -> HttpRelayLinkChannel {
        let channel_bytes = random_bytes::<32>();
        let channel_id = URL_SAFE_NO_PAD.encode(channel_bytes);
        HttpRelayLinkChannel::new(link_base.clone(), channel_id).unwrap()
    }

    #[tokio::test]
    async fn test_poll() {
        let (_relay, link_base) = start_relay().await;
        let channel = random_channel(&link_base);

        let chan = channel.clone();
        let poll_handle = tokio::spawn(async move {
            let client = PubkyHttpClient::new().unwrap();
            let response = chan.poll(&client, None).await.unwrap().unwrap();
            assert_eq!(response, b"Hello, world!");
        });

        let chan = channel.clone();
        let produce_handle = tokio::spawn(async move {
            let client = PubkyHttpClient::new().unwrap();
            let body = b"Hello, world!";
            chan.produce(&client, body).await.unwrap();
        });

        let (poll_result, produce_result) = tokio::join!(poll_handle, produce_handle);
        poll_result.unwrap();
        produce_result.unwrap();
    }

    /// Test that a poll can time out and then resume successfully.
    #[tokio::test]
    async fn test_poll_timeout() {
        let (_relay, link_base) = start_relay().await;
        let channel = random_channel(&link_base);

        let chan = channel.clone();
        let poll_handle = tokio::spawn(async move {
            let client = PubkyHttpClient::new().unwrap();
            // First poll should timeout
            match chan
                .poll_once(&client, Some(Duration::from_millis(300)))
                .await
            {
                Ok(_) => panic!("Expected timeout, got response"),
                Err(e) => {
                    assert!(matches!(e, PollError::Timeout));
                }
            }

            // Try again and should succeed
            let response = chan.poll_once(&client, None).await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            let body = response.text().await.unwrap();
            assert_eq!(body, "Hello, world!");
        });

        let chan = channel.clone();
        let produce_handle = tokio::spawn(async move {
            // Wait for the first poll to timeout
            tokio::time::sleep(Duration::from_secs(1)).await;
            let client = PubkyHttpClient::new().unwrap();
            chan.produce(&client, b"Hello, world!").await.unwrap();
        });

        let (poll_result, produce_result) = tokio::join!(poll_handle, produce_handle);
        poll_result.unwrap();
        produce_result.unwrap();
    }

    #[tokio::test]
    async fn test_encrypted_poll() {
        let (_relay, link_base) = start_relay().await;
        let encrypted_channel = EncryptedHttpRelayLinkChannel::random_secret(link_base).unwrap();

        let chan = encrypted_channel.clone();
        let produce_handle = tokio::spawn(async move {
            let client = PubkyHttpClient::new().unwrap();
            let body = b"Hello, world!";
            chan.produce(&client, body).await.unwrap();
        });

        let chan = encrypted_channel.clone();
        let poll_handle = tokio::spawn(async move {
            let client = PubkyHttpClient::new().unwrap();
            let response = chan.poll(&client, None).await.unwrap().unwrap();
            assert_eq!(response, b"Hello, world!");
        });

        let (produce_result, poll_result) = tokio::join!(produce_handle, poll_handle);
        produce_result.unwrap();
        poll_result.unwrap();
    }
}
