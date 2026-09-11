use std::{fmt::Display, str::FromStr, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::crypto::hash;
use reqwest::{Method, StatusCode};
use url::Url;

use crate::{PubkyHttpClient, cross_log};

/// Default HTTP relay inbox base when none is supplied.
pub const DEFAULT_HTTP_RELAY_INBOX: &str = "https://httprelay.pubky.app/inbox";

/// Internal poll error.
#[derive(Debug)]
enum PollError {
    Timeout,
    Failure(crate::errors::Error),
}

/// An HTTP relay inbox channel for store-and-forward messaging.
///
/// Unlike `HttpRelayLinkChannel` (synchronous producer/consumer pairing), the
/// inbox channel persists messages server-side for up to 5 minutes. The consumer
/// retrieves via long-poll GET, acknowledges via DELETE, and the producer can
/// verify delivery via the `/ack` and `/await` sub-endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRelayInboxChannel {
    /// The base URL of the relay inbox endpoint.
    /// Guaranteed to be a valid URL with a base (checked in `new`).
    base_url: Url,
    channel_id: String,
}

impl HttpRelayInboxChannel {
    /// Create a new HTTP relay inbox channel.
    ///
    /// # Errors
    /// Returns an error if `base_url` cannot be a base or `channel_id` is empty.
    pub fn new(base_url: Url, channel_id: String) -> crate::errors::Result<Self> {
        if base_url.cannot_be_a_base() {
            return Err(crate::errors::Error::Parse(
                url::ParseError::RelativeUrlWithCannotBeABaseBase,
            ));
        }
        if channel_id.is_empty() {
            return Err(crate::errors::AuthError::Validation(
                "channel_id must not be empty".into(),
            )
            .into());
        }
        Ok(Self {
            base_url,
            channel_id,
        })
    }

    /// The base URL of the relay.
    #[cfg(test)]
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// The full URL of the inbox channel: `{base_url}/{channel_id}`.
    ///
    /// # Panics
    /// Panics if the base URL (validated in [`Self::new`]) is unexpectedly not a valid base.
    #[must_use]
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

    /// URL for the ACK status sub-endpoint: `{base_url}/{channel_id}/ack`.
    fn ack_url(&self) -> Url {
        let mut url = self.to_url();
        url.path_segments_mut()
            .expect("Always valid base url")
            .push("ack");
        url
    }

    /// URL for the await sub-endpoint: `{base_url}/{channel_id}/await`.
    fn await_url(&self) -> Url {
        let mut url = self.to_url();
        url.path_segments_mut()
            .expect("Always valid base url")
            .push("await");
        url
    }

    /// Single long-poll attempt to retrieve a message.
    ///
    /// The inbox server returns 408 if no message arrives within its
    /// server-side timeout (~25s). This method treats 408 as [`PollError::Timeout`]
    /// rather than a failure, allowing the retry loop in [`Self::poll`] to continue.
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

        // The inbox server returns 408 Request Timeout when no message
        // is available within its server-side long-poll window (~25s).
        // Treat this as a timeout (retry), not an error.
        if response.status() == StatusCode::REQUEST_TIMEOUT {
            return Err(PollError::Timeout);
        }

        let response = match client.check_http_status(response).await {
            Ok(response) => response,
            Err(e) => return Err(PollError::Failure(e)),
        };
        Ok(response)
    }

    /// Poll the inbox channel until a message is received or the timeout expires.
    ///
    /// Retries on both client-side timeouts and server-side 408 responses.
    /// Returns `Ok(None)` if the caller-specified timeout is reached.
    ///
    /// # Errors
    /// Returns an error after 3 consecutive non-timeout failures.
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
                        "Received response for http relay inbox channel polling attempt {attempt}: status {}",
                        response.status()
                    );
                    return Ok(Some(response.bytes().await?.to_vec()));
                }
                Err(e) => match e {
                    PollError::Timeout => {
                        consecutive_failures = 0;
                    }
                    PollError::Failure(e) => {
                        consecutive_failures += 1;
                        cross_log!(
                            error,
                            "Http relay inbox channel polling attempt {attempt} failed at {}: {e}",
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

    /// Store a message in the inbox channel.
    ///
    /// Unlike the link channel's produce (which blocks until a consumer reads),
    /// the inbox produce returns immediately. The message persists server-side
    /// for approximately 5 minutes or until acknowledged via DELETE.
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the server returns a non-success status.
    pub async fn produce(
        &self,
        client: &PubkyHttpClient,
        body: &[u8],
    ) -> crate::errors::Result<()> {
        let request = client.cross_request(Method::POST, self.to_url()).await?;
        let request = request.body(body.to_vec());
        let response = request.send().await?;
        client.check_http_status(response).await?;
        Ok(())
    }

    /// Acknowledge receipt of a message by sending DELETE to the inbox.
    ///
    /// Returns `Ok(true)` if the message was found and deleted (200),
    /// `Ok(false)` if no message existed (404).
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the server returns an unexpected status.
    pub async fn ack(&self, client: &PubkyHttpClient) -> crate::errors::Result<bool> {
        let request = client.cross_request(Method::DELETE, self.to_url()).await?;
        let response = request.send().await?;
        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            _ => {
                client.check_http_status(response).await?;
                Ok(false)
            }
        }
    }

    /// Check whether the message has been acknowledged.
    ///
    /// Returns `Ok(Some(true))` if acked, `Ok(Some(false))` if not yet acked,
    /// or `Ok(None)` if the channel does not exist (404).
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the server returns an unexpected status.
    pub async fn check_ack(&self, client: &PubkyHttpClient) -> crate::errors::Result<Option<bool>> {
        let request = client.cross_request(Method::GET, self.ack_url()).await?;
        let response = request.send().await?;
        match response.status() {
            StatusCode::OK => {
                let body = response.text().await?;
                Ok(Some(body.trim() == "true"))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => {
                client.check_http_status(response).await?;
                Ok(None)
            }
        }
    }

    /// Block until the consumer acknowledges receipt, or the server times out.
    ///
    /// Returns `Ok(Some(true))` if acknowledged (200), `Ok(Some(false))` if the
    /// server timed out (408), or `Ok(None)` if the channel does not exist (404).
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the server returns an unexpected status.
    pub async fn await_ack(
        &self,
        client: &PubkyHttpClient,
        timeout: Option<Duration>,
    ) -> crate::errors::Result<Option<bool>> {
        let request = client.cross_request(Method::GET, self.await_url()).await?;
        let request = match timeout {
            Some(timeout) => request.timeout(timeout),
            None => request,
        };
        let response = match request.send().await {
            Ok(response) => response,
            Err(err) if err.is_timeout() => return Ok(Some(false)),
            Err(err) => return Err(err.into()),
        };
        match response.status() {
            StatusCode::OK => Ok(Some(true)),
            StatusCode::REQUEST_TIMEOUT => Ok(Some(false)),
            StatusCode::NOT_FOUND => Ok(None),
            _ => {
                client.check_http_status(response).await?;
                Ok(None)
            }
        }
    }
}

impl Display for HttpRelayInboxChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_url())
    }
}

impl FromStr for HttpRelayInboxChannel {
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
            return Err(crate::errors::AuthError::Validation(
                "channel_id must not be empty".into(),
            )
            .into());
        }

        url.path_segments_mut()
            .expect("Always valid url because it's been checked in parse")
            .pop();

        Self::new(url, channel_id)
    }
}

/// An encrypted HTTP relay inbox channel that encrypts/decrypts messages
/// using a shared secret, with store-and-forward semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedHttpRelayInboxChannel {
    channel: HttpRelayInboxChannel,
    secret: [u8; 32],
}

impl EncryptedHttpRelayInboxChannel {
    /// Create a new encrypted inbox channel.
    ///
    /// The `channel_id` is derived as `base64url(hash(secret))`.
    ///
    /// # Errors
    /// Returns an error if `relay_base_url` cannot be a base.
    pub fn new(relay_base_url: Url, secret: [u8; 32]) -> crate::errors::Result<Self> {
        let channel_id = URL_SAFE_NO_PAD.encode(hash(&secret).as_bytes());
        let channel = HttpRelayInboxChannel::new(relay_base_url, channel_id)?;
        Ok(Self { channel, secret })
    }

    /// Create an encrypted inbox channel with a random secret (for testing).
    ///
    /// # Errors
    /// Propagates any error from [`Self::new`] if the base URL is not a valid base.
    #[cfg(test)]
    pub fn random_secret(relay_base_url: Url) -> crate::errors::Result<Self> {
        use pubky_common::crypto::random_bytes;

        let secret = random_bytes::<32>();
        Self::new(relay_base_url, secret)
    }

    /// Returns the shared secret.
    #[cfg(test)]
    #[must_use]
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Store an encrypted message in the inbox.
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the server returns a non-success status.
    pub async fn produce(
        &self,
        client: &PubkyHttpClient,
        body: &[u8],
    ) -> crate::errors::Result<()> {
        let encrypted = pubky_common::crypto::encrypt(body, &self.secret);
        self.channel.produce(client, &encrypted).await
    }

    /// Poll the inbox and decrypt the message.
    /// Returns `Ok(None)` if the timeout is reached.
    ///
    /// # Errors
    /// Returns an error on repeated poll failures or decryption failure.
    pub async fn poll(
        &self,
        client: &PubkyHttpClient,
        timeout: Option<Duration>,
    ) -> crate::errors::Result<Option<Vec<u8>>> {
        let Some(response) = self.channel.poll(client, timeout).await? else {
            return Ok(None);
        };
        let decrypted = pubky_common::crypto::decrypt(&response, &self.secret)?;
        Ok(Some(decrypted))
    }

    /// Acknowledge receipt of the current message.
    /// Returns `Ok(true)` if deleted, `Ok(false)` if no message existed.
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the server returns an unexpected status.
    pub async fn ack(&self, client: &PubkyHttpClient) -> crate::errors::Result<bool> {
        self.channel.ack(client).await
    }

    /// Check whether the message has been acknowledged.
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the server returns an unexpected status.
    pub async fn check_ack(&self, client: &PubkyHttpClient) -> crate::errors::Result<Option<bool>> {
        self.channel.check_ack(client).await
    }

    /// Block until the consumer acknowledges or the server times out.
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the server returns an unexpected status.
    pub async fn await_ack(
        &self,
        client: &PubkyHttpClient,
        timeout: Option<Duration>,
    ) -> crate::errors::Result<Option<bool>> {
        self.channel.await_ack(client, timeout).await
    }
}

impl Display for EncryptedHttpRelayInboxChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.channel.to_url())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Error, errors::RequestError};
    use httpmock::MockServer;
    use pubky_common::crypto::random_bytes;

    use super::*;

    #[test]
    fn test_new() {
        let base_url = Url::parse(DEFAULT_HTTP_RELAY_INBOX).unwrap();
        let channel = HttpRelayInboxChannel::new(base_url, "1234567890".to_string()).unwrap();
        assert_eq!(
            channel.to_url().as_str(),
            "https://httprelay.pubky.app/inbox/1234567890"
        );
    }

    #[test]
    fn test_from_str() {
        let channel = "https://httprelay.pubky.app/inbox/1234567890"
            .parse::<HttpRelayInboxChannel>()
            .unwrap();
        assert_eq!(channel.base_url.as_str(), DEFAULT_HTTP_RELAY_INBOX);
        assert_eq!(channel.channel_id, "1234567890");
    }

    #[test]
    fn test_from_str_missing_channel_id() {
        match "https://httprelay.pubky.app/".parse::<HttpRelayInboxChannel>() {
            Ok(_) => {
                panic!("Should error because missing channel id");
            }
            Err(e) => {
                assert!(
                    matches!(
                        e,
                        crate::errors::Error::Authentication(crate::errors::AuthError::Validation(
                            _
                        ))
                    ),
                    "Expected validation error, got {e:?}"
                );
            }
        }
    }

    #[test]
    fn test_sub_urls() {
        let base_url = Url::parse(DEFAULT_HTTP_RELAY_INBOX).unwrap();
        let channel = HttpRelayInboxChannel::new(base_url, "test123".to_string()).unwrap();
        assert_eq!(
            channel.ack_url().as_str(),
            "https://httprelay.pubky.app/inbox/test123/ack"
        );
        assert_eq!(
            channel.await_url().as_str(),
            "https://httprelay.pubky.app/inbox/test123/await"
        );
    }

    async fn start_relay() -> (http_relay::HttpRelay, Url) {
        let relay = http_relay::HttpRelay::builder()
            .http_port(0)
            .run()
            .await
            .unwrap();
        let inbox_base = relay.local_url().join("inbox").unwrap();
        (relay, inbox_base)
    }

    fn random_channel(inbox_base: &Url) -> HttpRelayInboxChannel {
        let channel_bytes = random_bytes::<32>();
        let channel_id = URL_SAFE_NO_PAD.encode(channel_bytes);
        HttpRelayInboxChannel::new(inbox_base.clone(), channel_id).unwrap()
    }

    #[tokio::test]
    async fn test_produce_and_poll() {
        let (_relay, inbox_base) = start_relay().await;
        let client = PubkyHttpClient::new().unwrap();
        let channel = random_channel(&inbox_base);

        // Produce first (inbox stores the message)
        channel.produce(&client, b"Hello, inbox!").await.unwrap();

        // Poll should return the message immediately
        let response = channel
            .poll(&client, Some(Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"Hello, inbox!");
    }

    #[tokio::test]
    async fn test_idempotent_get_until_ack() {
        let (_relay, inbox_base) = start_relay().await;
        let client = PubkyHttpClient::new().unwrap();
        let channel = random_channel(&inbox_base);

        channel.produce(&client, b"persistent msg").await.unwrap();

        // First poll
        let resp1 = channel
            .poll(&client, Some(Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap();
        // Second poll (same message, not yet acked)
        let resp2 = channel
            .poll(&client, Some(Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp1, resp2);

        // ACK
        let acked = channel.ack(&client).await.unwrap();
        assert!(acked);

        // After ACK, poll should timeout (no more messages)
        let resp3 = channel
            .poll(&client, Some(Duration::from_millis(500)))
            .await
            .unwrap();
        assert!(resp3.is_none());
    }

    #[tokio::test]
    async fn test_ack_nonexistent() {
        let (_relay, inbox_base) = start_relay().await;
        let client = PubkyHttpClient::new().unwrap();
        let channel = random_channel(&inbox_base);

        let acked = channel.ack(&client).await.unwrap();
        assert!(!acked);
    }

    #[tokio::test]
    async fn test_check_ack() {
        let (_relay, inbox_base) = start_relay().await;
        let client = PubkyHttpClient::new().unwrap();
        let channel = random_channel(&inbox_base);

        channel.produce(&client, b"check me").await.unwrap();

        // Before ACK
        let status = channel.check_ack(&client).await.unwrap();
        assert_eq!(status, Some(false));

        // ACK
        channel.ack(&client).await.unwrap();

        // After ACK
        let status = channel.check_ack(&client).await.unwrap();
        assert_eq!(status, Some(true));
    }

    #[tokio::test]
    async fn test_await_ack() {
        let (_relay, inbox_base) = start_relay().await;
        let client = PubkyHttpClient::new().unwrap();
        let channel = random_channel(&inbox_base);

        channel.produce(&client, b"await me").await.unwrap();

        let channel_clone = channel.clone();
        let ack_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let client = PubkyHttpClient::new().unwrap();
            channel_clone.ack(&client).await.unwrap();
        });

        let result = channel
            .await_ack(&client, Some(Duration::from_secs(10)))
            .await
            .unwrap();
        assert_eq!(result, Some(true));

        ack_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_poll_timeout_no_message() {
        let (_relay, inbox_base) = start_relay().await;
        let client = PubkyHttpClient::new().unwrap();
        let channel = random_channel(&inbox_base);

        let result = channel
            .poll(&client, Some(Duration::from_millis(500)))
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_encrypted_produce_poll_ack() {
        let (_relay, inbox_base) = start_relay().await;
        let encrypted_channel = EncryptedHttpRelayInboxChannel::random_secret(inbox_base).unwrap();
        let client = PubkyHttpClient::new().unwrap();

        encrypted_channel
            .produce(&client, b"encrypted inbox msg")
            .await
            .unwrap();

        let response = encrypted_channel
            .poll(&client, Some(Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"encrypted inbox msg");

        let acked = encrypted_channel.ack(&client).await.unwrap();
        assert!(acked);
    }

    #[tokio::test]
    async fn test_check_ack_nonexistent_channel() {
        let (_relay, inbox_base) = start_relay().await;
        let client = PubkyHttpClient::new().unwrap();
        let channel = random_channel(&inbox_base);

        // No message was ever produced, so the channel doesn't exist.
        let status = channel.check_ack(&client).await.unwrap();
        assert_eq!(status, None);
    }

    #[tokio::test]
    async fn test_await_ack_nonexistent_channel() {
        let (_relay, inbox_base) = start_relay().await;
        let client = PubkyHttpClient::new().unwrap();
        let channel = random_channel(&inbox_base);

        // No message produced → channel doesn't exist → Ok(None)
        let result = channel
            .await_ack(&client, Some(Duration::from_secs(2)))
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_await_ack_server_timeout() {
        let (_relay, inbox_base) = start_relay().await;
        let client = PubkyHttpClient::new().unwrap();
        let channel = random_channel(&inbox_base);

        // Produce a message but never ACK it.
        channel.produce(&client, b"no ack coming").await.unwrap();

        // await_ack with a short client timeout should return Some(false)
        // (either client timeout or server 408).
        let result = channel
            .await_ack(&client, Some(Duration::from_millis(500)))
            .await
            .unwrap();
        assert_eq!(result, Some(false));
    }

    #[tokio::test]
    async fn test_poll_returns_none_on_zero_timeout() {
        let (_relay, inbox_base) = start_relay().await;
        let client = PubkyHttpClient::new().unwrap();
        let channel = random_channel(&inbox_base);

        // Zero-duration timeout should return None immediately
        let result = channel.poll(&client, Some(Duration::ZERO)).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_poll_succeeds_after_delayed_produce() {
        let (_relay, inbox_base) = start_relay().await;
        let client = PubkyHttpClient::new().unwrap();
        let channel = random_channel(&inbox_base);

        // Produce after a delay — poll should retry on timeout and succeed.
        let chan = channel.clone();
        let produce_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let client = PubkyHttpClient::new().unwrap();
            chan.produce(&client, b"delayed msg").await.unwrap();
        });

        let result = channel
            .poll(&client, Some(Duration::from_secs(10)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, b"delayed msg");

        produce_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_encrypted_concurrent() {
        let (_relay, inbox_base) = start_relay().await;
        let encrypted_channel = EncryptedHttpRelayInboxChannel::random_secret(inbox_base).unwrap();

        let chan = encrypted_channel.clone();
        let produce_handle = tokio::spawn(async move {
            let client = PubkyHttpClient::new().unwrap();
            chan.produce(&client, b"Hello, world!").await.unwrap();
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

    #[tokio::test]
    async fn test_poll_errors_after_max_failures() {
        use httpmock::prelude::*;

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path_contains("/inbox/");
            then.status(500).body("Internal Server Error");
        });

        let base_url = Url::parse(&format!("{}/inbox", server.base_url())).unwrap();
        let channel = random_channel(&base_url);
        let client = PubkyHttpClient::new().unwrap();

        // poll should fail after MAX_FAILURES (3) consecutive 500 errors
        let result = channel.poll(&client, Some(Duration::from_secs(30))).await;
        assert!(
            result.is_err(),
            "Expected error after MAX_FAILURES, got {result:?}"
        );
    }
    #[tokio::test]
    async fn relay_errors_use_the_client_limit() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method("DELETE");
            then.status(500).body("diagnostic");
        });
        let channel = random_channel(&Url::parse(&server.base_url()).unwrap());
        for (limit, expected) in [
            (0, "Internal Server Error"),
            (4, "diag\n[response body truncated at 4 bytes]"),
        ] {
            let client = PubkyHttpClient::builder()
                .isolated_pkarr_test()
                .max_error_body_bytes(limit)
                .build()
                .unwrap();
            let error = channel.ack(&client).await.unwrap_err();
            let Error::Request(RequestError::Server { status, message }) = error else {
                panic!("unexpected error: {error:?}");
            };
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(message, expected);
        }
    }
}
