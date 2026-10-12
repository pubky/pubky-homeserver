use crate::errors::{AuthError, Result};
use crate::util::{ResponseBodyError, read_response_body};

/// Maximum wire size for a received auth relay message, including encryption.
/// Allows larger custom deployments without trusting the relay's upload limit.
pub(super) const MAX_RELAY_BODY_BYTES: usize = 1024 * 1024;

/// Apply the auth relay limit before decryption or parsing.
pub(super) async fn read_relay_body(response: reqwest::Response) -> Result<Vec<u8>> {
    read_response_body(response, MAX_RELAY_BODY_BYTES)
        .await
        .map_err(|error| match error {
            ResponseBodyError::TooLarge => AuthError::Validation(format!(
                "Auth relay response exceeds the {MAX_RELAY_BODY_BYTES}-byte limit"
            ))
            .into(),
            ResponseBodyError::Transport(error) => error.into(),
        })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    #![allow(
        deprecated,
        reason = "Both supported relay transports must enforce the limit"
    )]

    use std::time::Duration;

    use httpmock::prelude::*;
    use url::Url;

    use super::*;
    use crate::util::tests::serve_response;
    use crate::{
        Error, PubkyHttpClient,
        actors::auth::relay::{
            http_relay_inbox_channel::HttpRelayInboxChannel,
            http_relay_link_channel::HttpRelayLinkChannel,
        },
    };

    #[tokio::test]
    async fn both_transports_enforce_the_response_limit() {
        let server = MockServer::start();
        let base = Url::parse(&server.base_url()).unwrap();
        let inbox = HttpRelayInboxChannel::new(base.clone(), "test".into()).unwrap();
        let link = HttpRelayLinkChannel::new(base, "test".into()).unwrap();
        let client = PubkyHttpClient::builder()
            .isolated_pkarr_test()
            .max_error_body_bytes(16)
            .build()
            .unwrap();
        for size in [
            0,
            16,
            MAX_RELAY_BODY_BYTES - 1,
            MAX_RELAY_BODY_BYTES,
            MAX_RELAY_BODY_BYTES + 1,
        ] {
            let body = vec![b'x'; size];
            let mut response = server.mock(|when, then| {
                when.method(GET).path("/test");
                then.status(200).body(&body);
            });
            for result in [
                inbox.poll(&client, None).await,
                link.poll(&client, None).await,
            ] {
                if size <= MAX_RELAY_BODY_BYTES {
                    assert_eq!(result.unwrap().unwrap(), body);
                } else {
                    assert_too_large(result.unwrap_err());
                }
            }
            response.assert_calls(2);
            response.delete();
        }
    }

    #[tokio::test]
    async fn chunked_bodies_at_the_limit_are_accepted() {
        let body = vec![b'x'; MAX_RELAY_BODY_BYTES];
        let mut wire = format!("{:x}\r\n", body.len()).into_bytes();
        wire.extend_from_slice(&body);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        let (response, _socket) =
            serve_response(200, "Transfer-Encoding: chunked\r\n", &wire).await;
        assert_eq!(read_relay_body(response).await.unwrap(), body);
    }

    #[tokio::test]
    async fn truncated_bodies_preserve_transport_errors() {
        let (response, socket) = serve_response(200, "Content-Length: 100\r\n", b"partial").await;
        drop(socket);
        assert!(matches!(
            read_relay_body(response).await,
            Err(Error::Request(_))
        ));
    }

    fn assert_too_large(error: Error) {
        let Error::Authentication(AuthError::Validation(message)) = error else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(
            message,
            format!("Auth relay response exceeds the {MAX_RELAY_BODY_BYTES}-byte limit")
        );
    }

    #[tokio::test]
    async fn oversized_bodies_are_rejected_before_eof() {
        let size = MAX_RELAY_BODY_BYTES + 1;
        let declared = format!("Content-Length: {size}\r\n");
        let body = vec![b'x'; size];
        let mut chunked = format!("{size:x}\r\n").into_bytes();
        chunked.extend_from_slice(&body);
        // Withhold both EOF and the chunked terminator; headers alone must
        // reject the declared size, and streaming must reject the other cases.
        for (framing, wire) in [
            (declared.as_str(), b"".as_slice()),
            ("Transfer-Encoding: chunked\r\n", chunked.as_slice()),
            ("Connection: close\r\n", body.as_slice()),
        ] {
            let (response, _socket) = serve_response(200, framing, wire).await;
            let error = tokio::time::timeout(Duration::from_secs(2), read_relay_body(response))
                .await
                .expect("reader must stop before EOF")
                .unwrap_err();
            assert_too_large(error);
        }
    }
}
