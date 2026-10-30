use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use pkarr::{Cache, InMemoryCache, SignedPacket, dns::rdata::SVCB};
use pubky_common::auth::{
    grant::GrantClaims,
    grant_revocation::GrantRevocationDisposition,
    grant_session_responses::{GrantSessionInfo, GrantSessionResponse},
    jws::{ClientId, GRANT_JWS_TYP, GrantId},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, oneshot},
};
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::{Capability, Keypair, actors::auth::grant::pop_signer::GrantPopSigner};

fn credential(homeserver: PublicKey) -> GrantCredential {
    let user = Keypair::random();
    let client = Keypair::random();
    let now = now_unix();
    let claims = GrantClaims {
        iss: user.public_key(),
        client_id: ClientId::new("captured.test").unwrap(),
        caps: vec![Capability::root()],
        cnf: client.public_key(),
        jti: GrantId::generate(),
        iat: now,
        exp: now + 3600,
    };
    GrantCredential::from_response(
        GrantSessionResponse {
            token: "original-test-bearer".into(),
            session: GrantSessionInfo {
                homeserver: homeserver.clone(),
                pubky: claims.iss.clone(),
                client_id: claims.client_id.clone(),
                capabilities: claims.caps.clone(),
                grant_id: claims.jti.clone(),
                token_expires_at: now + 300,
                grant_expires_at: claims.exp,
                created_at: now,
            },
        },
        claims.sign(&user, GRANT_JWS_TYP),
        claims,
        GrantPopSigner::local(client),
        homeserver,
    )
}

fn client() -> PubkyHttpClient {
    PubkyHttpClient::builder()
        .isolated_pkarr_test()
        .build()
        .unwrap()
}

fn receipt(operation: &GrantRevocation) -> GrantRevocationReceipt {
    GrantRevocationReceipt {
        disposition: GrantRevocationDisposition::OriginalBearerRevoked,
        operation_id: operation.binding.operation_id.clone(),
        homeserver: operation.homeserver.clone(),
        grant_id: operation.binding.grant_id.clone(),
        pubky: operation.binding.pubky.clone(),
        client_id: operation.binding.client_id.clone(),
    }
}

#[tokio::test]
async fn captured_revocation_is_an_independent_snapshot_and_redacts_secrets() {
    let credential = credential(Keypair::random().public_key());
    let operation = GrantRevocation::capture(&credential, client(), RandomId::generate())
        .await
        .unwrap();
    let original = operation.binding.clone();
    let homeserver = operation.homeserver.clone();
    let mut state = credential.state.lock().await;
    state.bearer = "replacement-test-bearer".into();
    state.session.pubky = Keypair::random().public_key();
    state.homeserver_pk = Keypair::random().public_key();
    let secret = state.grant_jws.clone();
    drop(state);
    assert_eq!(operation.bearer.as_str(), "original-test-bearer");
    assert_eq!(operation.binding, original);
    assert_eq!(operation.homeserver, homeserver);
    let debug = format!("{operation:?}");
    assert!(!debug.contains("test-bearer"));
    assert!(!debug.contains(&secret));
    assert_eq!(
        Arc::strong_count(&credential.state),
        1,
        "handle retains no mutable credential"
    );
}

#[tokio::test]
async fn captured_revocation_invalid_or_expired_state_fails_before_transport() {
    for field in [
        "bearer",
        "token_expiry",
        "grant_expiry",
        "grant",
        "owner",
        "client",
        "homeserver",
    ] {
        let credential = credential(Keypair::random().public_key());
        let mut state = credential.state.lock().await;
        match field {
            "bearer" => state.bearer.clear(),
            "token_expiry" => state.session.token_expires_at = now_unix(),
            "grant_expiry" => state.grant_claims.exp = now_unix(),
            "grant" => state.session.grant_id = GrantId::generate(),
            "owner" => state.session.pubky = Keypair::random().public_key(),
            "client" => state.session.client_id = ClientId::new("other.test").unwrap(),
            _ => state.session.homeserver = Keypair::random().public_key(),
        }
        drop(state);
        let error = GrantRevocation::capture(&credential, client(), RandomId::generate())
            .await
            .unwrap_err();
        assert_eq!(error, GrantRevocationError::InvalidSnapshot, "{field}");
    }
}

#[tokio::test]
async fn captured_revocation_receipt_requires_every_original_binding_and_version() {
    let credential = credential(Keypair::random().public_key());
    let operation = GrantRevocation::capture(&credential, client(), RandomId::generate())
        .await
        .unwrap();
    let good = receipt(&operation);
    let value = serde_json::to_value(&good).unwrap();
    assert_eq!(
        operation
            .validate_receipt(&serde_json::to_vec(&value).unwrap())
            .unwrap(),
        good
    );
    for field in [
        "operation_id",
        "homeserver",
        "grant_id",
        "pubky",
        "client_id",
        "disposition",
    ] {
        let mut wrong = value.clone();
        wrong[field] = match field {
            "operation_id" => serde_json::json!(RandomId::generate()),
            "homeserver" | "pubky" => serde_json::json!(Keypair::random().public_key()),
            "grant_id" => serde_json::json!(GrantId::generate()),
            "client_id" => serde_json::json!("other.test"),
            _ => serde_json::json!("revoked_v2"),
        };
        assert_eq!(
            operation
                .validate_receipt(&serde_json::to_vec(&wrong).unwrap())
                .unwrap_err(),
            GrantRevocationError::Unacknowledged { status: Some(200) },
            "{field}"
        );
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            operation
                .validate_receipt(&serde_json::to_vec(&missing).unwrap())
                .is_err(),
            "{field}"
        );
    }
    let mut extra = value;
    extra["success"] = serde_json::json!(true);
    assert_eq!(
        operation
            .validate_receipt(&serde_json::to_vec(&extra).unwrap())
            .unwrap_err(),
        GrantRevocationError::Unacknowledged { status: Some(200) }
    );
    for bytes in [
        vec![],
        b"{}".to_vec(),
        b"{\"ok\":true}".to_vec(),
        vec![b' '; MAX_RECEIPT_BYTES + 1],
    ] {
        assert_eq!(
            operation.validate_receipt(&bytes).unwrap_err(),
            GrantRevocationError::Unacknowledged { status: Some(200) }
        );
    }
}

struct TransportFixture {
    client: PubkyHttpClient,
    credential: GrantCredential,
    requests: mpsc::UnboundedReceiver<String>,
    reply: oneshot::Sender<Vec<u8>>,
    task: tokio::task::JoinHandle<()>,
    port: u16,
}

impl Drop for TransportFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TransportFixture {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cert = CertificateDer::from_pem_slice(include_bytes!(
            "../../../../client/test_certs/server.pem"
        ))
        .unwrap();
        let key = PrivateKeyDer::from_pem_slice(include_bytes!(
            "../../../../client/test_certs/server.key"
        ))
        .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let (requests_tx, requests) = mpsc::unbounded_channel();
        let (reply, response) = oneshot::channel::<Vec<u8>>();
        let task = tokio::spawn(async move {
            let mut response = Some(response);
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(socket).await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 1024];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                        let length: usize = headers
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .unwrap_or("0")
                            .parse()
                            .unwrap();
                        if bytes.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                requests_tx.send(String::from_utf8(bytes).unwrap()).unwrap();
                if let Some(response) = response.take() {
                    if let Ok(bytes) = response.await {
                        let _ = stream.write_all(&bytes).await;
                    }
                } else {
                    let _ = stream.write_all(b"HTTP/1.1 500 Unexpected retry\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                }
            }
        });
        let homeserver = pkarr::Keypair::random();
        let cache: Arc<dyn Cache> = Arc::new(InMemoryCache::new(NonZeroUsize::new(1).unwrap()));
        let mut endpoint = SVCB::new(10, "localhost".try_into().unwrap());
        endpoint.set_port(port);
        let packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), endpoint, 3600)
            .sign(&homeserver)
            .unwrap();
        cache.put(&homeserver.public_key().into(), &packet);
        let client = PubkyHttpClient::builder()
            .isolated_pkarr_test()
            .pkarr(|b| b.cache(cache))
            .request_timeout(Duration::from_secs(2))
            .read_timeout(Duration::from_millis(250))
            .add_root_certificates_pem(include_bytes!("../../../../client/test_certs/ca.pem"))
            .unwrap()
            .build()
            .unwrap();
        let credential =
            credential(PublicKey::try_from_z32(&homeserver.public_key().to_string()).unwrap());
        Self {
            client,
            credential,
            requests,
            reply,
            task,
            port,
        }
    }

    async fn capture(&self) -> GrantRevocation {
        GrantRevocation::capture(&self.credential, self.client.clone(), RandomId::generate())
            .await
            .unwrap()
    }

    async fn assert_no_more_requests(&mut self) {
        tokio::time::timeout(Duration::from_millis(75), self.requests.recv())
            .await
            .expect_err("unexpected second request");
    }

    fn respond(&mut self, response: Vec<u8>) {
        let (replacement, _) = oneshot::channel();
        std::mem::replace(&mut self.reply, replacement)
            .send(response)
            .unwrap();
    }
}

fn http_response(status: u16, body: &[u8], extra: &str) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

#[tokio::test]
async fn captured_revocation_transport_keeps_original_request_and_custom_trust() {
    let mut fixture = TransportFixture::new().await;
    let operation = fixture.capture().await;
    let expected = receipt(&operation);
    fixture.credential.state.lock().await.bearer = "replacement-test-bearer".into();
    fixture.respond(http_response(
        200,
        &serde_json::to_vec(&expected).unwrap(),
        "",
    ));
    assert_eq!(operation.execute().await.unwrap(), expected);
    let request = fixture.requests.recv().await.unwrap();
    assert!(request.starts_with("POST /auth/grant/session-revocation HTTP/1.1\r\n"));
    assert!(request.contains("authorization: Bearer original-test-bearer\r\n"));
    assert!(request.contains(&format!("pubky-host: {}\r\n", expected.pubky.z32())));
    assert!(!request.to_ascii_lowercase().contains("cookie:"));
    let body = request.split_once("\r\n\r\n").unwrap().1;
    let sent: ConditionalGrantRevocation = serde_json::from_str(body).unwrap();
    assert_eq!(sent.operation_id, expected.operation_id);
    assert_eq!(
        fixture.credential.state.lock().await.bearer,
        "replacement-test-bearer"
    );
    fixture.assert_no_more_requests().await;
}

#[tokio::test]
async fn captured_revocation_transport_never_follows_redirects_or_retries_failures() {
    for status in [307, 401, 412, 404, 503] {
        let mut fixture = TransportFixture::new().await;
        let operation = fixture.capture().await;
        fixture.respond(http_response(
            status,
            b"",
            &format!("Location: https://localhost:{}/forbidden\r\n", fixture.port),
        ));
        assert_eq!(
            operation.execute().await.unwrap_err(),
            GrantRevocationError::Unacknowledged {
                status: Some(status)
            }
        );
        assert!(
            fixture
                .requests
                .recv()
                .await
                .unwrap()
                .starts_with("POST /auth/grant/session-revocation ")
        );
        fixture.assert_no_more_requests().await;
    }
}

#[tokio::test]
async fn captured_revocation_transport_rejects_lost_malformed_and_oversized_receipts() {
    for body in [
        vec![],
        b"{\"ok\":true}".to_vec(),
        vec![b' '; MAX_RECEIPT_BYTES + 1],
    ] {
        let mut fixture = TransportFixture::new().await;
        let operation = fixture.capture().await;
        fixture.respond(http_response(200, &body, ""));
        assert_eq!(
            operation.execute().await.unwrap_err(),
            GrantRevocationError::Unacknowledged { status: Some(200) }
        );
        fixture.requests.recv().await.unwrap();
        fixture.assert_no_more_requests().await;
    }
    let mut fixture = TransportFixture::new().await;
    let operation = fixture.capture().await;
    fixture.respond(
        b"HTTP/1.1 200 OK\r\nContent-Length: 400\r\nConnection: close\r\n\r\n{\"disposition\":"
            .to_vec(),
    );
    assert_eq!(
        operation.execute().await.unwrap_err(),
        GrantRevocationError::Unacknowledged { status: Some(200) }
    );
    fixture.requests.recv().await.unwrap();
    fixture.assert_no_more_requests().await;
}

#[tokio::test]
async fn captured_revocation_cancellation_before_poll_sends_nothing_after_send_is_unknown() {
    let mut fixture = TransportFixture::new().await;
    let unpolled = fixture.capture().await.execute();
    drop(unpolled);
    fixture.assert_no_more_requests().await;
    let operation = fixture.capture().await;
    let task = tokio::spawn(operation.execute());
    fixture.requests.recv().await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    fixture.respond(http_response(200, b"{}", ""));
    fixture.assert_no_more_requests().await;
    assert_eq!(
        fixture.credential.state.lock().await.bearer,
        "original-test-bearer"
    );
}
