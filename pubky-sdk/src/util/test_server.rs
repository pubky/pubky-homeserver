//! A one-request Pubky TLS peer whose response never reaches EOF until released.

use std::{
    io::{Read, Write},
    net::TcpListener,
    num::NonZeroUsize,
    sync::{Arc, mpsc},
    time::Duration,
};

use pkarr::{Cache, InMemoryCache, SignedPacket, dns::rdata::SVCB};

use crate::{Keypair, PubkyHttpClient, PublicKey};

pub(crate) struct TestServer {
    pub client: PubkyHttpClient,
    pub user: PublicKey,
    pub homeserver: PublicKey,
    finish: mpsc::Sender<()>,
    task: tokio::task::JoinHandle<String>,
}

impl TestServer {
    pub fn start(response: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let homeserver = Keypair::random();
        let user = Keypair::random();
        let cache = Arc::new(InMemoryCache::new(NonZeroUsize::new(8).unwrap()));
        let mut endpoint = SVCB::new(1, ".".try_into().unwrap());
        endpoint.set_port(address.port());
        endpoint.set_ipv4hint(&[u32::from(std::net::Ipv4Addr::LOCALHOST)]);
        let packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), endpoint, 3600)
            .address(".".try_into().unwrap(), address.ip(), 3600)
            .sign(&homeserver)
            .unwrap();
        cache.put(&homeserver.public_key().as_inner().into(), &packet);
        let packet = SignedPacket::builder()
            .https(
                "_pubky".try_into().unwrap(),
                SVCB::new(
                    0,
                    homeserver.public_key().z32().as_str().try_into().unwrap(),
                ),
                3600,
            )
            .sign(&user)
            .unwrap();
        cache.put(&user.public_key().as_inner().into(), &packet);
        let client = PubkyHttpClient::builder()
            .isolated_pkarr_test()
            .pkarr(|builder| builder.cache(Arc::<InMemoryCache>::clone(&cache)))
            .build()
            .unwrap();
        client
            .features
            .insert(&homeserver.public_key(), &["path-addressed-storage"]);
        let config = homeserver.to_rpk_rustls_server_config();
        let (finish, finished) = mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            // A bounded nonblocking accept also lets fixture cleanup finish if
            // validation/refresh fails before opening a socket.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let socket = loop {
                if let Ok((socket, _)) = listener.accept() {
                    break socket;
                }
                if finished.try_recv().is_ok() || std::time::Instant::now() >= deadline {
                    return String::new();
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16 * 1024);
            }
            stream.write_all(&response).unwrap();
            stream.flush().unwrap();
            let _ = finished.recv_timeout(Duration::from_secs(5));
            String::from_utf8(request).unwrap()
        });
        Self {
            client,
            user: user.public_key(),
            homeserver: homeserver.public_key(),
            finish,
            task,
        }
    }

    pub async fn finish(self) -> String {
        let _ = self.finish.send(());
        self.task.await.unwrap()
    }
}
