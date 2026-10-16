//! Attach an identified client address to each accepted TCP connection.

use std::io;

use axum::{middleware::AddExtension, Extension};
use axum_server::accept::Accept;
use futures_util::future::BoxFuture;
use tcp_client_addr::{ClientAddr, IdentityMode};
use tokio::net::TcpStream;
use tower::Layer;

#[derive(Clone)]
pub(super) struct ClientIdentityAcceptor {
    mode: IdentityMode,
}

impl ClientIdentityAcceptor {
    pub(super) fn new(mode: IdentityMode) -> Self {
        Self { mode }
    }
}

impl<S> Accept<TcpStream, S> for ClientIdentityAcceptor
where
    S: Send + 'static,
{
    type Stream = TcpStream;
    type Service = AddExtension<S, ClientAddr>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let mode = self.mode.clone();
        Box::pin(async move {
            let (stream, address) = mode.identify(stream).await.map_err(|error| {
                tracing::warn!(%error, "Rejected connection during client identification");
                io::Error::other(error)
            })?;
            let service = Extension(address).layer(service);
            Ok((stream, service))
        })
    }
}
