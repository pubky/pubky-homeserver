//! Attach a verified client address to each accepted TCP connection.
//!
//! Serve with `into_make_service()`: Axum's `with_connect_info` service would
//! overwrite this address with the immediate TCP peer.

use std::{io, net::SocketAddr};

use axum::{extract::ConnectInfo, middleware::AddExtension, Extension};
use axum_server::accept::Accept;
use futures_util::future::BoxFuture;
use tcp_client_addr::IdentityMode;
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
    type Service = AddExtension<S, ConnectInfo<SocketAddr>>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let mode = self.mode.clone();
        Box::pin(async move {
            let (stream, address) = mode.identify(stream).await.map_err(|error| {
                tracing::warn!(%error, "Rejected connection during client identification");
                io::Error::other(error)
            })?;
            let service = Extension(ConnectInfo(address.normalized_client())).layer(service);
            Ok((stream, service))
        })
    }
}
