//! Identify TCP connections and resolve trusted HTTP client headers per request.

use std::{io, net::IpAddr};

use axum::{
    extract::{Request, State},
    http::{header::InvalidHeaderName, HeaderName, StatusCode},
    middleware::{self, AddExtension, Next},
    response::Response,
    Extension, Router,
};
use axum_server::accept::Accept;
use futures_util::future::BoxFuture;
use ipnet::IpNet;
use tcp_client_addr::{ClientAddr, IdentityMode};
use tokio::net::TcpStream;
use tower::Layer;

use crate::ClientIdentityToml;

/// Enforce the listener's peer policy and attach its TCP client address.
#[derive(Clone)]
pub(super) struct ClientIdentityAcceptor {
    mode: IdentityMode,
    trusted_header_proxies: Option<Vec<IpNet>>,
}

impl ClientIdentityAcceptor {
    pub(super) fn from_config(
        config: &ClientIdentityToml,
    ) -> Result<Self, tcp_client_addr::ConfigError> {
        let trusted_header_proxies = match config {
            ClientIdentityToml::HttpHeader {
                trusted_proxies, ..
            } => Some(trusted_proxies.clone()),
            ClientIdentityToml::Direct {} | ClientIdentityToml::ProxyProtocol { .. } => None,
        };
        Ok(Self {
            mode: config.to_identity_mode()?,
            trusted_header_proxies,
        })
    }

    /// Reject untrusted header proxies before HTTP parsing or TLS handshakes.
    fn check_peer(&self, stream: &TcpStream) -> io::Result<()> {
        let peer = stream.peer_addr()?;
        if self.trusts_peer(peer.ip()) {
            return Ok(());
        }
        tracing::warn!(%peer, "Rejected connection from untrusted HTTP header proxy");
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted HTTP header proxy",
        ))
    }

    fn trusts_peer(&self, peer: IpAddr) -> bool {
        let Some(networks) = &self.trusted_header_proxies else {
            return true;
        };
        // Dual-stack sockets can report IPv4 peers as mapped IPv6 addresses.
        let canonical_peer = peer.to_canonical();
        networks
            .iter()
            .any(|network| network.contains(&peer) || network.contains(&canonical_peer))
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
        // Borrow the allowlist before creating the owned connection future.
        let peer_check = self.check_peer(&stream);
        let mode = self.mode.clone();
        Box::pin(async move {
            peer_check?;
            let (stream, address) = mode.identify(stream).await.map_err(|error| {
                tracing::warn!(%error, "Rejected connection during client identification");
                io::Error::other(error)
            })?;
            let service = Extension(address).layer(service);
            Ok((stream, service))
        })
    }
}

/// An IP resolved from the configured header for this request only.
#[derive(Clone, Copy)]
pub(crate) struct HeaderClientIp(pub(crate) IpAddr);

/// Wrap the complete router so identity is resolved before either rate limiter.
pub(super) fn with_http_header_identity(
    router: Router,
    header: &str,
) -> Result<Router, InvalidHeaderName> {
    let header: HeaderName = header.parse()?;
    Ok(router.layer(middleware::from_fn_with_state(header, resolve_http_header)))
}

async fn resolve_http_header(
    State(header): State<HeaderName>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let mut values = request.headers().get_all(&header).iter();
    let value = values.next().ok_or(StatusCode::BAD_REQUEST)?;
    if values.next().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let ip: IpAddr = value
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .parse()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    request
        .extensions_mut()
        .insert(HeaderClientIp(ip.to_canonical()));
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_header_matches_original_and_canonical_peer_addresses() {
        for (network, peer, trusted) in [
            ("::ffff:127.0.0.1/128", "::ffff:127.0.0.1", true),
            ("127.0.0.1/32", "::ffff:127.0.0.1", true),
            ("127.0.0.1/32", "127.0.0.1", true),
            ("2001:db8::/64", "2001:db8::1", true),
            ("::ffff:127.0.0.1/128", "::ffff:127.0.0.2", false),
            ("127.0.0.1/32", "::ffff:127.0.0.2", false),
            ("2001:db8::/64", "2001:db8:1::1", false),
        ] {
            let identity = ClientIdentityAcceptor::from_config(&ClientIdentityToml::HttpHeader {
                header: "x-real-ip".into(),
                trusted_proxies: vec![network.parse().unwrap()],
            })
            .unwrap();
            assert_eq!(
                identity.trusts_peer(peer.parse().unwrap()),
                trusted,
                "network {network}, peer {peer}"
            );
        }
    }

    #[test]
    fn http_header_rejects_invalid_configured_header_names() {
        for header in ["", "bad header", "bad:header"] {
            assert!(with_http_header_identity(Router::new(), header).is_err());
        }
    }
}
