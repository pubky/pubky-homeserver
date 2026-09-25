use axum::extract::{ConnectInfo, Request};
use std::net::{IpAddr, SocketAddr};

pub fn extract_ip<T>(req: &Request<T>) -> anyhow::Result<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|address| address.ip())
        .ok_or_else(|| anyhow::anyhow!("Verified client address is missing"))
}
