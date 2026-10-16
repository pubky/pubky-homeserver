use axum::extract::Request;
use std::net::IpAddr;
use tcp_client_addr::ClientAddr;

#[derive(Debug, thiserror::Error)]
#[error("Verified client address is missing")]
pub(super) struct MissingClientAddress;

pub(super) fn extract_ip<T>(req: &Request<T>) -> Result<IpAddr, MissingClientAddress> {
    req.extensions()
        .get::<ClientAddr>()
        .map(|address| address.client_ip())
        .ok_or(MissingClientAddress)
}
