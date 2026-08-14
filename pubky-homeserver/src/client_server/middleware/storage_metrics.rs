//! Migration metrics for path-addressed and legacy storage requests.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use pubky_common::crypto::PublicKey;
use url::form_urlencoded;

use crate::{
    client_server::{auth::AuthSession, middleware::request_tenant::RequestTenant},
    observability::{Metrics, PubkyHostHeaderUsage, StorageAddressingMode, StorageAuthMethod},
};

pub(crate) async fn record_request(
    State(metrics): State<Metrics>,
    request: Request,
    next: Next,
) -> Response {
    let tenant = request.extensions().get::<RequestTenant>();
    let addressing_mode = if tenant.and_then(RequestTenant::storage_path).is_some() {
        StorageAddressingMode::Path
    } else {
        StorageAddressingMode::Legacy
    };
    let pubky_host_header = match request.headers().get("pubky-host") {
        None => PubkyHostHeaderUsage::Absent,
        Some(value)
            if value
                .to_str()
                .ok()
                .and_then(|value| PublicKey::try_from_z32(value).ok())
                .zip(tenant)
                .is_some_and(|(header, tenant)| &header == tenant.public_key()) =>
        {
            PubkyHostHeaderUsage::Matching
        }
        Some(_) => PubkyHostHeaderUsage::Other,
    };
    let pubky_host_query = request.uri().query().is_some_and(|query| {
        form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == "pubky-host")
    });
    let auth_method = match request.extensions().get::<AuthSession>() {
        Some(AuthSession::Cookie(_)) => StorageAuthMethod::Cookie,
        Some(AuthSession::Grant(_)) => StorageAuthMethod::Grant,
        None => StorageAuthMethod::None,
    };

    metrics.record_storage_request(
        addressing_mode,
        pubky_host_header,
        pubky_host_query,
        auth_method,
    );
    next.run(request).await
}
