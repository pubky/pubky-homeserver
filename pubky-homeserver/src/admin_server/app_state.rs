use std::sync::Arc;

use dav_server::{fakels::FakeLs, DavHandler};
use dav_server_opendalfs::OpendalFs;

use crate::AppContext;
use crate::ConfigToml;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) context: Arc<AppContext>,
    pub(crate) inner_dav_handler: DavHandler,
}

impl AppState {
    pub fn new(context: Arc<AppContext>) -> Self {
        let webdavfs = OpendalFs::new(context.file_service.opendal.admin_operator.clone());
        let inner_dav_handler = DavHandler::builder()
            .filesystem(webdavfs)
            .locksystem(FakeLs::new())
            .strip_prefix("/dav")
            .autoindex(true)
            .build_handler();
        Self {
            inner_dav_handler,
            context,
        }
    }

    pub(crate) fn admin_password(&self) -> &str {
        &self.context.config_toml.admin.admin_password
    }

    pub(crate) fn public_key(&self) -> String {
        self.context.keypair.public_key().z32()
    }

    pub(crate) fn pkarr_pubky_address(&self) -> Option<String> {
        pkarr_pubky_tls_address(&self.context.config_toml)
    }

    pub(crate) fn pkarr_icann_domain(&self) -> Option<String> {
        pkarr_icann_domain(&self.context.config_toml)
    }

    pub(crate) fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    #[cfg(test)]
    pub(crate) fn test_server(context: &Arc<AppContext>) -> axum_test::TestServer {
        axum_test::TestServer::new(super::app::create_app(Self::new(Arc::clone(context)))).unwrap()
    }
}

fn pkarr_pubky_tls_address(config: &ConfigToml) -> Option<String> {
    let port = config
        .pkdns
        .public_pubky_tls_port
        .unwrap_or(config.drive.pubky_listen_socket.port());

    if port == 0 {
        return None;
    }

    Some(format!("{}:{}", config.pkdns.public_ip, port))
}

fn pkarr_icann_domain(config: &ConfigToml) -> Option<String> {
    let domain = config.pkdns.icann_domain.as_ref()?;
    let port = config
        .pkdns
        .public_icann_http_port
        .unwrap_or(config.drive.icann_listen_socket.port());

    if port == 0 {
        return None;
    }

    Some(format!("{}:{}", domain.0, port))
}
