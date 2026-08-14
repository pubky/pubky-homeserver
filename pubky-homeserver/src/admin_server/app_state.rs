use dav_server::{fakels::FakeLs, DavHandler};
use dav_server_opendalfs::OpendalFs;

use crate::AppContext;
use crate::ConfigToml;

#[derive(Clone, Default)]
pub(crate) struct AdminMetadata {
    pub(crate) public_key: String,
    pub(crate) pkarr_pubky_address: Option<String>,
    pub(crate) pkarr_icann_domain: Option<String>,
    pub(crate) version: String,
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) context: AppContext,
    pub(crate) admin_password: String,
    pub(crate) inner_dav_handler: DavHandler,
    pub(crate) metadata: AdminMetadata,
}

impl AppState {
    pub fn new(context: &AppContext) -> Self {
        let webdavfs = OpendalFs::new(context.file_service.opendal.admin_operator.clone());
        let inner_dav_handler = DavHandler::builder()
            .filesystem(webdavfs)
            .locksystem(FakeLs::new())
            .strip_prefix("/dav")
            .autoindex(true)
            .build_handler();
        Self {
            admin_password: context.config_toml.admin.admin_password.clone(),
            inner_dav_handler,
            metadata: AdminMetadata {
                public_key: context.keypair.public_key().z32(),
                pkarr_pubky_address: pkarr_pubky_tls_address(&context.config_toml),
                pkarr_icann_domain: pkarr_icann_domain(&context.config_toml),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            context: context.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_server(context: &AppContext) -> axum_test::TestServer {
        axum_test::TestServer::new(super::app::create_app(Self::new(context))).unwrap()
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
