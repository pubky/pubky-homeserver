use dav_server::{fakels::FakeLs, DavHandler};
use dav_server_opendalfs::OpendalFs;

use crate::data_directory::DefaultQuotasToml;
use crate::observability::Metrics;
use crate::persistence::{
    files::{events::EventsService, FileService},
    sql::SqlDb,
};
use crate::services::user_service::UserService;
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
    pub(crate) sql_db: SqlDb,
    pub(crate) file_service: FileService,
    pub(crate) admin_password: String,
    pub(crate) inner_dav_handler: DavHandler,
    pub(crate) metadata: AdminMetadata,
    pub(crate) user_service: UserService,
    /// Event service for the admin all-events stream.
    pub(crate) events_service: EventsService,
    /// Metrics shared with the rest of the homeserver.
    pub(crate) metrics: Metrics,
    /// System-wide default quotas for resolving effective values.
    pub(crate) default_storage_mb: Option<u64>,
    pub(crate) default_quotas: DefaultQuotasToml,
}

impl AppState {
    pub fn new(
        sql_db: SqlDb,
        file_service: FileService,
        admin_password: &str,
        user_service: UserService,
        events_service: EventsService,
        metrics: Metrics,
    ) -> Self {
        let webdavfs = OpendalFs::new(file_service.opendal.admin_operator.clone());
        let inner_dav_handler = DavHandler::builder()
            .filesystem(webdavfs)
            .locksystem(FakeLs::new())
            .strip_prefix("/dav")
            .autoindex(true)
            .build_handler();
        Self {
            sql_db,
            file_service,
            admin_password: admin_password.to_string(),
            inner_dav_handler,
            metadata: AdminMetadata::default(),
            user_service,
            events_service,
            metrics,
            default_storage_mb: None,
            default_quotas: DefaultQuotasToml::default(),
        }
    }

    pub fn with_metadata_from_config(
        mut self,
        public_key: String,
        config: &ConfigToml,
        version: &str,
    ) -> Self {
        self.metadata = AdminMetadata {
            public_key,
            pkarr_pubky_address: pkarr_pubky_tls_address(config),
            pkarr_icann_domain: pkarr_icann_domain(config),
            version: version.to_string(),
        };
        self.default_storage_mb = config.storage.default_quota_mb;
        self.default_quotas = config.default_quotas.clone();
        self
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
