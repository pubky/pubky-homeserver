#[cfg(feature = "storage-gcs")]
use super::opendal::gcs_name_repair::GcsNameRepairJob;
use crate::persistence::sql::SqlDb;
#[cfg(feature = "storage-gcs")]
use crate::storage_config::StorageConfigToml;
use crate::storage_config::StorageToml;

/// Background repairs the configured storage backend needs. Dropping it
/// stops them. Only Google Cloud Storage has one: the repair of the object
/// names of `gcs_name_repair`.
pub(crate) struct StorageRepair {
    #[cfg(feature = "storage-gcs")]
    _gcs_name_repair: Option<GcsNameRepairJob>,
}

impl StorageRepair {
    /// Start the repairs `storage` needs.
    // Without GCS support no backend needs a repair.
    #[cfg_attr(not(feature = "storage-gcs"), allow(unused_variables))]
    pub(crate) fn start(storage: &StorageToml, sql_db: &SqlDb) -> Self {
        Self {
            #[cfg(feature = "storage-gcs")]
            _gcs_name_repair: match &storage.backend {
                StorageConfigToml::GoogleBucket(config) => {
                    Some(GcsNameRepairJob::start(config, sql_db.clone()))
                }
                _ => None,
            },
        }
    }
}
