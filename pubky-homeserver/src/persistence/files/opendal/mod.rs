//! OpenDAL-based storage backend.
//!
//! [`OpendalService`](opendal_service::OpendalService) configures the appropriate
//! storage operator (filesystem, in-memory, or GCS) based on the server's
//! [`StorageConfig`](crate::data_directory::storage_config::StorageConfig).

#[cfg(feature = "storage-gcs")]
pub(crate) mod gcs_name_repair;
pub mod opendal_service;
#[cfg(test)]
pub(crate) mod opendal_test_operators;
