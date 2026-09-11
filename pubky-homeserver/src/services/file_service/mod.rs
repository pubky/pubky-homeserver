//! Coordinates immutable backend blobs with logical file entries, quota, and events.

mod admin;
mod cleanup;
mod cleanup_task;
mod reads;
mod service;
mod upload_heartbeat;
mod writes;

pub(crate) use cleanup_task::BlobCleanupTask;
pub use service::FileService;
