//! File storage and persistence coordination.
//!
//! Blob I/O is handled by [`opendal`] (supporting filesystem, in-memory, and GCS
//! backends). [`file`] provides the high-level [`FileService`](file::file_service::FileService),
//! which stores bytes under immutable internal keys and atomically switches the
//! logical entry pointer together with events and quota accounting.

mod blob_cleanup;
mod file;
mod opendal;
pub(crate) mod storage_quota;
mod write_preconditions;

pub(crate) mod events;

pub(crate) use blob_cleanup::BlobCleanupTask;
pub use file::file_io_error::{FileIoError, WriteStreamError};
pub(crate) use file::file_metadata::{content_hash_etag, FileMetadata, FileMetadataBuilder};
pub(crate) use file::file_service::BlobReadLease;
pub use file::file_service::{FileService, WriteOutcome};
pub use file::file_stream_type::FileStream;
pub use opendal::opendal_service::OpendalService;
pub(crate) use write_preconditions::WritePreconditions;
