//! File storage types and backend I/O.
//!
//! Blob I/O is handled by [`opendal`] (supporting filesystem, in-memory, and GCS
//! backends). [`FileService`](crate::services::file_service::FileService) coordinates
//! immutable blobs with database-managed logical entries, events, and quota accounting.

mod file;
mod opendal;
pub(crate) mod storage_quota;

pub(crate) mod events;

pub use file::file_io_error::{FileIoError, WriteStreamError};
pub(crate) use file::file_metadata::{FileMetadata, FileMetadataBuilder};
pub use file::file_stream_type::FileStream;
pub use opendal::opendal_service::OpendalService;
