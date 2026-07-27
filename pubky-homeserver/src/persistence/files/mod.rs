//! File storage and associated middleware.
//!
//! Blob I/O is handled by [`opendal`] (supporting filesystem, in-memory, and GCS
//! backends). Operations pass through a layered middleware stack (outermost first):
//!
//! 1. **[`write_path_layer`]** — enforces per-user allowed write paths (outermost, runs first).
//! 2. **[`write_finalization_layer`]** — atomically finalizes collision checks,
//!    entry metadata, events, and quota accounting around backend writes.
//! 3. **OpenDAL base** — physical storage I/O.
//!
//! [`file`] provides the high-level [`FileService`](file::file_service::FileService)
//! used by route handlers.

mod file;
mod layer_domain_error;
mod opendal;

pub(crate) mod events;
pub(crate) mod write_finalization_layer;
pub(crate) mod write_path_layer;

pub use file::file_io_error::{FileIoError, WriteStreamError};
pub(crate) use file::file_metadata::{FileMetadata, FileMetadataBuilder};
pub use file::file_service::FileService;
pub use file::file_stream_type::FileStream;
pub use opendal::opendal_service::OpendalService;
