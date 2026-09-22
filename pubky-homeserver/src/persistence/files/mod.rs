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
//! A write never touches the existing blob before it is finalized: every
//! backend publishes on close, and the filesystem backend does so by staging
//! the upload in `data/files-tmp` and renaming it into place. An upload that is
//! rejected, breaks mid-stream, or loses its client is aborted instead. Once
//! the body has streamed, finalization runs on its own task, so a client that
//! disconnects at that moment cannot stop it halfway. Two limits of that task:
//! a disconnect also drops the request's lock keep-alive, so a lock can expire
//! while its finalization is still running; and a runtime shutdown that cancels
//! the task leaves the staged upload neither published nor aborted.
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
