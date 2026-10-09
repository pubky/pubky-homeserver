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
//! # Write lifecycle
//!
//! A write never touches the existing blob before it is finalized: every
//! backend publishes on close, and the filesystem backend does so by staging
//! the upload in `data/files-tmp` and renaming it into place. An upload that is
//! rejected by quota or a collision, breaks mid-stream, or loses its client is
//! aborted instead, leaving the existing blob untouched.
//!
//! Finalizing a write publishes the blob and then commits the entry row;
//! finalizing a delete commits the row removal and then removes the blob,
//! unless a write has put the file back in between. Blob
//! storage cannot join the database transaction, so the two can diverge if the
//! database update fails after publication or the process dies between the
//! steps: the blob then holds new content while the entry describes the old,
//! or no entry exists, or an unreferenced blob remains after a delete. A client
//! disconnect cannot cause this: the finalization layer runs every
//! finalization on its own task, so dropping the request, or any other user of
//! the operator, cannot stop it halfway. A writer dropped before it closes, as
//! a disconnect mid-upload does, discards its staged bytes the same way.
//!
//! A write under a lock reserves the lock for as long as its publish can
//! still reach the backend, so the lock cannot change hands under it and a
//! stalled publish can never land on top of the next holder. A write whose
//! lock is gone, or still reserved for an earlier change, is refused before
//! it publishes. See [`write_finalization_layer::write_lock`].
//!
//! One limit of that task: a runtime shutdown that cancels it leaves the
//! staged upload neither published nor aborted.
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
