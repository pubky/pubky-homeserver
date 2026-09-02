//! High-level file I/O abstractions.
//!
//! [`file_service::FileService`] is the main interface used by route handlers for
//! reading, writing, deleting, and listing files. It stores immutable backend
//! objects behind database-managed logical entries and provides streaming I/O
//! with 16KB chunks.

pub mod file_io_error;
pub mod file_metadata;
pub mod file_service;
pub mod file_stream_type;
