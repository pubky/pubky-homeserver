//! Data persistence layer.
//!
//! - [`sql`]: PostgreSQL storage for users, sessions, entries (file metadata),
//!   events, and signup codes. Uses the repository pattern with `sea-query`.
//! - [`files`]: Immutable blob storage via OpenDAL (filesystem, in-memory, or GCS)
//!   coordinated with logical entries, quota accounting, and events in PostgreSQL.

pub mod files;
pub mod sql;
