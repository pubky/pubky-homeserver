//! Database entity definitions and repositories.
//!
//! Each submodule defines a domain entity struct and a repository with
//! query/mutation methods:
//! - [`user`]: User accounts keyed by Ed25519 public key, with quota tracking.
//! - [`entry`]: File metadata (path, content hash, MIME type, timestamps).
//! - [`signup_code`]: Token-gated registration codes.
//! - [`entry_lock`]: Exclusive WebDAV write locks on storage paths.

pub mod entry;
pub mod entry_lock;
pub mod signup_code;
pub mod user;
