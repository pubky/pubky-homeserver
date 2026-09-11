//! Database entity definitions and repositories.
//!
//! Each submodule defines a domain entity struct and a repository with
//! query/mutation methods:
//! - [`blob`]: Immutable blob upload and deferred-deletion bookkeeping.
//! - [`user`]: User accounts keyed by Ed25519 public key, with quota tracking.
//! - [`entry`]: File metadata (path, content hash, MIME type, timestamps).
//! - [`signup_code`]: Token-gated registration codes.

pub mod blob;
pub mod entry;
pub mod signup_code;
pub mod user;
