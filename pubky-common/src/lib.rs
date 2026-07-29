#![doc = include_str!("../README.md")]
//!

#![warn(unused_crate_dependencies)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(any(), deny(clippy::unwrap_used))]

pub mod auth;
pub mod capabilities;
pub mod constants;
pub mod crypto;
pub mod events;
mod keys;
pub mod namespaces;
pub mod recovery_file;
pub mod session;

pub mod timestamp {
    //! Timestamp used across Pubky crates.
    pub use pubky_timestamp::*;
}

pub mod storage_path;
pub use storage_path::{StoragePath, StoragePathError};
