//! Test-only helpers for the storage layer: the backends the storage
//! contract runs on, the real GCS bucket, and layers that make a local
//! backend behave like, or report on, an object store.
//!
//! The contract itself is in `storage_contract.rs`.

mod counting_reads;
#[cfg(feature = "storage-gcs")]
pub(crate) mod gcs_test_bucket;
mod test_storage;
mod versioned;

pub(crate) use counting_reads::CountingReads;
#[cfg(feature = "storage-gcs")]
pub(crate) use gcs_test_bucket::TestBucket;
pub(crate) use test_storage::{
    get_fs_operator, get_memory_operator, storage_contract_tests, TestStorage,
};
pub(crate) use versioned::Versioned;
