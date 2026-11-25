//! Finalizes storage mutations and their corresponding database effects.

mod delete;
mod layer;
mod quota;
mod upload_limit;
mod write;
pub(crate) mod write_lock;

pub use delete::WriteFinalizationDeleter;
#[cfg(test)]
pub(crate) use layer::test_support;
pub use layer::WriteFinalizationLayer;
pub(crate) use quota::{would_exceed_quota, write_bytes_delta};
pub(in crate::persistence::files) use upload_limit::{UploadLimit, UploadSlot};
pub use write::WriteFinalizationWriter;
