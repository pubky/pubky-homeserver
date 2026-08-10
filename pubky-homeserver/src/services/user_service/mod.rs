//! User service — coordinates user lookups, creation, quota enforcement, and caching.

mod quota_cache;
mod service;

pub use service::{UserService, FILE_METADATA_SIZE};

// Re-export entity types as the canonical public surface.
pub use crate::persistence::sql::user::UserEntity;
