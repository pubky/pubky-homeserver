// The default limit of a list api if no `limit` query parameter is provided.
pub const DEFAULT_LIST_LIMIT: u16 = 100;
pub const DEFAULT_MAX_LIST_LIMIT: u16 = 1000;

/// Storage root for private data (`/priv/...`).
pub use pubky_common::constants::storage::PRIVATE_ROOT;

/// Storage root for public data (`/pub/...`).
pub use pubky_common::constants::storage::PUBLIC_ROOT;
