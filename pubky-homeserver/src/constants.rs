// The default limit of a list api if no `limit` query parameter is provided.
pub const DEFAULT_LIST_LIMIT: u16 = 100;
pub const DEFAULT_MAX_LIST_LIMIT: u16 = 1000;

/// Maximum upload body size in bytes, enforced on both storage PUT routes.
pub const MAX_UPLOAD_BYTES: usize = 100 * 1024 * 1024;

/// Storage root for private data (`/priv/...`).
pub use pubky_common::constants::storage::PRIVATE_ROOT;

/// Storage root for public data (`/pub/...`).
pub use pubky_common::constants::storage::PUBLIC_ROOT;
