//! Event entity and repository for file change notifications.
//!
//! - [`EventEntity`]: Represents a PUT or DEL event with path, content hash, and cursor ID.
//! - [`EventRepository`]: Database queries for historical event retrieval and cursor pagination.
//! - [`PathFilter`]: Authorized path filter shared by the routes and the repository.

mod entity;
mod path_filter;
mod repository;

pub use entity::EventEntity;
pub use path_filter::PathFilter;
pub use repository::{EventIden, EventRepository, EventVisibility};

// Re-export from pubky_common for convenience
pub use pubky_common::events::{EventCursor, EventType};
