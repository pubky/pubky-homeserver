//! Event system for file change notifications.
//!
//! - [`EventEntity`]: Represents a PUT or DEL event with path, content hash, and cursor ID.
//! - [`EventRepository`]: Database queries for historical event retrieval and cursor pagination.
//! - [`EventsService`]: In-memory broadcast channel (capacity 1000) for real-time SSE
//!   streaming, combined with database persistence for historical replay.

mod events_entity;
pub(crate) mod events_repository;
mod events_service;
mod path_filter;

pub use events_entity::EventEntity;
pub use events_repository::{EventIden, EventRepository, EventVisibility};
pub(crate) use events_service::{AllEventsFilter, Mode, PG_NOTIFY_CHANNEL};
pub use events_service::{EventsService, MAX_EVENT_STREAM_USERS};
pub use path_filter::PathFilter;

// Re-export from pubky_common for convenience
pub use pubky_common::events::{EventCursor, EventType};
