//! Events service — in-memory broadcast channel (capacity 1000) for real-time SSE
//! streaming, combined with database persistence for historical replay.

mod query;
mod service;
mod stream;

pub(crate) use query::{EventStreamError, EventStreamQuery, Resume};
pub use service::{EventsService, MAX_EVENT_STREAM_USERS};
pub(crate) use service::{Mode, PG_NOTIFY_CHANNEL};
pub(crate) use stream::{EventStreamFilter, NoGuard, StreamCursor, StreamGuard};
