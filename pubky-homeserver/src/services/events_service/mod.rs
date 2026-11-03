//! Events service — in-memory broadcast channel (capacity 1000) for real-time SSE
//! streaming, combined with database persistence for historical replay.

mod query;
mod service;

pub(crate) use query::{EventStreamError, EventStreamQuery, StreamKind};
pub(crate) use service::{AllEventsFilter, Mode, PG_NOTIFY_CHANNEL};
pub use service::{EventsService, MAX_EVENT_STREAM_USERS};
