//! Events service — in-memory broadcast channel (capacity 1000) for real-time SSE
//! streaming, combined with database persistence for historical replay.

mod query;
mod service;
mod stream;

pub(crate) use query::{AdminStreamQuery, ClientStreamQuery, EventStreamError};
pub(crate) use service::{AllEventsFilter, Mode, UserEventsFilter, PG_NOTIFY_CHANNEL};
pub use service::{EventsService, MAX_EVENT_STREAM_USERS};
pub(crate) use stream::StreamGuard;
