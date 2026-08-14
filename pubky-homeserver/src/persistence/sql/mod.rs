//! PostgreSQL persistence.
//!
//! Manages the connection pool ([`SqlDb`]), schema migrations ([`Migrator`]),
//! and entity repositories for users, sessions, entries, events, and signup codes.
//! The [`UnifiedExecutor`] abstraction allows repository methods to work with
//! both pooled connections and explicit transactions.

mod connection_string;
pub(crate) mod entities;
mod migration;
pub(crate) mod migrations;
mod migrator;
mod pg_event_listener;
mod sql_db;
mod unified_executor;

pub use connection_string::ConnectionString;
pub use entities::entry;
pub use entities::signup_code;
pub(crate) use entities::user;
pub use migrator::Migrator;
pub(crate) use pg_event_listener::PgEventListener;
pub use sql_db::SqlDb;
pub(crate) use unified_executor::uexecutor;
pub(crate) use unified_executor::UnifiedExecutor;
