//! Application services — business logic and coordination.
//!
//! A service is organised around a capability of the homeserver, such as
//! users, signup, events or files. The split keeps each layer to one job:
//! route handlers turn HTTP into a service call and the result back into a
//! response, services hold the rules and coordinate the work, and
//! repositories only read and write rows.
//!
//! A few things follow from that:
//!
//! - Handlers reach data through a service, never a repository or the pool
//!   directly, so the rules of a capability live in one place.
//! - A service takes what it depends on at construction: a database handle,
//!   other services, the config values it decides on. It does not carry the
//!   whole config or context, which keeps its inputs visible.
//! - A service that both the client and admin servers use lives here and is
//!   built once on `AppContext`. One that only serves a single transport can
//!   stay with that transport, as the auth services do.
//! - Services run on their own pool unless a caller needs the work inside a
//!   larger transaction, in which case an executor-taking variant exists for
//!   that caller. Repositories always use the executor they are given.
//! - Services return domain errors. Turning them into HTTP responses is the
//!   server's job.
//!
//! Treat these as the default shape, not a checklist. When a capability does
//! not fit, say why in the code.

pub mod events_service;
pub mod signup_service;
pub mod user_service;
