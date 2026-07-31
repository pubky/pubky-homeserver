//! Cross-instance notification of authentication revocations.
//!
//! A private SSE subscription authorizes once when it is opened, so a normal
//! request-time auth check is not enough to stop it after its credential is
//! revoked. This module forwards Postgres `LISTEN`/`NOTIFY` messages to a local
//! broadcast channel that those subscriptions can observe.
//!
//! This listener intentionally has its own connection instead of sharing the
//! file-event listener. File events have a durable database catch-up path;
//! auth revocations do not, and therefore must fail closed on any listener
//! gap. Sharing lifecycle and failure handling would make an event-listener
//! disruption unnecessarily disconnect every private stream.
//!
//! The current listener actor holds the broadcast sender, so anything that
//! ends that actor closes every stream it handed a receiver to. The supervisor
//! starts a replacement for the next subscription, and a replacement can never
//! revive its predecessor's receivers.

mod listener;
mod notification;

pub(crate) use listener::{RevocationListener, RevocationUnavailable};
pub(crate) use notification::AuthRevocation;

/// Postgres channel used for committed authentication revocations.
pub(super) const PG_AUTH_REVOCATION_CHANNEL: &str = "auth_revocations";
