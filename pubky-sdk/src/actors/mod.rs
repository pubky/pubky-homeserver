pub(crate) mod auth;
pub mod event_stream;
pub mod pkdns;
mod session;
mod signer;
pub mod storage;

pub use auth::AuthFlowKind;
#[allow(deprecated, reason = "Re-exporting deprecated public API")]
pub use auth::cookie::PubkyCookieAuthFlow;
#[allow(deprecated, reason = "Re-exporting deprecated public API")]
pub use auth::cookie::{CookieCredential, CookieSessionView};
pub use auth::deep_links;
#[doc(hidden)]
pub use auth::grant::pop_signer::{DelegatedSignFn, delegated_sign_callback};
pub use auth::grant::{DelegatedGrantAuthFlowState, GrantAuthFlowState, PubkyGrantAuthFlow};
pub use auth::grant::{
    DelegatedGrantCredentialState, GrantCredential, GrantManager, GrantSessionView,
};
pub use auth::relay::http_relay_inbox_channel::{
    DEFAULT_HTTP_RELAY_INBOX, EncryptedHttpRelayInboxChannel, HttpRelayInboxChannel,
};
#[allow(
    deprecated,
    reason = "Re-exporting deprecated public API for backwards compat"
)]
pub use auth::relay::http_relay_link_channel::DEFAULT_HTTP_RELAY;
pub use event_stream::{Event, EventCursor, EventStreamBuilder, EventType};
pub use pkdns::Pkdns;
pub use session::SessionInfo;
pub use session::core::PubkySession;
pub use signer::PubkySigner;
pub use storage::core::{PublicStorage, SessionStorage};
