//! Grant + `PoP` authentication flow.
//!
//! The signer returns a user-signed `pubky-grant` JWS which the SDK exchanges
//! for a self-refreshing grant-backed session. Preferred for long-lived,
//! mirror-friendly sessions.

pub(crate) mod approval;
pub(crate) mod builder;
pub(crate) mod constants;
pub(crate) mod credential;
pub(crate) mod flow;
pub(crate) mod grant_exchange;
pub mod manager;
pub(crate) mod pop_signer;
pub mod service_auth;
#[doc(hidden)]
pub mod shared_session;
pub mod view;

pub use credential::{DelegatedGrantCredentialState, GrantCredential};
pub use flow::{DelegatedGrantAuthFlowState, GrantAuthFlowState, PubkyGrantAuthFlow};
pub use manager::GrantManager;
pub use service_auth::ServiceAuthProofError;
pub use view::GrantSessionView;
