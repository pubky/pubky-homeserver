//! Custom proofs signed by a grant's client key, with offline verification.
//!
//! Applications define the JSON data and validate its meaning, including any
//! audience, challenge, freshness, replay protection, and authorization rules.

mod proof;
mod verifier;

pub use crate::actors::CustomPopError;
pub(crate) use proof::CustomPopClaims;
pub use proof::{CUSTOM_POP_JWS_TYP, CustomPop};
pub use verifier::{
    CustomPopVerificationError, DEFAULT_CUSTOM_POP_CLOCK_SKEW, VerifiedCustomPop,
    verify_custom_grant_pop,
};
