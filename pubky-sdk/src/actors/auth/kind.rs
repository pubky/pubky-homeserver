use crate::PublicKey;

/// The kind of authentication flow to perform.
///
/// Used when starting a [`PubkyGrantAuthFlow`](crate::PubkyGrantAuthFlow) or
/// legacy cookie auth flow to tell the SDK whether the user already has an
/// account (`SignIn`) or needs to create one (`SignUp`).
///
/// # When to use which
///
/// - **`SignUp`** — the user does not yet have an account. The flow creates
///   the account on the specified homeserver as part of the auth handshake.
///   Some homeservers require a `signup_token` (invite code).
/// - **`SignIn`** — the user already signed up on a homeserver. The flow
///   authenticates against the existing account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFlowKind {
    /// Sign in to an existing account.
    SignIn,
    /// Sign up for a new account on a specific homeserver.
    SignUp {
        /// The public key of the homeserver to sign up on.
        homeserver_public_key: Box<PublicKey>,
        /// Optional invite token required by some homeservers.
        signup_token: Option<String>,
    },
}

impl AuthFlowKind {
    /// Create a sign-in flow kind.
    #[must_use]
    pub fn signin() -> Self {
        Self::SignIn
    }

    /// Create a sign-up flow kind.
    ///
    /// # Arguments
    /// - `homeserver_public_key` — the public key of the homeserver to create the account on.
    /// - `signup_token` — optional invite token required by some homeservers.
    #[must_use]
    pub fn signup(homeserver_public_key: PublicKey, signup_token: Option<String>) -> Self {
        Self::SignUp {
            homeserver_public_key: Box::new(homeserver_public_key),
            signup_token,
        }
    }
}
