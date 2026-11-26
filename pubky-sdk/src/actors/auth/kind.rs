use crate::PublicKey;

/// The intent a requesting app sends to the signer in a
/// [`PubkyGrantAuthFlow`](crate::PubkyGrantAuthFlow).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFlowKind {
    /// Sign in to an existing account.
    SignIn,
    /// Request a new account on a specific homeserver. The signer app must call
    /// [`PubkySigner::signup`](crate::PubkySigner::signup) with the homeserver
    /// and optional invite token before approving the request.
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
