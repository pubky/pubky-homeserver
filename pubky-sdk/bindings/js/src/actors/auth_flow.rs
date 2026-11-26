use wasm_bindgen::prelude::*;

use crate::wrappers::keys::PublicKey;

/// The kind of authentication flow to perform.
/// This can either be a sign in or a sign up flow.
#[wasm_bindgen]
#[derive(Clone)]
pub struct AuthFlowKind(pub(crate) pubky::AuthFlowKind);

#[wasm_bindgen]
impl AuthFlowKind {
    /// Create a sign in flow.
    #[wasm_bindgen(js_name = "signin")]
    pub fn signin() -> Self {
        Self(pubky::AuthFlowKind::SignIn)
    }

    /// Create a sign up flow.
    /// # Arguments
    /// * `homeserver_public_key` - The public key of the homeserver to sign up on.
    /// * `signup_token` - The signup token to use for the signup flow. This is optional.
    #[wasm_bindgen(js_name = "signup")]
    pub fn signup(homeserver_public_key: &PublicKey, signup_token: Option<String>) -> Self {
        Self(pubky::AuthFlowKind::SignUp {
            homeserver_public_key: Box::new(homeserver_public_key.0.to_owned()),
            signup_token,
        })
    }

    /// Get the intent of the authentication flow.
    /// # Returns
    /// * `"signin"` - If the authentication flow is a sign in flow.
    /// * `"signup"` - If the authentication flow is a sign up flow.
    #[wasm_bindgen(js_name = "intent", getter)]
    pub fn intent(&self) -> String {
        match &self.0 {
            pubky::AuthFlowKind::SignIn => "signin".to_string(),
            pubky::AuthFlowKind::SignUp { .. } => "signup".to_string(),
        }
    }
}
