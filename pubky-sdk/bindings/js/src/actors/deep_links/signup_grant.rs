use std::str::FromStr;

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use crate::{
    js_error::{JsResult, PubkyError, PubkyErrorName},
    wrappers::keys::PublicKey,
};

use super::XCallbackParams;

/// Parsed grant-based signup deeplink.
///
/// This is useful for tools, tests, and signer UIs that need to inspect a
/// `pubky://signup-grant` authorization URL before approving it.
#[wasm_bindgen]
pub struct SignupGrantDeepLink(pubky::deep_links::SignupGrantDeepLink);

#[wasm_bindgen]
impl SignupGrantDeepLink {
    /// Parse a grant signup deeplink URL.
    ///
    /// @param {string} url
    /// @returns {SignupGrantDeepLink}
    /// @throws {PubkyError} `InvalidInput` when the URL is malformed or not a grant signup link.
    #[wasm_bindgen(js_name = "parse")]
    pub fn try_from(url: &str) -> JsResult<Self> {
        Ok(Self(
            pubky::deep_links::SignupGrantDeepLink::from_str(url).map_err(|e| {
                PubkyError::new(
                    PubkyErrorName::InvalidInput,
                    format!("Invalid signup grant deep link: {}", e),
                )
            })?,
        ))
    }

    /// Capabilities requested by the application.
    ///
    /// @returns {string}
    #[wasm_bindgen(getter)]
    pub fn capabilities(&self) -> String {
        self.0.params().capabilities.to_string()
    }

    /// Base HTTP relay inbox URL used by this auth request.
    ///
    /// @returns {string}
    #[wasm_bindgen(js_name = "baseRelayUrl", getter)]
    pub fn base_relay_url(&self) -> String {
        self.0.params().relay.to_string()
    }

    /// Relay channel secret embedded in the deeplink.
    ///
    /// Treat this as sensitive temporary auth-flow material.
    ///
    /// @returns {Uint8Array}
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Uint8Array {
        Uint8Array::from(self.0.params().secret.as_ref())
    }

    /// Homeserver public key requested for account creation.
    ///
    /// @returns {PublicKey}
    #[wasm_bindgen(getter)]
    pub fn homeserver(&self) -> PublicKey {
        PublicKey(self.0.params().homeserver.clone())
    }

    /// Optional signup token included in the request.
    ///
    /// @returns {string|undefined}
    #[wasm_bindgen(js_name = "signupToken", getter)]
    pub fn signup_token(&self) -> Option<String> {
        self.0.params().signup_token.clone()
    }

    /// Application identifier shown in the user's grant/session list.
    ///
    /// @returns {string}
    #[wasm_bindgen(js_name = "clientId", getter)]
    pub fn client_id(&self) -> String {
        self.0.params().client_id.to_string()
    }

    /// Public key for the Proof-of-Possession client created by the application.
    ///
    /// @returns {PublicKey}
    #[wasm_bindgen(js_name = "clientPublicKey", getter)]
    pub fn client_public_key(&self) -> PublicKey {
        PublicKey(self.0.params().client_pk.clone())
    }

    /// Optional x-callback-url metadata carried by this deep link.
    #[wasm_bindgen(js_name = "xCallback", getter)]
    pub fn x_callback(&self) -> XCallbackParams {
        self.0.x_callback().into()
    }

    #[allow(
        clippy::inherent_to_string,
        reason = "Display trait doesn't work with wasm-bindgen"
    )]
    /// Serialize this parsed deeplink back to its URL form.
    ///
    /// @returns {string}
    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}
