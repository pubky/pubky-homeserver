use std::str::FromStr;

use wasm_bindgen::prelude::*;

use crate::{
    js_error::{JsResult, PubkyError, PubkyErrorName},
    wrappers::keys::PublicKey,
};

/// Parsed direct signup deeplink.
#[wasm_bindgen]
pub struct DirectSignupDeepLink(pubky::deep_links::DirectSignupDeepLink);

#[wasm_bindgen]
impl DirectSignupDeepLink {
    /// Parse a direct signup deeplink URL.
    #[wasm_bindgen(js_name = "parse")]
    pub fn try_from(url: &str) -> JsResult<Self> {
        Ok(Self(
            pubky::deep_links::DirectSignupDeepLink::from_str(url).map_err(|e| {
                PubkyError::new(
                    PubkyErrorName::InvalidInput,
                    format!("Invalid direct signup deep link: {e}"),
                )
            })?,
        ))
    }

    /// Homeserver public key requested for account creation.
    #[wasm_bindgen(getter)]
    pub fn homeserver(&self) -> PublicKey {
        PublicKey(self.0.params().homeserver.clone())
    }

    /// Optional signup token included in the request.
    #[wasm_bindgen(js_name = "signupToken", getter)]
    pub fn signup_token(&self) -> Option<String> {
        self.0.params().signup_token.clone()
    }

    #[allow(
        clippy::inherent_to_string,
        reason = "Display trait doesn't work with wasm-bindgen"
    )]
    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}
