use std::str::FromStr;

use js_sys::Uint8Array;
use tsify::Ts;
use wasm_bindgen::prelude::*;

use crate::{
    js_error::{JsResult, PubkyError, PubkyErrorName, serialize_ts},
    wrappers::keys::PublicKey,
};

use super::XCallbackParams;

/// Parsed parent-grant deeplink, for signer UIs that show it before approving.
#[wasm_bindgen]
pub struct ParentGrantDeepLink(pubky::deep_links::ParentGrantDeepLink);

#[wasm_bindgen]
impl ParentGrantDeepLink {
    /// Parse a parent-grant deeplink URL.
    ///
    /// @throws {PubkyError} `InvalidInput` when the URL is malformed, exceeds
    /// `/pub/:rwe` and `/priv/:rwe`, or has no exact HTTPS callback.
    #[wasm_bindgen(js_name = "parse")]
    pub fn try_from(url: &str) -> JsResult<Self> {
        Ok(Self(
            pubky::deep_links::ParentGrantDeepLink::from_str(url).map_err(|e| {
                PubkyError::new(
                    PubkyErrorName::InvalidInput,
                    format!("Invalid parent grant deep link: {e}"),
                )
            })?,
        ))
    }

    /// Capabilities requested by the holder.
    #[wasm_bindgen(getter)]
    pub fn capabilities(&self) -> String {
        self.0.params().capabilities.to_string()
    }

    /// Base HTTP relay inbox URL used by this request.
    #[wasm_bindgen(js_name = "baseRelayUrl", getter)]
    pub fn base_relay_url(&self) -> String {
        self.0.params().relay.to_string()
    }

    /// The holder's exact callback URL.
    #[wasm_bindgen(js_name = "clientId", getter)]
    pub fn client_id(&self) -> String {
        self.0.params().client_id.to_string()
    }

    /// Public key of the holder's signing key, which signs child grants.
    #[wasm_bindgen(js_name = "clientPublicKey", getter)]
    pub fn client_public_key(&self) -> PublicKey {
        PublicKey(self.0.params().client_pk.clone())
    }

    /// The 32-byte HPKE public key the approval is encrypted to.
    #[wasm_bindgen(js_name = "ephemeralPublicKey", getter)]
    pub fn ephemeral_public_key(&self) -> Uint8Array {
        Uint8Array::from(self.0.params().ephemeral_public_key.as_slice())
    }

    /// Optional x-callback-url metadata carried by this deep link.
    #[wasm_bindgen(js_name = "xCallback", getter)]
    pub fn x_callback(&self) -> JsResult<Ts<XCallbackParams>> {
        serialize_ts(&XCallbackParams::from(self.0.x_callback()))
    }

    /// Serialize this link back to its URL.
    #[wasm_bindgen(js_name = "toString")]
    #[allow(
        clippy::inherent_to_string,
        reason = "Exposed as JavaScript's toString"
    )]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}
