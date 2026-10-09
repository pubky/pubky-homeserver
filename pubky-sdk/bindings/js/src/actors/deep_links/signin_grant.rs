use std::str::FromStr;

use js_sys::Uint8Array;
use tsify::Ts;
use wasm_bindgen::prelude::*;

use crate::{
    js_error::{JsResult, PubkyError, PubkyErrorName, serialize_ts},
    wrappers::keys::PublicKey,
};

use super::XCallbackParams;

/// Parsed grant-based signin deeplink.
///
/// This is useful for tools, tests, and signer UIs that need to inspect a
/// `pubky://signin-grant` authorization URL before approving it.
#[wasm_bindgen]
pub struct SigninGrantDeepLink(pubky::deep_links::SigninGrantDeepLink);

#[wasm_bindgen]
impl SigninGrantDeepLink {
    /// Parse a grant signin deeplink URL.
    ///
    /// @param {string} url
    /// @returns {SigninGrantDeepLink}
    /// @throws {PubkyError} `InvalidInput` when the URL is malformed or not a grant signin link.
    #[wasm_bindgen(js_name = "parse")]
    pub fn try_from(url: &str) -> JsResult<Self> {
        Ok(Self(
            pubky::deep_links::SigninGrantDeepLink::from_str(url).map_err(|e| {
                PubkyError::new(
                    PubkyErrorName::InvalidInput,
                    format!("Invalid signin grant deep link: {}", e),
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

    /// Shared relay secret, or `undefined` for an HPKE link.
    /// Keep this secret confidential until the flow completes or is abandoned.
    ///
    /// @returns {Uint8Array|undefined}
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Option<Uint8Array> {
        match self.0.params().relay_channel {
            pubky::deep_links::GrantRelayChannel::SharedSecret(secret) => {
                Some(Uint8Array::from(secret.as_ref()))
            }
            pubky::deep_links::GrantRelayChannel::Hpke { .. } => None,
        }
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

    /// Negotiated approval format: `bareGrant` or `signedApprovalV1`.
    #[wasm_bindgen(js_name = "approvalFormat", getter)]
    pub fn approval_format(&self) -> String {
        match self.0.params().approval_format {
            pubky::deep_links::GrantApprovalFormat::BareGrant => "bareGrant",
            pubky::deep_links::GrantApprovalFormat::SignedApprovalV1 => "signedApprovalV1",
        }
        .to_owned()
    }

    /// The 32-byte ephemeral HPKE public key from `epk`, or `undefined`
    /// for a shared-secret link. Its unpadded base64url encoding identifies
    /// the relay channel.
    ///
    /// @returns {Uint8Array|undefined}
    #[wasm_bindgen(js_name = "ephemeralPublicKey", getter)]
    pub fn ephemeral_public_key(&self) -> Option<Uint8Array> {
        match self.0.params().relay_channel {
            pubky::deep_links::GrantRelayChannel::SharedSecret(_) => None,
            pubky::deep_links::GrantRelayChannel::Hpke {
                ephemeral_public_key,
            } => Some(Uint8Array::from(ephemeral_public_key.as_slice())),
        }
    }

    /// Optional x-callback-url metadata carried by this deep link.
    #[wasm_bindgen(js_name = "xCallback", getter)]
    pub fn x_callback(&self) -> JsResult<Ts<XCallbackParams>> {
        serialize_ts(&XCallbackParams::from(self.0.x_callback()))
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
