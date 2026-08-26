use wasm_bindgen::prelude::*;

use crate::js_error::JsResult;
use crate::wrappers::keys::PublicKey;
use pubky::PubkyResource as NativePubkyResource;

/// An addressed resource: a user's public key paired with an absolute path.
///
/// This represents a specific file or directory on a user's homeserver.
///
/// @example
/// ```typescript
/// // Parse from a pubky URL
/// const resource = PubkyResource.parse("pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/example.txt");
/// console.log(resource.owner.z32()); // The user's public key
/// console.log(resource.path);        // "/pub/example.txt"
/// console.log(resource.toPubkyUrl()); // "pubky://o1gg96.../pub/example.txt"
/// ```
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct PubkyResource(pub(crate) NativePubkyResource);

#[wasm_bindgen]
impl PubkyResource {
    /// Parse a pubky resource from a string.
    ///
    /// Accepts:
    /// - `pubky://<public_key>/<path>` (URL form)
    /// - legacy `pubky<public_key>/<path>` (identifier form)
    ///
    /// @param {string} value - The resource string to parse
    /// @returns {PubkyResource} - The parsed resource
    /// @throws {Error} - If the string is not a valid pubky resource
    #[wasm_bindgen]
    pub fn parse(value: String) -> JsResult<PubkyResource> {
        let native: NativePubkyResource = value.parse()?;
        Ok(PubkyResource(native))
    }

    /// Get the owner's public key.
    #[wasm_bindgen(getter)]
    pub fn owner(&self) -> PublicKey {
        PublicKey::from(self.0.owner.clone())
    }

    /// Get the absolute path (e.g., "/pub/example.txt").
    #[wasm_bindgen(getter)]
    pub fn path(&self) -> String {
        self.0.path.to_string()
    }

    /// Render as `pubky://<owner>/<path>` (deep-link/URL form).
    #[wasm_bindgen(js_name = "toPubkyUrl")]
    pub fn to_pubky_url(&self) -> String {
        self.0.to_pubky_url()
    }

    /// Render as `pubky://<owner>/<path>`.
    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string_js(&self) -> String {
        self.0.to_string()
    }
}

impl From<NativePubkyResource> for PubkyResource {
    fn from(value: NativePubkyResource) -> Self {
        PubkyResource(value)
    }
}
