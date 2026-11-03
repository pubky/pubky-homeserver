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
/// const resource = PubkyResource.fromPubkyUrl("pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/example.txt");
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
    /// - `pubky<public_key>/<path>` (identifier form)
    ///
    /// Paths are decoded filenames; percent signs are literal.
    /// Use `fromPubkyUrl()` for encoded URLs from listings or events.
    ///
    /// @param {string} value - The resource string to parse
    /// @returns {PubkyResource} - The parsed resource
    /// @throws {Error} - If the string is not a valid pubky resource
    #[wasm_bindgen]
    pub fn parse(value: String) -> JsResult<PubkyResource> {
        let native: NativePubkyResource = value.parse()?;
        Ok(PubkyResource(native))
    }

    /// Parse an encoded `pubky://` URL, decoding its path exactly once.
    /// Unlike `parse()`, this reverses `toPubkyUrl()`.
    ///
    /// @throws {Error} If the URL or decoded path is invalid.
    #[wasm_bindgen(js_name = "fromPubkyUrl")]
    pub fn from_pubky_url(value: String) -> JsResult<PubkyResource> {
        Ok(PubkyResource(NativePubkyResource::from_pubky_url(&value)?))
    }

    /// Get the owner's public key.
    #[wasm_bindgen(getter)]
    pub fn owner(&self) -> PublicKey {
        PublicKey::from(self.0.owner.clone())
    }

    /// Get the percent-encoded absolute path (e.g., "/pub/example.txt").
    #[wasm_bindgen(getter)]
    pub fn path(&self) -> String {
        self.0.path.to_string()
    }

    /// Render as `pubky://<owner>/<path>` (deep-link/URL form).
    #[wasm_bindgen(js_name = "toPubkyUrl")]
    pub fn to_pubky_url(&self) -> String {
        self.0.to_pubky_url()
    }

    /// Render as `pubky<owner>/<path>` (identifier form).
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

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn encoded_resource_round_trip() {
        let owner = "o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo";
        let path = "/pub/a%20b%2520%23%C3%BC.txt";
        let url = format!("pubky://{owner}{path}");
        let resource = PubkyResource::from_pubky_url(url.clone()).unwrap();
        assert_eq!(resource.path(), path);
        assert_eq!(resource.to_pubky_url(), url);
        let reparsed = PubkyResource::from_pubky_url(resource.to_pubky_url()).unwrap();
        assert_eq!(reparsed.to_pubky_url(), url);
        // Public-storage string inputs retain their decoded-filename semantics.
        let address = String::from(js_sys::decode_uri_component(&url).unwrap());
        assert_eq!(PubkyResource::parse(address).unwrap().to_pubky_url(), url);
    }

    #[wasm_bindgen_test]
    fn parse_keeps_percent_escapes_literal() {
        let owner = "o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo";
        for prefix in [format!("pubky://{owner}"), format!("pubky{owner}")] {
            let resource = PubkyResource::parse(format!("{prefix}/pub/a%20b.txt")).unwrap();
            assert_eq!(resource.path(), "/pub/a%2520b.txt");
        }
    }
}
