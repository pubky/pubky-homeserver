use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

/// Bytes read from storage together with the entity tag they were verified
/// against. `etag` equals `contentEtag(bytes)`.
#[wasm_bindgen]
pub struct VerifiedBytes {
    bytes: Vec<u8>,
    etag: String,
}

#[wasm_bindgen]
impl VerifiedBytes {
    /// The content.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Uint8Array {
        Uint8Array::from(self.bytes.as_slice())
    }

    /// The entity tag, without quotes, as `putBytesIfMatch` expects it.
    #[wasm_bindgen(getter)]
    pub fn etag(&self) -> String {
        self.etag.clone()
    }
}

impl From<pubky::VerifiedBody> for VerifiedBytes {
    fn from(body: pubky::VerifiedBody) -> Self {
        Self {
            bytes: body.bytes,
            etag: body.etag,
        }
    }
}

/// The entity tag a homeserver reports for `bytes`: its blake3 hash, base64
/// encoded, without quotes. Use it to verify a body against a reported
/// `ETag`, or with `putBytesIfMatch` against content you have in hand.
///
/// @param {Uint8Array} bytes
/// @returns {string}
#[wasm_bindgen(js_name = "contentEtag")]
pub fn content_etag(bytes: &[u8]) -> String {
    pubky::content_etag(bytes)
}
