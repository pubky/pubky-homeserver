//! WASM wrapper for `pubky::AuthToken`.
//!
//! This type represents a signed, time-bound authentication token produced by a Pubky **Signer**.
use wasm_bindgen::prelude::*;

use crate::js_error::JsResult;
use crate::wrappers::keys::PublicKey;

/// AuthToken: signed, time-bound proof of key ownership.
///
/// ### Binary format
/// `AuthToken` serializes to a canonical binary (postcard) form; use [`AuthToken.toBytes()`] to get a
/// `Uint8Array`, and [`AuthToken.verify()`] to parse + verify on the server.
#[wasm_bindgen]
pub struct AuthToken(pub(crate) pubky::AuthToken);

#[wasm_bindgen]
impl AuthToken {
    // ---------------------------------------------------------------------
    // Constructors / statics
    // ---------------------------------------------------------------------

    /// Parse and verify an `AuthToken` from its canonical bytes.
    ///
    /// - Verifies version, timestamp freshness window, and signature.
    /// - Throws on invalid/expired/unknown version.
    ///
    /// Use this on your server after receiving `Uint8Array` from the client.
    ///
    /// ```js
    /// import { AuthToken } from "@synonymdev/pubky";
    ///
    /// export async function POST(req) {
    ///   const bytes = new Uint8Array(await req.arrayBuffer());
    ///   const token = AuthToken.verify(bytes); // throws on failure
    ///   return new Response(token.publicKey.toString(), { status: 200 });
    /// }
    /// ```
    #[wasm_bindgen(js_name = "verify")]
    pub fn verify_js(bytes: js_sys::Uint8Array) -> JsResult<AuthToken> {
        let vec = bytes.to_vec();
        let token = pubky::AuthToken::verify(&vec)?; // maps to PubkyError on failure
        Ok(AuthToken(token))
    }

    /// Deserialize an `AuthToken` **without** verification.
    ///
    /// Most apps should call [`AuthToken.verify()`]. This is provided for tooling or diagnostics
    /// where you want to inspect the structure first.
    ///
    /// Throws if the bytes cannot be parsed as a valid serialized token.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: js_sys::Uint8Array) -> JsResult<AuthToken> {
        let vec = bytes.to_vec();
        let token = pubky::AuthToken::deserialize(&vec)?; // parse only
        Ok(AuthToken(token))
    }

    // ---------------------------------------------------------------------
    // Instance methods
    // ---------------------------------------------------------------------

    /// Returns the **public key** that authenticated with this token.
    ///
    /// Use `.toString()` on the returned `PublicKey` to get the `pubky<z32>` identifier.
    /// Call `.z32()` when you specifically need the raw z-base32 value (e.g. hostnames).
    ///
    /// @example
    /// const who = token.publicKey.toString();
    #[wasm_bindgen(js_name = "publicKey", getter)]
    pub fn public_key(&self) -> PublicKey {
        // `pubky::PublicKey` implements `Clone`
        PublicKey(self.0.public_key().clone())
    }

    /// Returns the capabilities the signer approved for this token.
    ///
    /// Returns: `string[]`, where each item is the canonical entry `"<scope>:<actions>"`.
    ///
    /// Example entry: `"/pub/my-cool-app/:rw"`
    #[wasm_bindgen(getter)]
    pub fn capabilities(&self) -> Vec<String> {
        self.0
            .capabilities()
            .iter()
            .map(|cap| cap.to_string())
            .collect()
    }

    /// Serialize the token to a `Uint8Array` in its **canonical** (postcard) binary format.
    ///
    /// Use this to send the token to a backend for verification.
    ///
    /// ```js
    /// const bytes = token.toBytes();
    /// await fetch("/api/verify", { method: "POST", body: bytes });
    /// ```
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> js_sys::Uint8Array {
        let bytes = self.0.serialize();
        js_sys::Uint8Array::from(bytes.as_slice())
    }
}
