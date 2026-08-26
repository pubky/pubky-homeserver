// js/src/client/storage/public.rs
use super::stats::ResourceStats;
use js_sys::Uint8Array;
use serde::Serialize;
use tsify::Ts;
use wasm_bindgen::prelude::*;
use web_sys::Response;

use crate::js_error::{JsResult, serialize_ts};

#[wasm_bindgen(typescript_custom_section)]
const TS_ADDRESS: &'static str = r#"export type Address = `pubky://${string}/pub/${string}`;"#;

/// Read-only public storage using Pubky URLs (`"pubky://<user>/pub/..."`).
#[wasm_bindgen]
pub struct PublicStorage(pub(crate) pubky::PublicStorage);

#[wasm_bindgen]
impl PublicStorage {
    /// Construct PublicStorage using global client (mainline relays).
    #[wasm_bindgen(constructor)]
    pub fn new() -> JsResult<PublicStorage> {
        Ok(PublicStorage(pubky::PublicStorage::new()?))
    }

    /// List a directory. Results are `pubky://…` identifier URLs.
    ///
    /// @param {Address} address Addressed directory (must end with `/`).
    /// @param {string|null=} cursor Optional suffix or full URL to start **after**.
    /// @param {boolean=} reverse Default `false`. When `true`, newest/lexicographically-last first.
    /// @param {number=} limit Optional result limit.
    /// @param {boolean=} shallow Default `false`. When `true`, lists only first-level entries.
    /// @returns {Promise<string[]>}
    #[wasm_bindgen]
    pub async fn list(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Address")] address: String,
        cursor: Option<String>,
        reverse: Option<bool>,
        limit: Option<u16>,
        shallow: Option<bool>,
    ) -> JsResult<Vec<String>> {
        let builder = self.0.list(address)?;
        super::utils::apply_list_options(builder, cursor, reverse, limit, shallow).await
    }

    /// Perform a streaming `GET` and expose the raw `Response` object.
    ///
    /// @param {Address} address
    /// @returns {Promise<Response>}
    #[wasm_bindgen]
    pub async fn get(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Address")] address: String,
    ) -> JsResult<Response> {
        let resp = self.0.get(address).await?;
        super::utils::response_to_web_response(resp)
    }

    /// Fetch bytes from an addressed path.
    ///
    /// @param {Address} address
    /// @returns {Promise<Uint8Array>}
    #[wasm_bindgen(js_name = "getBytes")]
    pub async fn get_bytes(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Address")] address: String,
    ) -> JsResult<Uint8Array> {
        let resp = self.0.get(address).await?;
        let bytes = resp.bytes().await?;
        Ok(Uint8Array::from(bytes.as_ref()))
    }

    /// Fetch text from an addressed path as UTF-8 text.
    ///
    /// @param {Address} address
    /// @returns {Promise<string>}
    #[wasm_bindgen(js_name = "getText")]
    pub async fn get_text(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Address")] address: String,
    ) -> JsResult<String> {
        let resp = self.0.get(address).await?;
        Ok(resp.text().await?)
    }

    /// Fetch JSON from an addressed path.
    ///
    /// @param {Address} address `"pubky://<user>/pub/.../file.json"`.
    /// @returns {Promise<any>}
    #[wasm_bindgen(js_name = "getJson")]
    pub async fn get_json(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Address")] address: String,
    ) -> JsResult<JsValue> {
        let v: serde_json::Value = self.0.get_json(address).await?;
        let ser = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
        Ok(v.serialize(&ser)?)
    }

    /// Check if a path exists.
    ///
    /// @param {Address} address
    /// @returns {Promise<boolean>}
    #[wasm_bindgen]
    pub async fn exists(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Address")] address: String,
    ) -> JsResult<bool> {
        Ok(self.0.exists(address).await?)
    }

    /// Get metadata for an address
    ///
    /// @param {Address} address `"pubky://<user>/pub/.../file.json"`.
    /// @returns {Promise<ResourceStats|undefined>} `undefined` if the resource does not exist.
    /// @throws {PubkyError} On invalid input or transport/server errors.
    #[wasm_bindgen(js_name = "stats")]
    pub async fn stats(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Address")] address: String,
    ) -> JsResult<Option<Ts<ResourceStats>>> {
        match self.0.stats(address).await? {
            Some(stats) => Ok(Some(serialize_ts(&ResourceStats::from(stats))?)),
            None => Ok(None),
        }
    }
}
