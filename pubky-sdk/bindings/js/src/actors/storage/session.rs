// js/src/client/storage/session.rs
use js_sys::Uint8Array;
use serde::Serialize;
use tsify::Ts;
use wasm_bindgen::prelude::*;
use web_sys::Response;

use super::stats::ResourceStats;
use super::verified::VerifiedBytes;
use crate::js_error::{JsResult, serialize_ts};

#[wasm_bindgen(typescript_custom_section)]
const TS_PATH: &'static str = r#"export type Path = `/pub/${string}` | `/priv/${string}`;"#;

/// Read/write storage scoped to **your** session (absolute paths: `/pub/...` or `/priv/...`).
#[wasm_bindgen]
pub struct SessionStorage(pub(crate) pubky::SessionStorage);

#[wasm_bindgen]
impl SessionStorage {
    /// List a directory (absolute session path). Returns `pubky://…` URLs.
    ///
    /// @param {Path} path Must end with `/`.
    /// @param {string|null=} cursor Optional suffix or full URL to start **after**.
    /// @param {boolean=} reverse Default `false`.
    /// @param {number=} limit Optional result limit.
    /// @param {boolean=} shallow Default `false`.
    /// @returns {Promise<string[]>}
    #[wasm_bindgen]
    pub async fn list(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
        cursor: Option<String>,
        reverse: Option<bool>,
        limit: Option<u16>,
        shallow: Option<bool>,
    ) -> JsResult<Vec<String>> {
        let builder = self.0.list(path)?;
        super::utils::apply_list_options(builder, cursor, reverse, limit, shallow).await
    }

    /// GET a streaming response for an absolute session path.
    ///
    /// @param {Path} path
    /// @returns {Promise<Response>}
    #[wasm_bindgen]
    pub async fn get(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
    ) -> JsResult<Response> {
        let resp = self.0.get(path).await?;
        super::utils::response_to_web_response(resp)
    }

    /// GET bytes from an absolute session path.
    ///
    /// @param {Path} path
    /// @returns {Promise<Uint8Array>}
    #[wasm_bindgen(js_name = "getBytes")]
    pub async fn get_bytes(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
    ) -> JsResult<Uint8Array> {
        let resp = self.0.get(path).await?;
        let bytes = resp.bytes().await?;
        Ok(Uint8Array::from(bytes.as_ref()))
    }

    /// GET text from an absolute session path.
    ///
    /// @param {Path} path
    /// @returns {Promise<string>}
    #[wasm_bindgen(js_name = "getText")]
    pub async fn get_text(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
    ) -> JsResult<String> {
        let resp = self.0.get(path).await?;
        Ok(resp.text().await?)
    }

    /// GET JSON from an absolute session path.
    ///
    /// @param {Path} path
    /// @returns {Promise<any>}
    #[wasm_bindgen(js_name = "getJson")]
    pub async fn get_json(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
    ) -> JsResult<JsValue> {
        let v: serde_json::Value = self.0.get_json(path).await?;
        let ser = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
        Ok(v.serialize(&ser)?)
    }

    /// Check existence.
    ///
    /// @param {Path} path
    /// @returns {Promise<boolean>}
    #[wasm_bindgen]
    pub async fn exists(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
    ) -> JsResult<bool> {
        Ok(self.0.exists(path).await?)
    }

    /// Get metadata for an absolute, session-scoped path (e.g. `"/pub/app/file.json"`).
    ///
    /// @param {Path} path Absolute path under your user (starts with `/`).
    /// @returns {Promise<ResourceStats|undefined>} `undefined` if the resource does not exist.
    /// @throws {PubkyError} On invalid input or transport/server errors.
    #[wasm_bindgen(js_name = "stats")]
    pub async fn stats(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
    ) -> JsResult<Option<Ts<ResourceStats>>> {
        match self.0.stats(path).await? {
            Some(stats) => Ok(Some(serialize_ts(&ResourceStats::from(stats))?)),
            None => Ok(None),
        }
    }

    /// PUT binary at an absolute session path.
    ///
    /// @param {Path} path
    /// @param {Uint8Array} bytes
    /// @returns {Promise<void>}
    #[wasm_bindgen(js_name = "putBytes")]
    pub async fn put_bytes(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
        body: &[u8],
    ) -> JsResult<()> {
        self.0.put(path, body.to_vec()).await?;
        Ok(())
    }

    /// PUT text at an absolute session path.
    ///
    /// @param {Path} path
    /// @param {string} text
    /// @returns {Promise<void>}
    #[wasm_bindgen(js_name = "putText")]
    pub async fn put_text(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
        body: &str,
    ) -> JsResult<()> {
        self.0.put(path, body.as_bytes().to_vec()).await?;
        Ok(())
    }

    /// PUT JSON at an absolute session path.
    ///
    /// @param {Path} path Absolute path (e.g. `"/pub/app/data.json"`).
    /// @param {any} value JSON-serializable value.
    /// @returns {Promise<void>}
    #[wasm_bindgen(js_name = "putJson")]
    pub async fn put_json(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
        body: JsValue,
    ) -> JsResult<()> {
        let v: serde_json::Value = serde_wasm_bindgen::from_value(body)?;
        self.0.put_json(path, &v).await?;
        Ok(())
    }

    /// Delete a path (file or empty directory).
    ///
    /// @param {Path} path
    /// @returns {Promise<void>}
    #[wasm_bindgen]
    pub async fn delete(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
    ) -> JsResult<()> {
        self.0.delete(path).await?;
        Ok(())
    }

    /// PUT binary only if the stored content still has entity tag `etag`.
    /// Resolves to the entity tag of what was written. Rejects with a
    /// `RequestError` carrying `statusCode: 412` if the content changed.
    ///
    /// @param {Path} path
    /// @param {Uint8Array} body
    /// @param {string} etag Entity tag as reported by `stats`, `getBytesVerified` or a previous write.
    /// @returns {Promise<string>}
    #[wasm_bindgen(js_name = "putBytesIfMatch")]
    pub async fn put_bytes_if_match(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
        body: &[u8],
        etag: &str,
    ) -> JsResult<String> {
        Ok(self.0.put_if_match(path, body.to_vec(), etag).await?)
    }

    /// PUT binary only if nothing is stored at `path` yet. Resolves to the
    /// entity tag of what was written. Rejects with a `RequestError`
    /// carrying `statusCode: 412` if the path already exists.
    ///
    /// @param {Path} path
    /// @param {Uint8Array} body
    /// @returns {Promise<string>}
    #[wasm_bindgen(js_name = "putBytesIfAbsent")]
    pub async fn put_bytes_if_absent(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
        body: &[u8],
    ) -> JsResult<String> {
        Ok(self.0.put_if_absent(path, body.to_vec()).await?)
    }

    /// Delete a path only if the stored content still has entity tag `etag`.
    /// Rejects with a `RequestError` carrying `statusCode: 412` if the
    /// content changed.
    ///
    /// @param {Path} path
    /// @param {string} etag
    /// @returns {Promise<void>}
    #[wasm_bindgen(js_name = "deleteIfMatch")]
    pub async fn delete_if_match(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
        etag: &str,
    ) -> JsResult<()> {
        Ok(self.0.delete_if_match(path, etag).await?)
    }

    /// GET bytes and verify they hash to the entity tag they came with.
    ///
    /// @param {Path} path
    /// @returns {Promise<VerifiedBytes>}
    #[wasm_bindgen(js_name = "getBytesVerified")]
    pub async fn get_bytes_verified(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
    ) -> JsResult<VerifiedBytes> {
        Ok(self.0.get_verified(path).await?.into())
    }
}
