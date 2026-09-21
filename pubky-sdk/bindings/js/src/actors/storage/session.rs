// js/src/client/storage/session.rs
use js_sys::Uint8Array;
use serde::Serialize;
use tsify::Ts;
use wasm_bindgen::prelude::*;
use web_sys::Response;

use super::stats::ResourceStats;
use crate::js_error::{JsResult, serialize_ts};

#[wasm_bindgen(typescript_custom_section)]
const TS_PATH: &'static str = r#"export type Path = `/pub/${string}` | `/priv/${string}`;"#;

/// Read/write storage scoped to **your** session (absolute paths: `/pub/...` or `/priv/...`).
///
/// Storage operations return Promises. SDK failures reject with a {@link PubkyError};
/// inspect `name`, `message`, and `data.statusCode` when present. Invalid resource
/// paths (empty paths, internal `//`, or `.`/`..` segments), transport failures,
/// and non-success HTTP statuses use `RequestError`. HTTP errors include a
/// status code; local path validation and network failures generally do not.
/// URL parsing failures use `InvalidInput`. Session credential preparation or
/// refresh can also fail.
///
/// HTTP errors include authentication or permission failures (401/403) and server
/// failures (5xx). Only {@link SessionStorage.exists} and {@link SessionStorage.stats}
/// treat 404 and 410 as successful missing-resource results. Writes require a valid session with
/// write permission and can fail on file/directory path conflicts (409) or
/// exceeded storage quotas (507).
#[wasm_bindgen]
pub struct SessionStorage(pub(crate) pubky::SessionStorage);

#[wasm_bindgen]
impl SessionStorage {
    /// List a directory (absolute session path).
    ///
    /// @param {Path} path Must end with `/`.
    /// @param {string|null=} cursor Optional last entry URL to start **after**.
    /// @param {boolean=} reverse Default `false`.
    /// @param {number=} limit Optional result limit.
    /// @param {boolean=} shallow Default `false`.
    /// @returns {Promise<string[]>} `pubky://…` entry URLs; an empty array for a successful
    /// page with no entries.
    /// @throws {PubkyError} Rejects for a missing directory (404), invalid path or cursor,
    /// invalid response entries, body-read failures, or shared request failures described
    /// on {@link SessionStorage}.
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
    /// Reading the returned response body can still fail after this resolves.
    ///
    /// @param {Path} path
    /// @returns {Promise<Response>} A response with a successful HTTP status and an unread body.
    /// @throws {PubkyError} Rejects for missing resources (404/410), response-construction
    /// failures, or shared request failures described on {@link SessionStorage}.
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
    /// @returns {Promise<Uint8Array>} The complete response body.
    /// @throws {PubkyError} Rejects for missing resources (404/410), body-read failures, or
    /// shared request failures described on {@link SessionStorage}.
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
    /// @returns {Promise<string>} The complete response body decoded as text.
    /// @throws {PubkyError} Rejects for missing resources (404/410), body-read failures, or
    /// shared request failures described on {@link SessionStorage}.
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
    /// @returns {Promise<any>} The parsed JSON value.
    /// @throws {PubkyError} Rejects for missing resources (404/410), invalid JSON,
    /// body-read or value-conversion failures, or shared request failures described on
    /// {@link SessionStorage}.
    #[wasm_bindgen(js_name = "getJson")]
    pub async fn get_json(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
    ) -> JsResult<JsValue> {
        let v: serde_json::Value = self.0.get_json(path).await?;
        let ser = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
        Ok(v.serialize(&ser)?)
    }

    /// Check existence with a HEAD request.
    ///
    /// @param {Path} path
    /// @returns {Promise<boolean>} `true` on success; `false` only for HTTP 404 Not Found
    /// or 410 Gone.
    /// @throws {PubkyError} Rejects for other non-success statuses (including 401/403 and
    /// 5xx) or shared request failures described on {@link SessionStorage}; these do not
    /// resolve to `false`.
    #[wasm_bindgen]
    pub async fn exists(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
    ) -> JsResult<bool> {
        Ok(self.0.exists(path).await?)
    }

    /// Get metadata for an absolute, session-scoped path (e.g. `"/pub/app/file.json"`).
    ///
    /// On a successful HEAD response, missing headers or metadata values that
    /// cannot be parsed leave the corresponding properties absent.
    ///
    /// @param {Path} path Absolute path under your user (starts with `/`).
    /// @returns {Promise<ResourceStats|undefined>} Metadata on success; `undefined` only
    /// for HTTP 404 Not Found or 410 Gone.
    /// @throws {PubkyError} Rejects for other non-success statuses (including 401/403 and
    /// 5xx) or shared request failures described on {@link SessionStorage}; these do not
    /// resolve to `undefined`.
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

    /// Create or replace a file with binary data at an absolute session path.
    ///
    /// @param {Path} path File path; must not end with `/`.
    /// @param {Uint8Array} body
    /// @returns {Promise<void>} Resolves after the server accepts the write.
    /// @throws {PubkyError} Rejects for directory targets (400), upload failures, or shared
    /// write/request failures described on {@link SessionStorage}.
    #[wasm_bindgen(js_name = "putBytes")]
    pub async fn put_bytes(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
        body: &[u8],
    ) -> JsResult<()> {
        self.0.put(path, body.to_vec()).await?;
        Ok(())
    }

    /// Create or replace a file with text at an absolute session path.
    ///
    /// @param {Path} path File path; must not end with `/`.
    /// @param {string} body
    /// @returns {Promise<void>} Resolves after the server accepts the write.
    /// @throws {PubkyError} Rejects for directory targets (400), upload failures, or shared
    /// write/request failures described on {@link SessionStorage}.
    #[wasm_bindgen(js_name = "putText")]
    pub async fn put_text(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
        body: &str,
    ) -> JsResult<()> {
        self.0.put(path, body.as_bytes().to_vec()).await?;
        Ok(())
    }

    /// Create or replace a file with JSON at an absolute session path.
    ///
    /// @param {Path} path File path (e.g. `"/pub/app/data.json"`); must not end with `/`.
    /// @param {any} body JSON-serializable value.
    /// @returns {Promise<void>} Resolves after the server accepts the write.
    /// @throws {PubkyError} Rejects with `InvalidInput` if the value cannot be converted to
    /// JSON; also rejects for directory targets (400), serialization/upload failures, or
    /// shared write/request failures described on {@link SessionStorage}.
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

    /// Delete a file. Directory targets are unsupported.
    ///
    /// @param {Path} path File path; must not end with `/`.
    /// @returns {Promise<void>} Resolves after the server accepts the deletion.
    /// @throws {PubkyError} Rejects for a missing file (404), directory targets (400), or
    /// shared request failures described on {@link SessionStorage}. Deleting a missing file
    /// does not succeed silently.
    #[wasm_bindgen]
    pub async fn delete(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
    ) -> JsResult<()> {
        self.0.delete(path).await?;
        Ok(())
    }
}
