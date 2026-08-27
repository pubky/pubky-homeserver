// js/src/client/storage/session.rs
use js_sys::{Object, Reflect, Uint8Array};
use reqwest::header::HeaderValue;
use serde::Serialize;
use tsify::Ts;
use wasm_bindgen::prelude::*;
use web_sys::Response;

use super::stats::ResourceStats;
use crate::js_error::{JsResult, PubkyError, PubkyErrorName, serialize_ts};

#[wasm_bindgen(typescript_custom_section)]
const TS_PATH: &'static str = r#"export type Path = `/pub/${string}` | `/priv/${string}`;"#;

#[wasm_bindgen(typescript_custom_section)]
const TS_VERSIONED_BYTES: &'static str = r#"export interface VersionedBytes {
  bytes: Uint8Array;
  etag: string;
}"#;

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

    /// GET bytes and the strong `ETag` from the same response.
    ///
    /// Use this for read-modify-write flows so the bytes and version cannot come
    /// from different resource revisions.
    ///
    /// @param {Path} path
    /// @returns {Promise<VersionedBytes>}
    #[wasm_bindgen(js_name = "getBytesWithEtag", unchecked_return_type = "VersionedBytes")]
    pub async fn get_bytes_with_etag(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
    ) -> JsResult<JsValue> {
        let response = self.0.get(path).await?;
        let etag = response_etag(&response)?;
        let bytes = response.bytes().await?;
        let result = Object::new();
        Reflect::set(
            &result,
            &JsValue::from_str("bytes"),
            &Uint8Array::from(bytes.as_ref()),
        )?;
        Reflect::set(
            &result,
            &JsValue::from_str("etag"),
            &JsValue::from_str(&etag),
        )?;
        Ok(result.into())
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

    /// PUT binary only if the current `ETag` matches.
    ///
    /// @param {Path} path
    /// @param {Uint8Array} bytes
    /// @param {string} etag Strong `ETag` returned with the bytes being modified;
    /// weak tags are rejected.
    /// @returns {Promise<string>} The strong `ETag` for the committed resource.
    /// @throws {PubkyError} With status code `412` when the resource changed.
    #[wasm_bindgen(js_name = "putBytesIfMatch")]
    pub async fn put_bytes_if_match(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
        body: &[u8],
        etag: &str,
    ) -> JsResult<String> {
        let response = self
            .0
            .put_if_match(path, body.to_vec(), etag)
            .await
            .map_err(conditional_write_error)?;
        response_etag(&response)
    }

    /// PUT binary only if the resource does not exist.
    ///
    /// @param {Path} path
    /// @param {Uint8Array} bytes
    /// @returns {Promise<string>} The strong `ETag` for the created resource.
    /// @throws {PubkyError} With status code `412` when the resource exists.
    #[wasm_bindgen(js_name = "putBytesIfAbsent")]
    pub async fn put_bytes_if_absent(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Path")] path: String,
        body: &[u8],
    ) -> JsResult<String> {
        let response = self.0.put_if_absent(path, body.to_vec()).await?;
        response_etag(&response)
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
}

fn response_etag(response: &reqwest::Response) -> JsResult<String> {
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .ok_or_else(|| {
            PubkyError::new(
                PubkyErrorName::InternalError,
                "conditional write response is missing an ETag",
            )
        })?;
    strong_response_etag(etag)
}

fn strong_response_etag(etag: &HeaderValue) -> JsResult<String> {
    let raw = etag.as_bytes();
    let opaque = raw
        .strip_prefix(b"\"")
        .and_then(|value| value.strip_suffix(b"\""))
        .filter(|value| {
            value
                .iter()
                .all(|byte| *byte == b'!' || (b'#'..=b'~').contains(byte))
        })
        .ok_or_else(|| {
            PubkyError::new(
                PubkyErrorName::InternalError,
                "conditional write response contains an invalid strong ETag",
            )
        })?;
    String::from_utf8(opaque.to_vec()).map_err(|_| {
        PubkyError::new(
            PubkyErrorName::InternalError,
            "conditional write response contains a non-ASCII ETag",
        )
    })
}

fn conditional_write_error(error: pubky::Error) -> PubkyError {
    match error {
        error @ pubky::Error::Request(pubky::errors::RequestError::Validation { .. }) => {
            PubkyError::new(PubkyErrorName::InvalidInput, error)
        }
        error => error.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strong_response_etag_requires_quoted_ascii_strong_tag() {
        assert_eq!(
            strong_response_etag(&HeaderValue::from_static("\"abc123\"")).unwrap(),
            "abc123"
        );
        for invalid in ["W/\"abc123\"", "abc123", "\"has space\""] {
            strong_response_etag(&HeaderValue::from_static(invalid)).unwrap_err();
        }
    }

    #[test]
    fn test_conditional_validation_maps_to_invalid_input() {
        let error = conditional_write_error(pubky::Error::Request(
            pubky::errors::RequestError::Validation {
                message: "invalid ETag".to_string(),
            },
        ));
        assert!(matches!(error.name, PubkyErrorName::InvalidInput));
    }
}
