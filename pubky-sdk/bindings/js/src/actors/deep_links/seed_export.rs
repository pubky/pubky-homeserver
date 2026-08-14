use std::str::FromStr;

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use crate::js_error::{JsResult, PubkyError, PubkyErrorName};

use super::XCallbackParams;

#[wasm_bindgen]
pub struct SeedExportDeepLink(pubky::deep_links::SeedExportDeepLink);

#[wasm_bindgen]
impl SeedExportDeepLink {
    #[wasm_bindgen(js_name = "parse")]
    pub fn try_from(url: &str) -> JsResult<Self> {
        Ok(Self(
            pubky::deep_links::SeedExportDeepLink::from_str(url).map_err(|e| {
                PubkyError::new(
                    PubkyErrorName::InvalidInput,
                    format!("Invalid seed export deep link: {}", e),
                )
            })?,
        ))
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Uint8Array {
        Uint8Array::from(self.0.params().secret.as_ref())
    }

    /// Optional x-callback-url metadata carried by this deep link.
    #[wasm_bindgen(js_name = "xCallback", getter)]
    pub fn x_callback(&self) -> XCallbackParams {
        self.0.x_callback().into()
    }

    #[allow(
        clippy::inherent_to_string,
        reason = "Display trait doesn't work with wasm-bindgen"
    )]
    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}
