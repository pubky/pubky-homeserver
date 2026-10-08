use wasm_bindgen::prelude::*;

use crate::js_error::JsResult;
use pubky_common::capabilities::Capabilities;

#[wasm_bindgen(typescript_custom_section)]
const TS_CAPABILITIES: &str = r#"export type CapabilityAction = "r" | "w" | "rw";
export type CapabilityScope = `/${string}`;
export type CapabilityEntry = `${CapabilityScope}:${CapabilityAction}`;
type CapabilitiesTail = `,${CapabilityEntry}${string}`;
export type Capabilities = "" | CapabilityEntry | `${CapabilityEntry}${CapabilitiesTail}`;"#;

pub(crate) fn parse_capabilities(input: &str) -> JsResult<Capabilities> {
    Ok(input.parse::<Capabilities>()?.normalize())
}

/// Validate and normalize a capabilities string.
///
/// - Normalizes action order (`wr` -> `rw`)
/// - Throws `InvalidInput` identifying the first malformed entry.
///
/// @param {string} input
/// @returns {string} Normalized string (same shape as input).
/// @throws {PubkyError} `{ name: "InvalidInput" }` with a helpful message.
/// The error's `data` field is `{ invalidEntries: string[] }` containing the malformed token.
#[wasm_bindgen(js_name = "validateCapabilities")]
pub fn validate_capabilities(input: &str) -> JsResult<String> {
    Ok(parse_capabilities(input)?.to_string())
}
