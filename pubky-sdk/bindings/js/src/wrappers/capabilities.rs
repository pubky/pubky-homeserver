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

/// Whether every capability in `wanted` is covered by one in `held`.
///
/// Used by session agents to answer `insufficient-scope` before lending a
/// bearer. Both inputs are capabilities strings.
///
/// @param {string} held Capabilities the session holds.
/// @param {string} wanted Capabilities an app asks for.
/// @returns {boolean}
/// @throws {PubkyError} `{ name: "InvalidInput" }` when either string is malformed.
#[wasm_bindgen(js_name = "capabilitiesCoverAll")]
pub fn capabilities_cover_all(
    #[wasm_bindgen(unchecked_param_type = "Capabilities")] held: &str,
    #[wasm_bindgen(unchecked_param_type = "Capabilities")] wanted: &str,
) -> JsResult<bool> {
    Ok(parse_capabilities(held)?.covers_all(&parse_capabilities(wanted)?))
}
