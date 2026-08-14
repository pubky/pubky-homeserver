use serde::{Deserialize, Serialize};
use tsify::Tsify;

/// Optional x-callback-url metadata carried by a Pubky deep link.
///
/// Callback destinations are untrusted navigation hints. Authentication still
/// completes through the encrypted relay.
#[derive(Tsify, Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct XCallbackParams {
    /// Human-readable name of the requesting application.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[tsify(optional, type = "string | null")]
    pub(crate) x_source: Option<String>,
    /// Destination to open after successful completion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[tsify(optional, type = "string | null")]
    pub(crate) x_success: Option<String>,
    /// Destination to open after an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[tsify(optional, type = "string | null")]
    pub(crate) x_error: Option<String>,
    /// Destination to open after user cancellation or timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[tsify(optional, type = "string | null")]
    pub(crate) x_cancel: Option<String>,
}

impl From<XCallbackParams> for pubky::deep_links::XCallbackParams {
    fn from(value: XCallbackParams) -> Self {
        Self {
            x_source: value.x_source,
            x_success: value.x_success,
            x_error: value.x_error,
            x_cancel: value.x_cancel,
        }
    }
}

impl From<&pubky::deep_links::XCallbackParams> for XCallbackParams {
    fn from(value: &pubky::deep_links::XCallbackParams) -> Self {
        Self {
            x_source: value.x_source.clone(),
            x_success: value.x_success.clone(),
            x_error: value.x_error.clone(),
            x_cancel: value.x_cancel.clone(),
        }
    }
}
