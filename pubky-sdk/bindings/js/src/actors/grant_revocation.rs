use wasm_bindgen::prelude::*;
use web_sys::AbortSignal;

use crate::js_error::{JsResult, PubkyError, PubkyErrorName};

/// Frozen original authority for one conditional revocation attempt.
/// Never persisted, cloned, refreshed or used to clear local/shared credentials.
#[wasm_bindgen]
pub struct GrantRevocation(Option<pubky::GrantRevocation>);

impl GrantRevocation {
    pub(crate) fn new(operation: pubky::GrantRevocation) -> Self {
        Self(Some(operation))
    }

    fn operation(&self) -> JsResult<&pubky::GrantRevocation> {
        self.0.as_ref().ok_or_else(consumed_error)
    }
}

fn consumed_error() -> PubkyError {
    PubkyError::new(
        PubkyErrorName::ClientStateError,
        "Captured revocation was already consumed",
    )
}

#[wasm_bindgen]
impl GrantRevocation {
    /// Fresh operation identifier bound to the confirmation.
    #[wasm_bindgen(js_name = "operationId", getter)]
    pub fn operation_id(&self) -> JsResult<String> {
        Ok(self.operation()?.binding().operation_id.to_string())
    }
    /// Original grant identifier.
    #[wasm_bindgen(js_name = "grantId", getter)]
    pub fn grant_id(&self) -> JsResult<String> {
        Ok(self.operation()?.binding().grant_id.to_string())
    }
    /// Original owner in z-base-32 encoding.
    #[wasm_bindgen(getter)]
    pub fn pubky(&self) -> JsResult<String> {
        Ok(self.operation()?.binding().pubky.z32())
    }
    /// Original application identifier.
    #[wasm_bindgen(js_name = "clientId", getter)]
    pub fn client_id(&self) -> JsResult<String> {
        Ok(self.operation()?.binding().client_id.to_string())
    }
    /// Original homeserver in z-base-32 encoding.
    #[wasm_bindgen(getter)]
    pub fn homeserver(&self) -> JsResult<String> {
        Ok(self.operation()?.homeserver().z32())
    }

    /// Consume this handle, including on failure or cancellation. A second call
    /// fails. No redirects, refresh, ambient cookies or automatic replay.
    /// Ignoring a Promise does not cancel it: use an AbortSignal. Cancellation
    /// after dispatch or any invalid/missing receipt leaves the outcome unknown.
    /// A valid receipt does not authorize erasing a replacement local session.
    #[wasm_bindgen(unchecked_return_type = "Promise<GrantRevocationReceipt>")]
    pub fn execute(&mut self, signal: Option<AbortSignal>) -> JsResult<js_sys::Promise> {
        // Take synchronously, before scheduling any JS future. Generated consuming
        // async methods have different moved-value errors in debug/release builds.
        let operation = self.0.take().ok_or_else(consumed_error)?;
        #[cfg(target_arch = "wasm32")]
        {
            Ok(wasm_bindgen_futures::future_to_promise(async move {
                operation
                    .execute_with_abort_signal(signal)
                    .await
                    .map(|receipt| JsValue::from(GrantRevocationReceipt(receipt)))
                    .map_err(|error| JsValue::from(revocation_error(error)))
            }))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (operation, signal);
            Err(PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Browser execution requires WASM",
            ))
        }
    }
}

/// Exact affirmative server receipt, validated against the consumed handle.
#[wasm_bindgen]
pub struct GrantRevocationReceipt(pub(crate) pubky::GrantRevocationReceipt);

#[wasm_bindgen]
impl GrantRevocationReceipt {
    /// The protocol's versioned committed disposition.
    #[wasm_bindgen(getter)]
    pub fn disposition(&self) -> String {
        "original_bearer_revoked_v1".into()
    }
    /// Identifier of the acknowledged operation.
    #[wasm_bindgen(js_name = "operationId", getter)]
    pub fn operation_id(&self) -> String {
        self.0.operation_id.to_string()
    }
    /// Original grant identifier.
    #[wasm_bindgen(js_name = "grantId", getter)]
    pub fn grant_id(&self) -> String {
        self.0.grant_id.to_string()
    }
    /// Original owner in z-base-32 encoding.
    #[wasm_bindgen(getter)]
    pub fn pubky(&self) -> String {
        self.0.pubky.z32()
    }
    /// Original application identifier.
    #[wasm_bindgen(js_name = "clientId", getter)]
    pub fn client_id(&self) -> String {
        self.0.client_id.to_string()
    }
    /// Homeserver that acknowledged the commit.
    #[wasm_bindgen(getter)]
    pub fn homeserver(&self) -> String {
        self.0.homeserver.z32()
    }
}

pub(super) fn revocation_error(error: pubky::GrantRevocationError) -> PubkyError {
    let name = match error {
        pubky::GrantRevocationError::InvalidSnapshot => PubkyErrorName::ClientStateError,
        _ => PubkyErrorName::RequestError,
    };
    match error {
        pubky::GrantRevocationError::Unacknowledged {
            status: Some(status),
        } => PubkyError::new_with_status(name, error, status),
        _ => PubkyError::new(name, error),
    }
}
