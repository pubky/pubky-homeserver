use std::fmt::Display;

use js_sys::{Error as JsError, Reflect};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use serde_wasm_bindgen::Serializer;
use tsify::Tsify;
use wasm_bindgen::convert::IntoWasmAbi;
use wasm_bindgen::describe::WasmDescribe;
use wasm_bindgen::prelude::*;

use pkarr::errors::PublicKeyError;
use pubky::errors::{BuildError, RequestError};
use pubky_common::auth::Error as AuthTokenError;
use pubky_common::capabilities::{CapabilitiesParseError, CapabilityParseError};
use pubky_common::recovery_file::Error as RecoveryFileError;

/// A convenient `Result` type alias for fallible functions exposed to WebAssembly.
///
/// An `Err` variant will be automatically converted into a structured JavaScript exception
/// that can be caught on the JS side.
pub type JsResult<T> = Result<T, PubkyError>;

// --- TypeScript Documentation & Schema ---

/// A union type of all possible machine-readable codes for the `name` property
/// of a {@link PubkyError}.
///
/// Provides a simplified, actionable set of error categories for developers
/// to handle in their code.
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "PascalCase")]
pub enum PubkyErrorName {
    /// A network or server request failed. Check the network connection or retry.
    RequestError,
    /// The error was caused by invalid user input, such as a malformed URL.
    InvalidInput,
    /// An error occurred during login, signup, or session validation.
    AuthenticationError,
    /// A failure in the underlying Pkarr DHT protocol.
    PkarrError,
    /// An error related to client state, like a corrupt recovery file.
    ClientStateError,
    /// An unexpected or internal error occurred. This may indicate a bug.
    InternalError,
}

impl PubkyErrorName {
    fn as_str(&self) -> &'static str {
        match self {
            PubkyErrorName::RequestError => "RequestError",
            PubkyErrorName::InvalidInput => "InvalidInput",
            PubkyErrorName::AuthenticationError => "AuthenticationError",
            PubkyErrorName::PkarrError => "PkarrError",
            PubkyErrorName::ClientStateError => "ClientStateError",
            PubkyErrorName::InternalError => "InternalError",
        }
    }
}

impl Display for PubkyErrorName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Represents the standard error structure for all exceptions thrown by the Pubky
/// WASM client.
///
/// @property name - A machine-readable error code from {@link PubkyErrorName}. Use this for programmatic error handling.
/// @property message - A human-readable, descriptive error message suitable for logging.
/// @property data - An optional payload containing structured context for an error. For a `RequestError`, this may contain an object with the HTTP status code, e.g., `{ statusCode: 404 }`.
///
/// @example
/// ```typescript
/// try {
///   await client.signup(...);
/// } catch (e) {
///   const error = e as PubkyError;
///   if (
///     error.name === 'RequestError' &&
///     typeof error.data === 'object' &&
///     error.data !== null &&
///     'statusCode' in error.data &&
///     (error.data as { statusCode?: number }).statusCode === 404
///   ) {
///     // Handle not found...
///   }
/// }
/// ```
#[derive(Tsify, Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PubkyError {
    pub name: PubkyErrorName,
    pub message: String,

    /// Optional structured context associated with the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional, type = "unknown")]
    pub data: Option<Value>,
}

// --- Constructors for Ergonomics ---
impl PubkyError {
    /// Creates a new error with a name and message.
    pub fn new<T: Display>(name: PubkyErrorName, message: T) -> Self {
        Self {
            name,
            message: message.to_string(),
            data: None,
        }
    }

    /// Creates a new error with a name, message, and structured data payload.
    pub fn new_with_status<T: Display>(name: PubkyErrorName, message: T, status: u16) -> Self {
        Self::new(name, message).with_status(status)
    }

    /// Attach structured context to this error.
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Attach an HTTP status code payload to this error's structured data.
    pub fn with_status(mut self, status: u16) -> Self {
        // If there is already data, try to merge the status code alongside the existing payload.
        self.data = match self.data.take() {
            Some(Value::Object(mut map)) => {
                map.insert("statusCode".to_string(), json!(status));
                Some(Value::Object(map))
            }
            Some(other) => Some(json!({
                "statusCode": status,
                "details": other,
            })),
            None => Some(json!({ "statusCode": status })),
        };
        self
    }
}

#[wasm_bindgen(typescript_custom_section)]
const TS_PUBKY_ERROR: &str = r#"/**
 * Represents the standard error structure for all exceptions thrown by the Pubky
 * WASM client.
 *
 * @property name - A machine-readable error code from {@link PubkyErrorName}. Use this for programmatic error handling.
 * @property message - A human-readable, descriptive error message suitable for logging.
 * @property data - An optional payload containing structured context for an error. For a `RequestError`, this may contain an object with the HTTP status code, e.g., `{ statusCode: 404 }`.
 *
 * @example
 * ```typescript
 * try {
 *   await client.signup(...);
 * } catch (e) {
 *   const error = e as PubkyError;
 *   if (
 *     error.name === "RequestError" &&
 *     typeof error.data === "object" &&
 *     error.data !== null &&
 *     "statusCode" in error.data &&
 *     (error.data as { statusCode?: number }).statusCode === 404
 *   ) {
 *     // Handle not found...
 *   }
 * }
 * ```
 */
export interface PubkyError extends Error {
  name: PubkyErrorName;
  message: string;
  data?: unknown;
}"#;

// --- Rust-to-JavaScript pubky::Error Conversion Pipeline ---

/// Converts a native `pubky::Error` into a `PubkyError`.
impl From<pubky::Error> for PubkyError {
    fn from(err: pubky::Error) -> Self {
        let name = match &err {
            pubky::Error::Request(_) => PubkyErrorName::RequestError,
            pubky::Error::Parse(_) => PubkyErrorName::InvalidInput,
            pubky::Error::Authentication(_) => PubkyErrorName::AuthenticationError,
            pubky::Error::Pkarr(_) => PubkyErrorName::PkarrError,
            pubky::Error::Build(_) => PubkyErrorName::InternalError,
        };

        // If this was a server error, attach status_code; else leave it None.
        if let pubky::Error::Request(RequestError::Server { status, .. }) = &err {
            return Self::new_with_status(name, &err, status.as_u16());
        }
        Self::new(name, err)
    }
}

/// Converts a `pubky::BuildError` into a `PubkyError`.
impl From<BuildError> for PubkyError {
    fn from(err: BuildError) -> Self {
        Self::new(PubkyErrorName::InternalError, err)
    }
}

/// Converts a `pubky_common::recovery_file::Error` into a `PubkyError`.
impl From<RecoveryFileError> for PubkyError {
    fn from(err: RecoveryFileError) -> Self {
        Self::new(PubkyErrorName::ClientStateError, err)
    }
}

/// Converts a capability parsing error into a `PubkyError`.
impl From<CapabilityParseError> for PubkyError {
    fn from(err: CapabilityParseError) -> Self {
        Self::new(PubkyErrorName::InvalidInput, err.to_string())
    }
}

/// Converts a capability-list parsing error into a `PubkyError`.
impl From<CapabilitiesParseError> for PubkyError {
    fn from(error: CapabilitiesParseError) -> Self {
        let data = json!({ "invalidEntries": [error.entry.clone()] });

        Self::new(PubkyErrorName::InvalidInput, error).with_data(data)
    }
}

/// Converts an AuthToken parsing/verification error into a `PubkyError`.
impl From<AuthTokenError> for PubkyError {
    fn from(err: AuthTokenError) -> Self {
        // Treat any token parse/verify failure as an authentication failure.
        // (No HTTP status here; it's a local verification error.)
        PubkyError::new(PubkyErrorName::AuthenticationError, err.to_string())
    }
}

/// Converts a `url::ParseError` into a `PubkyError`.
impl From<url::ParseError> for PubkyError {
    fn from(err: url::ParseError) -> Self {
        Self::new(PubkyErrorName::InvalidInput, err)
    }
}

/// Converts a `pkarr::PublicKeyError` into a `PubkyError`.
impl From<PublicKeyError> for PubkyError {
    fn from(err: PublicKeyError) -> Self {
        Self::new(PubkyErrorName::InvalidInput, err)
    }
}

/// Converts a `serde_wasm_bindgen::Error` (JS <-> Rust value (de)serialization) into `PubkyError`.
impl From<serde_wasm_bindgen::Error> for PubkyError {
    fn from(err: serde_wasm_bindgen::Error) -> Self {
        // Treat bad JS values / schema mismatches as invalid input.
        PubkyError::new(PubkyErrorName::InvalidInput, err)
    }
}

/// Converts a `reqwest::Error` into a `PubkyError`.
impl From<reqwest::Error> for PubkyError {
    fn from(err: reqwest::Error) -> Self {
        // Try to propagate status when present
        if let Some(status) = err.status() {
            PubkyError::new_with_status(
                PubkyErrorName::RequestError,
                err.to_string(),
                status.as_u16(),
            )
        } else {
            PubkyError::new(PubkyErrorName::RequestError, err.to_string())
        }
    }
}

/// Converts a generic `JsValue` error into a `PubkyError`.
impl From<JsValue> for PubkyError {
    fn from(err: JsValue) -> Self {
        let message = err
            .as_string()
            .unwrap_or_else(|| "An unknown JavaScript error occurred.".to_string());
        Self::new(PubkyErrorName::InternalError, message)
    }
}

impl From<PubkyError> for JsValue {
    fn from(err: PubkyError) -> Self {
        let js_error = JsError::new(&err.message);
        js_error.set_name(err.name.as_str());

        let value: JsValue = js_error.into();
        let _ = Reflect::set(
            &value,
            &JsValue::from_str("name"),
            &JsValue::from_str(err.name.as_str()),
        );
        if let Some(data) = err.data {
            let data_js = data
                .serialize(&Serializer::new().serialize_maps_as_objects(true))
                .unwrap_or(JsValue::UNDEFINED);
            let _ = Reflect::set(&value, &JsValue::from_str("data"), &data_js);
        }

        value
    }
}

impl IntoWasmAbi for PubkyError {
    type Abi = <JsValue as IntoWasmAbi>::Abi;

    fn into_abi(self) -> Self::Abi {
        JsValue::from(self).into_abi()
    }
}

impl WasmDescribe for PubkyError {
    fn describe() {
        JsValue::describe();
    }
}
