use std::fmt::Display;

use js_sys::{Error as JsError, Reflect};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use serde_wasm_bindgen::Serializer;
use tsify::{Ts, Tsify};
use wasm_bindgen::convert::IntoWasmAbi;
use wasm_bindgen::describe::WasmDescribe;
use wasm_bindgen::prelude::*;

use pkarr::errors::PublicKeyError;
use pubky::errors::{BuildError, RequestErrorKind};
use pubky_common::auth::Error as AuthTokenError;
use pubky_common::capabilities::{CapabilitiesParseError, CapabilityParseError};
use pubky_common::recovery_file::Error as RecoveryFileError;

/// A convenient `Result` type alias for fallible functions exposed to WebAssembly.
///
/// An `Err` variant will be automatically converted into a structured JavaScript exception
/// that can be caught on the JS side.
pub type JsResult<T> = Result<T, PubkyError>;

pub(crate) fn deserialize_ts<T>(value: &Ts<T>) -> JsResult<T>
where
    T: Tsify + DeserializeOwned,
    T::JsType: Clone,
{
    value
        .to_rust()
        .map_err(|error| PubkyError::new(PubkyErrorName::InvalidInput, error))
}

pub(crate) fn serialize_ts<T>(value: &T) -> JsResult<Ts<T>>
where
    T: Tsify + Serialize,
{
    Ts::from_rust(value).map_err(|error| PubkyError::new(PubkyErrorName::InternalError, error))
}

// --- TypeScript Documentation & Schema ---

/// A union type of all possible machine-readable codes for the `name` property
/// of a {@link PubkyError}.
///
/// Provides a simplified, actionable set of error categories for developers
/// to handle in their code.
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum PubkyErrorName {
    /// A request failed. Inspect its reason and status; retry safety is operation-specific.
    RequestError,
    /// A grant credential refresh request failed while preparing or retrying a request.
    CredentialRefreshError,
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
            PubkyErrorName::CredentialRefreshError => "CredentialRefreshError",
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
/// @property data - Optional structured context. For a `RequestError` it is a {@link RequestErrorData}, e.g. `{ reason: "Http", statusCode: 404 }`.
///
/// @example
/// ```typescript
/// try {
///   await client.signup(...);
/// } catch (e) {
///   const error = e as PubkyError;
///   if (error.name === 'RequestError') {
///     const data = error.data as RequestErrorData;
///     if (data.statusCode === 404) {
///       // Handle not found...
///     }
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
    pub(crate) fn request(message: impl Display, kind: RequestErrorKind) -> Self {
        let (reason, status) = match kind {
            RequestErrorKind::Http { status } => ("Http", Some(status)),
            RequestErrorKind::Timeout => ("Timeout", None),
            RequestErrorKind::Connection => ("Connection", None),
            RequestErrorKind::Body => ("Body", None),
            RequestErrorKind::Decode => ("Decode", None),
            RequestErrorKind::InvalidRequest => ("InvalidRequest", None),
            _ => ("Other", None),
        };
        let error =
            Self::new(PubkyErrorName::RequestError, message).with_data(json!({ "reason": reason }));
        match status {
            Some(status) => error.with_status(status),
            None => error,
        }
    }

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
 * @property data - Optional structured context. For a `RequestError` it is a {@link RequestErrorData}, e.g. `{ reason: "Http", statusCode: 404 }`.
 *
 * @example
 * ```typescript
 * try {
 *   await client.signup(...);
 * } catch (e) {
 *   const error = e as PubkyError;
 *   if (error.name === "RequestError") {
 *     const data = error.data as RequestErrorData;
 *     if (data.statusCode === 404) {
 *       // Handle not found...
 *     }
 *   }
 * }
 * ```
 */
export interface PubkyError extends Error {
  name: PubkyErrorName;
  message: string;
  data?: unknown;
}

/** The classified cause of a `RequestError`, carried in `PubkyError.data.reason`. */
export type RequestErrorReason =
  | "Http"
  | "Timeout"
  | "Connection"
  | "Body"
  | "Decode"
  | "InvalidRequest"
  | "Other";

/**
 * `PubkyError.data` for a `RequestError`.
 *
 * `statusCode` is present when `reason` is `"Http"`. A reason describes the
 * failure, not whether retrying is safe.
 */
export interface RequestErrorData {
  reason: RequestErrorReason;
  statusCode?: number;
}"#;

// --- Rust-to-JavaScript pubky::Error Conversion Pipeline ---

/// Converts a native `pubky::Error` into a `PubkyError`.
impl From<pubky::Error> for PubkyError {
    fn from(err: pubky::Error) -> Self {
        let name = match &err {
            pubky::Error::Request(request) => return Self::request(&err, request.kind()),
            pubky::Error::CredentialRefresh(_) => PubkyErrorName::CredentialRefreshError,
            pubky::Error::Parse(_) => PubkyErrorName::InvalidInput,
            pubky::Error::Authentication(_) => PubkyErrorName::AuthenticationError,
            pubky::Error::Pkarr(_) => PubkyErrorName::PkarrError,
            pubky::Error::Build(_) => PubkyErrorName::InternalError,
        };

        // Only errors that carry an HTTP status populate `data.statusCode`.
        if let pubky::Error::CredentialRefresh(pubky::CredentialRefreshError::Request {
            status: Some(status),
        }) = &err
        {
            return Self::new_with_status(name, &err, status.as_u16());
        }
        Self::new(name, err)
    }
}

/// Preserve custom proof errors independently of general auth errors.
impl From<pubky::custom_pop::CustomPopError> for PubkyError {
    fn from(error: pubky::custom_pop::CustomPopError) -> Self {
        use pubky::custom_pop::CustomPopError as Error;
        let reason = match error {
            Error::GrantExpired => "GrantExpired",
            Error::InvalidGrant(_) => "InvalidGrant",
            Error::SigningKeyUnavailable(_) => "SigningKeyUnavailable",
            Error::SigningFailed(_) => "SigningFailed",
            Error::SessionState(source) => return Self::from(*source),
        };
        Self::new(PubkyErrorName::AuthenticationError, error).with_data(json!({ "reason": reason }))
    }
}

/// Preserve verifier failures as machine-readable authentication errors.
impl From<pubky::custom_pop::CustomPopVerificationError> for PubkyError {
    fn from(error: pubky::custom_pop::CustomPopVerificationError) -> Self {
        use pubky::custom_pop::CustomPopVerificationError as Error;
        let reason = match &error {
            Error::MalformedCredential => "MalformedCredential",
            Error::UnsupportedHeader => "UnsupportedHeader",
            Error::InvalidGrantSignature => "InvalidGrantSignature",
            Error::InvalidProofSignature => "InvalidProofSignature",
            Error::InvalidGrant => "InvalidGrant",
            Error::GrantExpired => "GrantExpired",
            Error::GrantNotYetValid => "GrantNotYetValid",
            Error::ProofNotYetValid => "ProofNotYetValid",
            Error::ProofOutsideGrantValidity => "ProofOutsideGrantValidity",
            Error::InvalidClock => "InvalidClock",
            Error::GrantMismatch => "GrantMismatch",
        };
        Self::new(PubkyErrorName::AuthenticationError, error).with_data(json!({ "reason": reason }))
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
        Self::request(&err, RequestErrorKind::from_transport(&err))
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

#[cfg(test)]
mod tests {
    use super::*;
    use pubky::custom_pop::CustomPopError;
    use pubky::errors::RequestError;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn request_metadata_covers_all_categories() {
        for (kind, reason) in [
            (RequestErrorKind::Timeout, "Timeout"),
            (RequestErrorKind::Connection, "Connection"),
            (RequestErrorKind::Body, "Body"),
            (RequestErrorKind::Decode, "Decode"),
            (RequestErrorKind::InvalidRequest, "InvalidRequest"),
            (RequestErrorKind::Other, "Other"),
        ] {
            let error = PubkyError::request("request failed", kind);
            assert_eq!(error.name.as_str(), "RequestError");
            assert_eq!(error.message, "request failed");
            assert_eq!(error.data, Some(json!({ "reason": reason })));
        }
        let source = reqwest::Client::new().get("not a URL").build().unwrap_err();
        let message = source.to_string();
        let error = PubkyError::from(source);
        assert_eq!(error.name.as_str(), "RequestError");
        assert_eq!(error.message, message);
        assert_eq!(error.data, Some(json!({ "reason": "InvalidRequest" })));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn request_errors_preserve_names_status_and_categories() {
        for (error, expected) in [
            (
                RequestError::Server {
                    status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                    message: "unavailable".into(),
                },
                json!({ "reason": "Http", "statusCode": 503 }),
            ),
            (
                RequestError::Validation {
                    message: "invalid path".into(),
                },
                json!({ "reason": "InvalidRequest" }),
            ),
            (
                RequestError::DecodeJson {
                    message: "invalid response".into(),
                },
                json!({ "reason": "Decode" }),
            ),
            (
                RequestError::Transport(
                    reqwest::Client::new().get("not a URL").build().unwrap_err(),
                ),
                json!({ "reason": "InvalidRequest" }),
            ),
        ] {
            let source = pubky::Error::Request(error);
            let message = source.to_string();
            let actual = PubkyError::from(source);
            assert_eq!(actual.name.as_str(), "RequestError");
            assert_eq!(actual.message, message);
            assert_eq!(actual.data, Some(expected.clone()));
            #[cfg(target_arch = "wasm32")]
            {
                let value = JsValue::from(actual);
                let data = Reflect::get(&value, &JsValue::from_str("data")).unwrap();
                let data: Value = serde_wasm_bindgen::from_value(data).unwrap();
                assert_eq!(data, expected);
            }
        }
    }

    #[test]
    fn custom_proof_errors_preserve_javascript_names_and_reasons() {
        for (error, name, reason) in [
            (
                CustomPopError::GrantExpired,
                "AuthenticationError",
                "GrantExpired",
            ),
            (
                CustomPopError::InvalidGrant("binding mismatch".into()),
                "AuthenticationError",
                "InvalidGrant",
            ),
            (
                CustomPopError::SigningKeyUnavailable("deleted".into()),
                "AuthenticationError",
                "SigningKeyUnavailable",
            ),
            (
                CustomPopError::SigningFailed("WebCrypto failure".into()),
                "AuthenticationError",
                "SigningFailed",
            ),
        ] {
            let expected_message = error.to_string();
            let actual = PubkyError::from(error);
            assert_eq!(actual.name.as_str(), name);
            assert_eq!(actual.message, expected_message);
            assert_eq!(actual.data, Some(json!({ "reason": reason })));
        }
    }

    #[test]
    fn custom_proof_session_state_preserves_the_original_error_shape() {
        let source = pubky::errors::AuthError::Validation("Browser session was removed".into());
        let actual = PubkyError::from(CustomPopError::SessionState(Box::new(source.into())));
        assert_eq!(actual.name.as_str(), "AuthenticationError");
        assert_eq!(
            actual.message,
            "Authentication error: General authentication error: Browser session was removed"
        );
        assert_eq!(actual.data, None);
    }

    #[test]
    fn credential_refresh_errors_preserve_provenance_and_status() {
        let server = PubkyError::from(pubky::Error::CredentialRefresh(
            pubky::CredentialRefreshError::Request {
                status: Some(reqwest::StatusCode::SERVICE_UNAVAILABLE),
            },
        ));
        assert_eq!(server.name.as_str(), "CredentialRefreshError");
        assert_eq!(
            server.message,
            "Credential refresh failed: Grant credential refresh request failed"
        );
        assert_eq!(server.data, Some(json!({ "statusCode": 503 })));

        let transport = PubkyError::from(pubky::Error::CredentialRefresh(
            pubky::CredentialRefreshError::Request { status: None },
        ));
        assert_eq!(transport.name.as_str(), "CredentialRefreshError");
        assert_eq!(transport.data, None);
    }
}
