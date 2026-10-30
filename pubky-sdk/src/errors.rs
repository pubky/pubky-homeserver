//! Unified error types for the `pubky` crate.
//!
//! This module centralizes all failures that can occur while using the SDK and
//! provides a single top-level [`enum@Error`] enum plus the convenient [`Result`] alias.
//! Errors from lower layers (`reqwest`, `pkarr`, `pubky_common`, URL parsing) are
//! mapped into structured variants so callers can handle them precisely.

use thiserror::Error;

// --- Client Configuration and Build Errors ---

/// Errors that can occur while configuring or building a [`crate::PubkyHttpClient`].
#[derive(Debug, Error)]
pub enum BuildError {
    /// A supplied root certificate bundle contained no certificates.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("Root certificate bundle contained no certificates")]
    EmptyRootCertificates,

    /// A supplied root certificate bundle contains invalid PEM.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("Failed to parse root certificate PEM: {0}")]
    RootCertificatePem(#[from] rustls::pki_types::pem::Error),

    /// A supplied root certificate cannot be used as a trust anchor.
    #[cfg(not(target_arch = "wasm32"))]
    #[error("Invalid root certificate: {0}")]
    RootCertificate(#[from] rustls::Error),

    /// Failed to construct the underlying pkarr client (DHT/relay configuration).
    #[error("Failed to build the Pkarr client: {0}")]
    Pkarr(#[from] pkarr::errors::BuildError),

    /// Failed to build the HTTP client (reqwest configuration).
    #[error("Failed to build the HTTP client: {0}")]
    Http(#[from] reqwest::Error),
}

// --- The Main Operational Error Enum ---

/// The crate’s top-level error type.
///
/// It groups failures into high-level categories:
/// - [`Error::Request`] — HTTP transport/server/validation issues
/// - [`Error::CredentialRefresh`] — automatic grant credential refresh failed
/// - [`Error::Pkarr`] — PKARR/DHT resolution and publishing issues
/// - [`Error::Parse`] — URL parsing failures
/// - [`Error::Authentication`] — auth/session/token/crypto issues
/// - [`Error::Build`] — construction of the client failed
///
/// Most lower-level errors automatically convert into this enum via `From`.
#[derive(Debug, Error)]
pub enum Error {
    /// HTTP request/response failed (transport, server, validation, JSON).
    #[error("Request failed: {0}")]
    Request(#[from] RequestError),

    /// Automatic grant credential refresh failed while preparing or retrying a request.
    #[error("Credential refresh failed: {0}")]
    CredentialRefresh(#[from] CredentialRefreshError),

    /// PKARR/DHT operation failed.
    #[error("Pkarr operation failed: {0}")]
    Pkarr(#[from] PkarrError),

    /// URL parsing failed while preparing a request or path.
    #[error("Failed to parse URL: {0}")]
    Parse(#[from] url::ParseError),

    /// Authentication flow failed (token, session, crypto, or validation).
    #[error("Authentication error: {0}")]
    Authentication(#[from] AuthError),

    /// Building the client failed (reqwest or pkarr configuration).
    #[error("Client build failed: {0}")]
    Build(#[from] BuildError),
}

/// Secret-safe provenance for a failed grant credential refresh request.
///
/// This deliberately omits request URLs, response bodies, grants, proofs, and
/// bearer values from both [`std::fmt::Display`] and [`std::fmt::Debug`]. A
/// request status is retained when the refresh server returned one.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CredentialRefreshError {
    /// The refresh HTTP request failed. `status` is `None` for transport failures.
    #[error("Grant credential refresh request failed")]
    Request {
        /// HTTP status returned by the refresh endpoint, when available.
        status: Option<reqwest::StatusCode>,
    },
}

// --- Pkarr Operational Errors ---

/// Runtime errors produced while resolving or publishing PKARR records.
#[derive(Debug, Error)]
pub enum PkarrError {
    /// Low-level DNS encoding/decoding failure.
    #[error("DNS operation failed: {0}")]
    Dns(#[from] pkarr::dns::SimpleDnsError),

    /// Failed to construct or sign a PKARR DNS packet locally.
    #[error("Failed to build or sign DNS packet: {0}")]
    SignPacket(#[from] pkarr::errors::SignedPacketBuildError),

    /// DHT publish operation failed (often transient).
    #[error("Failed to publish record to the DHT: {0}")]
    Publish(#[from] pkarr::errors::PublishError),

    /// DHT resolution failed (often transient).
    #[error("Failed to resolve the DHT record: {0}")]
    Resolve(#[from] pkarr::errors::ResolveError),

    /// Record was present but malformed or missing required fields.
    #[error("Pkarr record is malformed or missing required data: {0}")]
    InvalidRecord(String),
}

impl PkarrError {
    /// Returns true if the error is from a DHT operation that might succeed by simply retrying.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Publish(_) | Self::Resolve(_))
    }
}

// --- Consolidated Authentication Error ---

/// Errors originating from authentication flows (sessions, tokens, crypto).
#[derive(Debug, Error)]
pub enum AuthError {
    /// Cookie session record (de)serialization or validation failed.
    #[error("Cookie session record handling failed: {0}")]
    CookieSessionRecord(#[from] pubky_common::session::Error),

    /// Auth token failed signature verification or was otherwise invalid.
    #[error("Token verification failed: {0}")]
    VerificationFailed(#[from] pubky_common::auth::Error),

    /// Failure to decrypt/verify an encrypted auth payload.
    #[error("Cryptography error: {0}")]
    DecryptError(#[from] pubky_common::crypto::DecryptError),

    /// Caller or input validation error (e.g., missing parameter, bad URL).
    #[error("General authentication error: {0}")]
    Validation(String),

    /// The auth/relay request expired or was canceled before completion.
    #[error("The provided auth request has expired or was cancelled.")]
    RequestExpired,
}

// --- Consolidated Request Error ---

/// A request failure category without URLs, response bodies or credentials.
///
/// Categories describe the observed failure, not whether retrying is safe. A
/// timeout or connection failure does not prove that a write was not committed.
/// Browser transports may expose less detail and return [`Self::Other`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RequestErrorKind {
    /// The server answered with a status outside the 2xx range.
    Http {
        /// The received HTTP response status code, always within `100..=999`
        /// (the range the HTTP status parser accepts; codes above 599 are
        /// non-standard but possible).
        status: u16,
    },
    /// A transport deadline expired, including during response-body consumption.
    Timeout,
    /// The native transport identified a connection failure, including TLS setup.
    Connection,
    /// Sending or receiving an HTTP body failed; the transport does not say why.
    /// Response reads report their failures as [`Self::Decode`], so in practice
    /// this covers request-body (upload) failures.
    Body,
    /// Response decoding failed, including incomplete HTTP framing. This does
    /// not establish that the stored application payload is corrupt.
    Decode,
    /// The request could not be constructed or its arguments were invalid.
    InvalidRequest,
    /// No more specific category is available from the transport.
    Other,
}

impl RequestErrorKind {
    /// Classifies a transport error without retaining its potentially sensitive context.
    ///
    /// Timeout takes precedence when the transport also identifies a connection
    /// or body failure. reqwest's kind records where the failure was noticed,
    /// while the timeout is the underlying cause in the error's source chain; a
    /// response body that stalls past the deadline would otherwise be reported
    /// as [`Self::Decode`]. Browser errors are not parsed to guess native causes.
    pub fn from_transport(error: &reqwest::Error) -> Self {
        if error.is_timeout() {
            return Self::Timeout;
        }
        if let Some(status) = error.status() {
            return Self::Http {
                status: status.as_u16(),
            };
        }
        #[cfg(not(target_arch = "wasm32"))]
        if error.is_connect() {
            return Self::Connection;
        }
        if error.is_body() {
            Self::Body
        } else if error.is_decode() {
            Self::Decode
        } else if error.is_builder() {
            Self::InvalidRequest
        } else {
            Self::Other
        }
    }
}

/// Transport and server-side HTTP errors.
#[derive(Debug, Error)]
pub enum RequestError {
    /// Network/protocol failure from reqwest (timeouts, TLS, I/O, etc.).
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// The server returned a status the SDK does not accept as success (anything
    /// other than 200, 201 or 204). Includes status and bounded diagnostics.
    #[error("Server responded with an error: {status} - {message}")]
    Server {
        /// The HTTP status code returned by the server.
        status: reqwest::StatusCode,
        /// Status reason or text decoded from the captured response bytes.
        /// The client's error-body limit caps raw bytes; decoded text can be up to
        /// three times larger, plus a truncation marker when the body exceeds the limit.
        message: String,
    },

    /// Caller supplied an invalid URL/path/argument for this API.
    #[error("Invalid request/URI: {message}")]
    Validation {
        /// Human-readable explanation of what was invalid.
        message: String,
    },

    /// JSON decoding failed when parsing a server response.
    #[error("JSON decode error: {message}")]
    DecodeJson {
        /// Error message from the JSON deserializer (with context if available).
        message: String,
    },
}

impl RequestError {
    /// Returns bounded failure metadata without inferring retry safety.
    pub fn kind(&self) -> RequestErrorKind {
        match self {
            Self::Transport(error) => RequestErrorKind::from_transport(error),
            Self::Server { status, .. } => RequestErrorKind::Http {
                status: status.as_u16(),
            },
            Self::Validation { .. } => RequestErrorKind::InvalidRequest,
            Self::DecodeJson { .. } => RequestErrorKind::Decode,
        }
    }
}

/// A specialized `Result` type for `pubky` operations.
pub type Result<T> = std::result::Result<T, Error>;

// Ergonomic "Staircase" From Implementations ---
// A macro to reduce boilerplate for converting base errors into the top-level Error.
macro_rules! impl_from_for_error {
    ($from_type:ty, $to_variant:path) => {
        impl From<$from_type> for Error {
            fn from(err: $from_type) -> Self {
                $to_variant(err.into())
            }
        }
    };
}

// Pkarr Errors
impl_from_for_error!(pkarr::errors::SignedPacketBuildError, Error::Pkarr);
impl_from_for_error!(pkarr::errors::PublishError, Error::Pkarr);
impl_from_for_error!(pkarr::errors::ResolveError, Error::Pkarr);
impl_from_for_error!(pkarr::dns::SimpleDnsError, Error::Pkarr);

// Auth Errors
impl_from_for_error!(pubky_common::session::Error, Error::Authentication);
impl_from_for_error!(pubky_common::auth::Error, Error::Authentication);
impl_from_for_error!(pubky_common::crypto::DecryptError, Error::Authentication);

// Request Errors
impl_from_for_error!(reqwest::Error, Error::Request);

#[cfg(test)]
mod tests {
    use super::{RequestError, RequestErrorKind};

    #[test]
    fn request_categories_do_not_contain_diagnostics() {
        for (error, expected) in [
            (
                RequestError::Server {
                    status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                    message: "private response".into(),
                },
                RequestErrorKind::Http { status: 503 },
            ),
            (
                RequestError::Validation {
                    message: "private path".into(),
                },
                RequestErrorKind::InvalidRequest,
            ),
            (
                RequestError::DecodeJson {
                    message: "private payload".into(),
                },
                RequestErrorKind::Decode,
            ),
        ] {
            assert_eq!(error.kind(), expected);
            assert!(!format!("{:?}", error.kind()).contains("private"));
        }
    }
}
