//! Unified error types for the `pubky` crate.
//!
//! This module centralizes all failures that can occur while using the SDK and
//! provides a single top-level [`enum@Error`] enum plus the convenient [`Result`] alias.
//! Errors from lower layers (`reqwest`, `pkarr`, `pubky_common`, URL parsing) are
//! mapped into structured variants so callers can handle them precisely.

use thiserror::Error;

// --- Build-Time Error ---

/// Errors that can occur while building a [`crate::PubkyHttpClient`].
#[derive(Debug, Error)]
pub enum BuildError {
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

/// Transport and server-side HTTP errors.
#[derive(Debug, Error)]
pub enum RequestError {
    /// Network/protocol failure from reqwest (timeouts, TLS, I/O, etc.).
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// The server returned a non-success status. Includes status and body message.
    #[error("Server responded with an error: {status} - {message}")]
    Server {
        /// The HTTP status code returned by the server.
        status: reqwest::StatusCode,
        /// Short description or the server response body captured for context.
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
