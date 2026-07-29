//! Cookie session rehydration from exports and secret tokens.
//!
//! - [`import_session`] — browser WASM rehydration from an `export()` string.
//! - [`import_session_secret`] — native/Node.js WASM rehydration from a
//!   `<pubkey>:<cookie_secret>` token.
//! - [`session_from_secret_file`] — native-only file-backed variant of
//!   [`import_session_secret`].

use std::sync::Arc;

#[cfg(target_arch = "wasm32")]
use base64::{Engine as _, engine::general_purpose::STANDARD};
use pubky_common::{capabilities::Capabilities, crypto::PublicKey, session::CookieSessionRecord};

use super::credential::CookieCredential;
use crate::actors::session::core::PubkySession;
use crate::actors::session::credential::SessionCredential;
use crate::errors::{AuthError, RequestError};
use crate::{PubkyHttpClient, Result, cross_log};

/// Restore a session from an `export()` string. No secrets are read or written;
/// the HTTP-only cookie jar must still contain the session cookie.
///
/// # Errors
/// - Returns [`crate::errors::RequestError::Validation`] if the export string is malformed.
/// - Returns [`crate::errors::AuthError::RequestExpired`] if the cookie is missing/expired.
/// - Propagates transport failures while revalidating the session with the homeserver.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn import_session(
    export: &str,
    client: Option<PubkyHttpClient>,
) -> Result<PubkySession> {
    let client = match client {
        Some(c) => c,
        None => PubkyHttpClient::new()?,
    };

    let bytes = STANDARD
        .decode(export)
        .map_err(|e| RequestError::Validation {
            message: format!("invalid session export: {e}"),
        })?;
    let record =
        CookieSessionRecord::deserialize(&bytes).map_err(|e| RequestError::Validation {
            message: format!("invalid session export: {e}"),
        })?;

    let user = record.public_key().clone();
    // Browser WASM cannot read Set-Cookie, so the secret is None and
    // attachment is delegated to the runtime cookie jar.
    let credential: Arc<dyn SessionCredential> =
        Arc::new(CookieCredential::new(user, None, record, None));
    let session = PubkySession::from_credential(client, Arc::clone(&credential));
    // Revalidate updates the credential's internal state automatically.
    session
        .revalidate()
        .await?
        .ok_or(AuthError::RequestExpired)?;
    cross_log!(info, "Rehydrated session");
    Ok(session)
}

/// Restore a session from an `export()` string (unsupported on native targets).
///
/// Use [`import_session_secret`] on native to restore a session using the secret token instead.
///
/// # Errors
/// - Returns [`crate::errors::RequestError::Validation`] because exports are only supported on WASM.
#[cfg(not(target_arch = "wasm32"))]
#[allow(
    clippy::unused_async,
    reason = "keep async signature aligned with WASM build"
)]
pub(crate) async fn import_session(
    _export: &str,
    _client: Option<PubkyHttpClient>,
) -> Result<PubkySession> {
    Err(RequestError::Validation {
        message: "session import is only supported on WASM targets".into(),
    }
    .into())
}

/// Rehydrate a session from a compact secret token `<pubkey>:<cookie_secret>`.
///
/// Useful for scripts that need restarting. Helps avoid a new auth flow
/// from a signer on a script restart.
///
/// Performs a `/session` roundtrip to validate and hydrate the
/// authoritative `SessionInfo`. Returns [`AuthError::RequestExpired`]
/// if the cookie is invalid/expired.
///
/// Available on every target.
/// # Errors
/// - Returns [`crate::errors::RequestError::Validation`] if the token
///   is malformed or contains an invalid public key.
/// - Propagates transport failures while validating the session with
///   the homeserver.
pub(crate) async fn import_session_secret(
    token: &str,
    client: Option<PubkyHttpClient>,
) -> Result<PubkySession> {
    let client = match client {
        Some(c) => c,
        None => PubkyHttpClient::new()?,
    };

    // Cookie may contain `:`, so split at the first colon only.
    let (pk_str, cookie) = token
        .split_once(':')
        .ok_or_else(|| RequestError::Validation {
            message: "invalid secret: expected `<pubkey>:<cookie>`".into(),
        })?;

    let public_key = PublicKey::try_from_z32(pk_str).map_err(|_err| RequestError::Validation {
        message: "invalid public key".into(),
    })?;
    cross_log!(info, "Importing session secret for {}", public_key);

    // Build minimal session; placeholder record will be replaced
    // after validation.
    let placeholder = CookieSessionRecord::new(&public_key, Capabilities::default(), None);
    let cookie_credential = CookieCredential::new(
        public_key.clone(),
        Some(cookie.to_string()),
        placeholder,
        None,
    );
    let credential: Arc<dyn SessionCredential> = Arc::new(cookie_credential);
    let session = PubkySession::from_credential(client, Arc::clone(&credential));

    // Validate cookie and fetch authoritative session data.
    // Revalidate updates the credential's internal state automatically.
    session
        .revalidate()
        .await?
        .ok_or(AuthError::RequestExpired)?;
    cross_log!(
        info,
        "Successfully imported session secret for {}",
        public_key
    );

    Ok(session)
}

/// Restore a session from a secret token stored in a file. Requires a
/// `.sess` extension. Native-only — depends on the standard filesystem
/// APIs.
///
/// Validation:
/// - `.sess` — valid; file is read and parsed.
/// - `.pkarr` — rejected with a clear error message pointing to
///   `Keypair::from_secret_file`.
/// - Any other or missing extension — rejected with a `.sess`-specific
///   error.
/// # Errors
/// - Returns [`crate::errors::RequestError::Validation`] when the file
///   extension is not `.sess`.
/// - Returns [`crate::errors::RequestError::Validation`] if the file
///   cannot be read.
/// - Propagates errors from [`import_session_secret`] when the stored
///   token is invalid or when the session cannot be revalidated.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn session_from_secret_file(
    secret_file_path: &std::path::Path,
    client: Option<PubkyHttpClient>,
) -> Result<PubkySession> {
    match secret_file_path.extension().and_then(|e| e.to_str()) {
        Some("sess") => { /* ok */ }
        Some("pkarr") => {
            return Err(RequestError::Validation {
                message: format!(
                    "refused to load `{}`: `.pkarr` is a keypair secret. \
                     Use `Keypair::from_secret_file` to load keys. \
                     Session secrets must use the `.sess` extension.",
                    secret_file_path.display()
                ),
            }
            .into());
        }
        Some(other) => {
            return Err(RequestError::Validation {
                message: format!(
                    "invalid session secret extension `.{other}` for `{}`; expected `.sess`",
                    secret_file_path.display()
                ),
            }
            .into());
        }
        None => {
            return Err(RequestError::Validation {
                message: format!(
                    "missing extension for `{}`; session secret files must end with `.sess`",
                    secret_file_path.display()
                ),
            }
            .into());
        }
    }

    let token =
        std::fs::read_to_string(secret_file_path).map_err(|e| RequestError::Validation {
            message: format!("failed to read session secret file: {e}"),
        })?;
    cross_log!(
        info,
        "Loading session secret from {}",
        secret_file_path.display()
    );
    import_session_secret(token.trim(), client).await
}
