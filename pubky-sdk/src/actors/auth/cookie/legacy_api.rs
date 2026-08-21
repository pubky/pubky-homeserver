//! Legacy cookie-session API shim on
//! [`PubkySession`](crate::actors::session::core::PubkySession).
//!
//! Preserves the older convenience methods (`export`, `import`,
//! `import_secret`, `from_secret_file`, `write_secret_file`) that live
//! directly on [`PubkySession`]. This module does not implement cookie
//! mechanics itself — it delegates to [`super::secret`] and
//! [`super::view::CookieSessionView`].

use crate::actors::session::core::PubkySession;
use crate::{PubkyHttpClient, Result};

impl PubkySession {
    /// Export session metadata for rehydrating after a tab refresh or process restart.
    ///
    /// Delegates to [`super::view::CookieSessionView::export`].
    ///
    /// # Panics
    /// Panics if the session is not cookie-backed.
    #[must_use]
    #[deprecated(note = "Use GrantSessionView::export_local_secret instead.")]
    pub fn export(&self) -> String {
        self.as_cookie()
            .expect("export() is only valid for cookie sessions")
            .export()
    }

    /// Restore a session from an `export()` string.
    ///
    /// Delegates to `super::secret::import_session`.
    ///
    /// # Errors
    /// - Returns [`crate::errors::RequestError::Validation`] if the export string is malformed.
    /// - On native, returns an error because exports are only supported on WASM.
    #[deprecated(note = "Use Pubky::restore_session with a grant secret instead.")]
    pub async fn import(export: &str, client: Option<PubkyHttpClient>) -> Result<Self> {
        super::secret::import_session(export, client).await
    }

    /// Rehydrate a session from a compact secret token `<pubkey>:<cookie_secret>`.
    ///
    /// Delegates to `super::secret::import_session_secret`.
    ///
    /// # Errors
    /// - Returns [`crate::errors::RequestError::Validation`] if the token is malformed.
    /// - Propagates transport failures while validating the session.
    #[deprecated(note = "Use Pubky::restore_session with a grant secret instead.")]
    pub async fn import_secret(token: &str, client: Option<PubkyHttpClient>) -> Result<Self> {
        super::secret::import_session_secret(token, client).await
    }

    /// Restore a session from a secret token stored in a file.
    ///
    /// Delegates to `super::secret::session_from_secret_file`.
    ///
    /// # Errors
    /// - Returns [`crate::errors::RequestError::Validation`] when the file extension is not `.sess`.
    /// - Propagates errors from the stored token validation.
    #[cfg(not(target_arch = "wasm32"))]
    #[deprecated(note = "Read the grant secret and pass it to Pubky::restore_session instead.")]
    pub async fn from_secret_file(
        path: &std::path::Path,
        client: Option<PubkyHttpClient>,
    ) -> Result<Self> {
        super::secret::session_from_secret_file(path, client).await
    }

    /// Write the session secret token to disk. Ensures a `.sess` extension.
    ///
    /// Delegates to [`super::view::CookieSessionView::write_secret_file`].
    ///
    /// # Panics
    /// Panics if the session is not cookie-backed.
    ///
    /// # Errors
    /// - Returns [`std::io::Error`] if the file cannot be written or
    ///   permissions cannot be set.
    #[cfg(not(target_arch = "wasm32"))]
    #[deprecated(
        note = "Use GrantSessionView::export_local_secret and persist that grant secret instead."
    )]
    pub fn write_secret_file<P: AsRef<std::path::Path>>(
        &self,
        secret_file_path: P,
    ) -> std::io::Result<()> {
        self.as_cookie()
            .expect("write_secret_file() is only valid for cookie sessions")
            .write_secret_file(secret_file_path)
    }
}
