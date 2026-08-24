//! Cookie-only capability view — type-safe access to cookie-specific operations.
//!
//! [`CookieSessionView`] is obtained via
//! [`PubkySession::as_cookie`](crate::actors::session::core::PubkySession::as_cookie).
//!
//! Available on every target. The view's surface narrows on browser WASM
//! because the runtime cookie jar holds the secret and JavaScript cannot
//! read it (the WHATWG fetch spec hides `Set-Cookie` from clients):
//! [`CookieSessionView::export_secret`] returns `None` in that case. On
//! native and Node.js WASM the SDK owns the secret and `export_secret`
//! always returns `Some`.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use pubky_common::session::CookieSessionRecord;

use super::credential::CookieCredential;
use crate::actors::session::core::PubkySession;

/// Cookie-only operations on a [`PubkySession`].
#[derive(Debug)]
#[deprecated(note = "Use GrantSessionView instead.")]
pub struct CookieSessionView<'a> {
    session: &'a PubkySession,
    credential: &'a CookieCredential,
}

impl PubkySession {
    /// Returns a [`CookieSessionView`] if this session is cookie-backed.
    ///
    /// Cookie-only operations live on the view. grant-backed sessions return
    /// `None`. The view is available on every target — what differs by
    /// runtime is whether the cookie secret is *capturable*: see
    /// [`CookieSessionView::export_secret`].
    #[must_use]
    #[deprecated(note = "Use PubkySession::as_grant instead.")]
    pub fn as_cookie(&self) -> Option<CookieSessionView<'_>> {
        self.try_downcast_credential::<CookieCredential>()
            .map(|c| CookieSessionView::new(self, c))
    }
}

impl<'a> CookieSessionView<'a> {
    pub(crate) const fn new(session: &'a PubkySession, credential: &'a CookieCredential) -> Self {
        Self {
            session,
            credential,
        }
    }

    /// Returns the full cookie session record.
    ///
    /// This gives access to cookie-specific fields like `created_at` and
    /// the binary serialization format that are not available via the
    /// shared
    /// [`PubkySession::info`](crate::actors::session::core::PubkySession::info)
    /// accessor.
    #[must_use]
    #[deprecated(note = "Use GrantSessionView::session_info instead.")]
    pub fn session_info(&self) -> CookieSessionRecord {
        self.credential.cookie_record()
    }

    /// Export session metadata for rehydrating after a tab refresh or process restart.
    ///
    /// The returned string contains **no secrets**; it is a base64 encoding of the
    /// public `SessionInfo`. The caller remains responsible for persisting the
    /// HTTP-only session cookie; `export()` merely captures the metadata needed to
    /// reconstruct a `PubkySession` handle.
    #[must_use]
    #[deprecated(note = "Use GrantSessionView::export_local_secret instead.")]
    pub fn export(&self) -> String {
        let record = self.session_info();
        crate::cross_log!(info, "Exporting session for {}", record.public_key());
        STANDARD.encode(record.serialize())
    }

    /// Export the minimum data needed to restore this session later.
    /// Returns a single compact secret token `<pubkey>:<cookie_secret>`.
    ///
    /// Useful for scripts that need restarting. Helps avoid a new auth
    /// flow from a signer on a script restart.
    ///
    /// Treat the returned String as a **bearer secret**. Do not log it;
    /// store it securely.
    ///
    /// # Returns
    /// - `Some(token)` on native and Node.js WASM (the SDK captured the
    ///   secret from `Set-Cookie`).
    /// - `None` on browser WASM, where `Set-Cookie` is hidden from
    ///   JavaScript by the WHATWG fetch spec — only the browser cookie
    ///   jar holds the value.
    #[must_use]
    #[deprecated(note = "Use GrantSessionView::export_local_secret instead.")]
    pub fn export_secret(&self) -> Option<String> {
        let public_key = self.session.info().public_key().z32();
        let cookie = self.credential.cookie_secret()?;
        crate::cross_log!(info, "Exporting session secret for {}", public_key);
        Some(format!("{public_key}:{cookie}"))
    }

    /// Write the session secret token to disk. Ensures a `.sess` extension.
    /// Native-only — depends on the standard filesystem APIs.
    ///
    /// Behavior:
    /// - If `secret_file_path` already ends with `.sess`, it is used as-is.
    /// - If it has no extension, `.sess` is added.
    /// - If it has a different extension, the filename gains `.sess` (e.g.,
    ///   `foo.txt` -> `foo.sess`).
    ///
    /// On Unix, permissions are set to `0o600`.
    /// # Errors
    /// - Returns [`std::io::Error`] if the file cannot be written or
    ///   permissions cannot be set. On native the secret is always
    ///   present, so this never errors with `NotFound` for that reason.
    #[cfg(not(target_arch = "wasm32"))]
    #[deprecated(
        note = "Use GrantSessionView::export_local_secret and persist that grant secret instead."
    )]
    pub fn write_secret_file<P: AsRef<std::path::Path>>(
        &self,
        secret_file_path: P,
    ) -> std::io::Result<()> {
        let token = self.export_secret().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no cookie secret captured for this session",
            )
        })?;
        let p = secret_file_path.as_ref();

        let target = match p.extension().and_then(|e| e.to_str()) {
            Some("sess") => p.to_path_buf(),
            Some(_) => {
                let mut out = p.to_path_buf();
                let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("session");
                out.set_file_name(format!("{fname}.sess"));
                out
            }
            None => {
                let mut out = p.to_path_buf();
                out.set_extension("sess");
                out
            }
        };

        std::fs::write(&target, token)?;
        crate::cross_log!(
            info,
            "Wrote session secret for {} to {}",
            self.session.info().public_key(),
            target.display()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))?;
        };
        Ok(())
    }
}
