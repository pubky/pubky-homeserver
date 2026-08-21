#![allow(
    deprecated,
    reason = "JS bindings preserve deprecated cookie compatibility APIs"
)]

use wasm_bindgen::prelude::*;

use crate::js_error::{JsResult, PubkyError, PubkyErrorName};

/// Cookie-only view over a cookie-backed `Session`.
///
/// New applications should use `session.grant` and `GrantSession`.
///
/// @deprecated Use `GrantSession` instead.
#[wasm_bindgen]
pub struct CookieSession(pub(crate) pubky::PubkySession);

#[wasm_bindgen]
impl CookieSession {
    /// Export session metadata for legacy cookie restore.
    ///
    /// The returned string contains no secrets; the browser cookie jar must
    /// still hold the HTTP-only cookie.
    ///
    /// @returns {string}
    /// @deprecated Use `GrantSession.exportLocalSecret()` instead.
    pub fn export(&self) -> JsResult<String> {
        let cookie = self.as_cookie()?;
        Ok(cookie.export())
    }

    /// Export the cookie secret needed to restore this cookie session.
    ///
    /// This is available when the SDK captured the cookie secret, such as in
    /// Node.js. Browser sessions cannot read HTTP-only Set-Cookie values.
    ///
    /// @returns {Promise<string>}
    /// @deprecated Use `GrantSession.exportLocalSecret()` instead.
    #[wasm_bindgen(js_name = "exportSecret")]
    pub async fn export_secret(&self) -> JsResult<String> {
        let cookie = self.as_cookie()?;
        cookie.export_secret().ok_or_else(|| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                "This cookie session cannot export a secret in the current runtime.",
            )
        })
    }

    fn as_cookie(&self) -> JsResult<pubky::CookieSessionView<'_>> {
        self.0.as_cookie().ok_or_else(|| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                "Session is not cookie-backed.",
            )
        })
    }
}
