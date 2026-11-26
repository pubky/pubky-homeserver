// js/src/wrappers/session.rs
#![allow(
    deprecated,
    reason = "JS bindings preserve deprecated cookie compatibility APIs"
)]

use wasm_bindgen::prelude::*;

use super::{cookie_session::CookieSession, grant_session::GrantSession, storage::SessionStorage};
use crate::client::constructor::Client;
use crate::js_error::{JsResult, PubkyError, PubkyErrorName};
use crate::wrappers::session_info::SessionInfo;

/// An authenticated context “as the user”.
/// - Use `storage` for reads/writes (absolute paths like `/pub/app/file.txt`)
/// - Storage requests use the session's grant or restored legacy cookie.
#[wasm_bindgen]
pub struct Session(pub(crate) pubky::PubkySession);

#[wasm_bindgen]
impl Session {
    /// Retrieve immutable info about this session (user & capabilities).
    ///
    /// @returns {SessionInfo}
    #[wasm_bindgen(getter)]
    pub fn info(&self) -> SessionInfo {
        SessionInfo(self.0.info().clone())
    }

    /// Access the session-scoped storage API (read/write).
    ///
    /// @returns {SessionStorage}
    #[wasm_bindgen(getter)]
    pub fn storage(&self) -> SessionStorage {
        SessionStorage(pubky::SessionStorage::new(&self.0))
    }

    /// Grant-only management view for grant-backed sessions.
    ///
    /// Cookie-backed sessions return `undefined`.
    ///
    /// @returns {GrantSession|undefined}
    #[wasm_bindgen(getter)]
    pub fn grant(&self) -> Option<GrantSession> {
        self.0.as_grant().map(|_| GrantSession(self.0.clone()))
    }

    /// Cookie-only view for cookie-backed sessions.
    ///
    /// Grant-backed sessions return `undefined`.
    ///
    /// @returns {CookieSession|undefined}
    /// @deprecated Use `session.grant` and `GrantSession` instead.
    #[wasm_bindgen(getter)]
    pub fn cookie(&self) -> Option<CookieSession> {
        self.0.as_cookie().map(|_| CookieSession(self.0.clone()))
    }

    /// Revoke this session's grant on the homeserver. This signs out every
    /// tab that uses the same grant. For a legacy cookie session, the
    /// homeserver invalidates the session cookie.
    ///
    /// @returns {Promise<void>}
    #[wasm_bindgen]
    pub async fn signout(&self) -> JsResult<()> {
        let callback = match self.0.as_grant() {
            Some(grant)
                if grant.parent_grant().is_some()
                    && grant.export_delegated_restore_state().await.is_some() =>
            {
                Some(grant.session_info().await.client_id)
            }
            _ => None,
        };
        let result = self
            .0
            .clone()
            .signout()
            .await
            .map_err(|(error, _)| PubkyError::from(error));
        let cleanup = match callback {
            Some(callback) => {
                super::redirect_auth_flow::finish_signout(self.0.client(), callback.as_str()).await
            }
            None => Ok(()),
        };
        result.and(cleanup)
    }

    /// Export metadata for a legacy cookie session only. To restore the
    /// snapshot, the browser must still hold the original HTTP-only cookie.
    ///
    /// @returns {string}
    /// A base64 string to store (e.g. in `localStorage`).
    ///
    /// @deprecated For grant sessions in a browser, use
    /// `pubky.browserSessionStore.save(session)`. To export a local grant
    /// session's secret, use `session.exportLocalSecret()`.
    #[wasm_bindgen]
    pub fn export(&self) -> String {
        self.0
            .as_cookie()
            .expect("export() is only valid for cookie sessions")
            .export()
    }

    /// Export the local secret material needed to restore this session.
    ///
    /// For local grant sessions this exports the grant JWS and PoP client secret;
    /// restoring mints a fresh bearer. For legacy cookie sessions this exports the
    /// cookie secret when the SDK owns it. Delegated browser grant sessions cannot
    /// export raw secret material; use `BrowserSessionStore`.
    ///
    /// Treat the returned string as a bearer-equivalent secret until the grant or
    /// cookie session expires or is revoked.
    ///
    /// @returns {Promise<string>}
    /// A secret token that can be passed to `pubky.restoreSession()`.
    #[wasm_bindgen(js_name = "exportLocalSecret")]
    pub async fn export_local_secret(&self) -> JsResult<String> {
        if let Some(grant) = self.0.as_grant() {
            return grant.export_local_secret().await.ok_or_else(|| {
                PubkyError::new(
                    PubkyErrorName::ClientStateError,
                    "Delegated grant sessions cannot export raw secret material. Use BrowserSessionStore.",
                )
            });
        }

        if let Some(cookie) = self.0.as_cookie() {
            return cookie.export_secret().ok_or_else(|| {
                PubkyError::new(
                    PubkyErrorName::ClientStateError,
                    "This cookie session cannot export a secret in the current runtime.",
                )
            });
        }

        Err(PubkyError::new(
            PubkyErrorName::ClientStateError,
            "Unsupported session credential type.",
        ))
    }

    /// Restore a session from an `export()` string.
    ///
    /// The HTTP-only cookie must still be present in the browser; this function does not
    /// read or write any secrets.
    ///
    /// @param {string} exported
    /// A string produced by `session.export()`.
    /// @param {Client=} client
    /// Optional client to reuse transport configuration.
    /// @returns {Promise<Session>}
    ///
    /// @deprecated Use `Pubky.restoreSession(...)` with a grant secret.
    #[wasm_bindgen(js_name = "restore")]
    pub async fn restore(exported: String, client: Option<Client>) -> JsResult<Session> {
        let session = match client {
            Some(c) => pubky::PubkySession::import(&exported, Some(c.0)).await?,
            None => pubky::PubkySession::import(&exported, None).await?,
        };
        Ok(Session(session))
    }
}

impl From<pubky::PubkySession> for Session {
    fn from(s: pubky::PubkySession) -> Self {
        Session(s)
    }
}
