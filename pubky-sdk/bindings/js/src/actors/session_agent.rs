//! Session agent host: lend one grant session to apps on allowlisted origins.
//!
//! The agent is a page on a dedicated same-site origin (for example
//! `auth.pubky.app`) that owns a grant session through `browserSessionStore`.
//! Apps embed it in an iframe and connect with
//! [`SessionAgentClient`](super::session_agent_client::SessionAgentClient).
//! Only the agent exchanges the grant; apps receive its short-lived bearer and
//! never the grant JWS, grant id or key. The protocol is documented in
//! `docs/sso-agent.md`.
//!
//! The message listener and the per-app ports live in JS, keyed by a `u32`
//! token, as in `browser_session.rs`: core traits require `Send + Sync`, and
//! `JsValue` is neither.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use pubky::{LentBearer, PubkyHttpClient, PubkySession};
use pubky_common::{capabilities::Capabilities, crypto::PublicKey};
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::session::Session;
use super::session_agent_protocol::{
    AgentSessionInfo, AgentState, AgentStatus, PROTOCOL_VERSION, validate_origin,
};
use super::session_store::{BrowserSessionStore, js_store_is_available, stored_session_id};
use crate::client::constructor::Client;
use crate::js_error::{JsResult, PubkyError, PubkyErrorName, js_error_message};

#[wasm_bindgen(inline_js = r#"
const PUBKY_AGENT_HOST_HELLO = "pubky-agent/hello";

function pubkyAgentOriginOf(url) {
  try { return new URL(url).origin; } catch { return null; }
}
const pubkyAgentHosts = new Map();
let nextPubkyAgentHost = 0;

/**
 * Answer hello handshakes from the allowlisted parent frame and route
 * requests to the Rust callbacks. Each agent frame has exactly one parent,
 * so it serves one connection: a new hello replaces the previous one, which
 * also drops the ports of hellos the client gave up on while the agent was
 * still starting.
 */
export function __pubkyAgentListen(version, allowedOrigins, status, bearer, signout, onSessionChange) {
  if (typeof globalThis.addEventListener !== "function") {
    throw new Error("Session agents require a browser window.");
  }
  const allowed = new Set(allowedOrigins);
  let connection = null;

  async function sendStatus(connection) {
    connection.port.postMessage({ type: "status", ...(await status(connection.capabilities)) });
  }
  async function handle(connection, data) {
    const { type, id } = data ?? {};
    try {
      if (type === "bearer") {
        const lent = await bearer(connection.capabilities, data.rejected ?? null);
        connection.port.postMessage({ id, ok: true, bearer: lent });
      } else if (type === "signout") {
        await signout();
        connection.port.postMessage({ id, ok: true });
      } else {
        connection.port.postMessage({ id, ok: false, code: "unsupported-message" });
      }
    } catch (error) {
      connection.port.postMessage({
        id, ok: false, code: error?.code ?? "error", message: error?.message ?? String(error),
      });
    }
  }
  const onHello = (event) => {
    const data = event.data;
    if (!data || data.type !== PUBKY_AGENT_HOST_HELLO) return;
    const port = event.ports?.[0];
    if (!port) return;
    if (event.source !== window.parent || !allowed.has(event.origin)) {
      port.postMessage({ type: "error", code: "origin-not-allowed" });
      port.close();
      return;
    }
    if (data.v !== version) {
      port.postMessage({ type: "error", code: "unsupported-version" });
      port.close();
      return;
    }
    connection?.port.close();
    connection = {
      port,
      capabilities: String(data.capabilities ?? ""),
      // Ring is sent back to this URL after a mobile approval, so only the
      // connecting app's own origin may name it.
      returnUrl: pubkyAgentOriginOf(data.returnUrl) === event.origin ? data.returnUrl : null,
    };
    const current = connection;
    port.onmessage = (message) => handle(current, message.data);
    sendStatus(current);
  };
  const onChange = (event) => onSessionChange(event.detail);
  // Let the app size the frame to the sign-in UI.
  const reportHeight = () => {
    connection?.port.postMessage({ type: "ui", height: document.documentElement.scrollHeight });
  };
  const observer = typeof ResizeObserver === "function" ? new ResizeObserver(reportHeight) : null;
  observer?.observe(document.documentElement);
  addEventListener("message", onHello);
  addEventListener("pubky-session-changed", onChange);

  const token = ++nextPubkyAgentHost;
  pubkyAgentHosts.set(token, {
    broadcast: () => (connection ? sendStatus(connection) : Promise.resolve()),
    returnUrl: () => connection?.returnUrl ?? undefined,
    close() {
      removeEventListener("message", onHello);
      removeEventListener("pubky-session-changed", onChange);
      observer?.disconnect();
      connection?.port.close();
      connection = null;
      pubkyAgentHosts.delete(token);
    },
  });
  return token;
}
export function __pubkyAgentBroadcast(token) { return pubkyAgentHosts.get(token)?.broadcast() ?? Promise.resolve(); }
export function __pubkyAgentReturnUrl(token) { return pubkyAgentHosts.get(token)?.returnUrl(); }
export function __pubkyAgentHostClose(token) { pubkyAgentHosts.get(token)?.close(); }
"#)]
extern "C" {
    #[wasm_bindgen(js_name = __pubkyAgentListen, catch)]
    fn js_agent_listen(
        version: u32,
        allowed_origins: js_sys::Array,
        status: &JsValue,
        bearer: &JsValue,
        signout: &JsValue,
        on_session_change: &JsValue,
    ) -> Result<u32, JsValue>;
    #[wasm_bindgen(js_name = __pubkyAgentBroadcast)]
    fn js_agent_broadcast(token: u32) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyAgentReturnUrl)]
    fn js_agent_return_url(token: u32) -> Option<String>;
    #[wasm_bindgen(js_name = __pubkyAgentHostClose)]
    fn js_agent_host_close(token: u32);
}

/// Options for `SessionAgent.listen`.
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SessionAgentOptions {
    /// Exact origins that may use this agent, e.g. `["https://pubky.app"]`.
    pub(crate) allowed_origins: Vec<String>,
    /// The shared scope: a served session must stay within it and never be root.
    #[tsify(type = "Capabilities")]
    pub(crate) capabilities: String,
}

/// Error reply sent to an app, as `{ code, message }`.
#[derive(Serialize)]
struct AgentFailure {
    code: &'static str,
    message: String,
}

impl AgentFailure {
    fn signed_out() -> Self {
        Self::new("signed-out", "Nobody is signed in on the session agent.")
    }
    fn insufficient_scope() -> Self {
        Self::new(
            "insufficient-scope",
            "The session does not cover the requested capabilities.",
        )
    }
    fn unavailable() -> Self {
        Self::new(
            "unavailable",
            "The session agent cannot persist a session here.",
        )
    }
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    fn into_js(self) -> JsValue {
        serde_wasm_bindgen::to_value(&self).unwrap_or_else(|_| JsValue::from_str(self.code))
    }
}

impl From<pubky::Error> for AgentFailure {
    fn from(error: pubky::Error) -> Self {
        Self::new("error", error.to_string())
    }
}

/// A session the agent serves, with the homeserver resolved once.
#[derive(Clone)]
struct Served {
    session: PubkySession,
    homeserver: PublicKey,
}

struct HostState {
    client: PubkyHttpClient,
    scope: Capabilities,
    unavailable: bool,
    served: Option<Served>,
}

type SharedHost = Rc<RefCell<HostState>>;

impl HostState {
    /// Status for an app that asked for `requested` capabilities.
    fn status(&self, requested: &str) -> AgentStatus {
        let state = match (&self.served, self.unavailable) {
            (_, true) => AgentState::Unavailable,
            (None, _) => AgentState::SignedOut,
            (Some(served), _) => {
                let held = served.session.info();
                let held_caps = Capabilities::from(held.capabilities().to_vec());
                match requested.parse::<Capabilities>() {
                    Ok(wanted) if held_caps.covers_all(&wanted) => {
                        return AgentStatus {
                            state: AgentState::SignedIn,
                            info: Some(AgentSessionInfo {
                                pubky: held.public_key().z32(),
                                capabilities: held_caps.iter().map(ToString::to_string).collect(),
                                homeserver: served.homeserver.z32(),
                            }),
                        };
                    }
                    _ => AgentState::InsufficientScope,
                }
            }
        };
        AgentStatus { state, info: None }
    }

    /// The served session, if it may lend to an app asking for `requested`.
    fn lender(&self, requested: &str) -> Result<Served, AgentFailure> {
        match self.status(requested).state {
            AgentState::SignedIn => Ok(self.served.clone().expect("signed-in implies a session")),
            AgentState::SignedOut => Err(AgentFailure::signed_out()),
            AgentState::InsufficientScope => Err(AgentFailure::insufficient_scope()),
            AgentState::Unavailable => Err(AgentFailure::unavailable()),
        }
    }

    /// Accept a session only if it stays within the shared scope.
    fn validate(&self, session: &PubkySession) -> JsResult<()> {
        let held = Capabilities::from(session.info().capabilities().to_vec());
        if held.iter().any(|cap| cap.is_root()) || !self.scope.covers_all(&held) {
            return Err(PubkyError::new(
                PubkyErrorName::InvalidInput,
                format!(
                    "Session capabilities `{held}` exceed the agent's shared scope `{}`.",
                    self.scope
                ),
            ));
        }
        Ok(())
    }
}

/// `detail` of the SDK's `pubky-session-changed` event.
#[derive(Deserialize)]
struct SessionChange {
    id: Option<String>,
    action: String,
}

/// The JS-facing callbacks, kept alive for as long as the agent listens.
struct HostCallbacks {
    status: Closure<dyn FnMut(String) -> js_sys::Promise>,
    bearer: Closure<dyn FnMut(String, JsValue) -> js_sys::Promise>,
    signout: Closure<dyn FnMut() -> js_sys::Promise>,
    on_session_change: Closure<dyn FnMut(JsValue)>,
}

impl HostCallbacks {
    /// `token` is filled in once `listen` returns it; the store listener
    /// reads it lazily because it only fires later.
    fn new(host: &SharedHost, token: &Rc<Cell<u32>>) -> Self {
        let for_status = host.clone();
        let status = Closure::new(move |requested: String| {
            let status = for_status.borrow().status(&requested);
            js_sys::Promise::resolve(
                &serde_wasm_bindgen::to_value(&status).unwrap_or(JsValue::NULL),
            )
        });
        let for_bearer = host.clone();
        let bearer = Closure::new(move |requested: String, rejected: JsValue| {
            let host = for_bearer.clone();
            wasm_bindgen_futures::future_to_promise(async move {
                lend(host, &requested, rejected.as_string())
                    .await
                    .map_err(AgentFailure::into_js)
            })
        });
        let for_signout = host.clone();
        let signout = Closure::new(move || {
            let host = for_signout.clone();
            wasm_bindgen_futures::future_to_promise(async move {
                sign_out(host).await.map_err(AgentFailure::into_js)?;
                Ok(JsValue::NULL)
            })
        });
        let (for_change, for_token) = (host.clone(), token.clone());
        let on_session_change = Closure::new(move |detail: JsValue| {
            wasm_bindgen_futures::spawn_local(follow_store(
                for_change.clone(),
                for_token.get(),
                detail,
            ));
        });
        Self {
            status,
            bearer,
            signout,
            on_session_change,
        }
    }
}

/// Serves one grant session to connecting apps.
///
/// Created with `SessionAgent.listen(options)` or
/// `pubky.listenSessionAgent(options)` on the agent origin. Keep it
/// referenced for as long as the page serves; dropping it closes every
/// app connection.
#[wasm_bindgen]
pub struct SessionAgent {
    token: u32,
    host: SharedHost,
    _callbacks: HostCallbacks,
}

#[wasm_bindgen]
impl SessionAgent {
    /// Start answering apps with a new DHT client.
    /// Prefer `pubky.listenSessionAgent()` to reuse a facade client.
    ///
    /// Probes the browser store first, so apps get `unavailable` where no
    /// session can be persisted. Picks up sessions saved with
    /// `browserSessionStore` in any tab on this origin.
    ///
    /// @param {SessionAgentOptions} options `{ allowedOrigins, capabilities }`.
    /// @returns {Promise<SessionAgent>}
    /// @throws {PubkyError} `{ name: "InvalidInput" }` for a malformed origin or scope,
    /// `{ name: "ClientStateError" }` outside a browser window.
    #[wasm_bindgen(js_name = "listen")]
    pub async fn listen(options: Ts<SessionAgentOptions>) -> JsResult<SessionAgent> {
        let options = crate::js_error::deserialize_ts(&options)?;
        Self::listen_with_client(options, None).await
    }

    /// Serve `session` to connecting apps.
    ///
    /// @throws {PubkyError} `{ name: "InvalidInput" }` when the session is root
    /// or exceeds the shared scope.
    #[wasm_bindgen(js_name = "setSession")]
    pub async fn set_session(&self, session: &Session) -> JsResult<()> {
        self.host.borrow().validate(&session.0)?;
        let served = served(session.0.clone()).await?;
        self.host.borrow_mut().served = Some(served);
        broadcast(self.token).await
    }

    /// Stop serving; connected apps see `signed-out`.
    #[wasm_bindgen(js_name = "clearSession")]
    pub async fn clear_session(&self) -> JsResult<()> {
        self.host.borrow_mut().served = None;
        broadcast(self.token).await
    }

    /// Whether a session is currently being served.
    #[wasm_bindgen(js_name = "hasSession", getter)]
    pub fn has_session(&self) -> bool {
        self.host.borrow().served.is_some()
    }

    /// Where the connected app wants Ring to return after approval. Only a
    /// URL on the app's own origin is accepted; otherwise `undefined`.
    #[wasm_bindgen(js_name = "returnUrl", getter)]
    pub fn return_url(&self) -> Option<String> {
        js_agent_return_url(self.token)
    }

    /// Stop listening and close every app connection.
    #[wasm_bindgen]
    pub fn close(&self) {
        js_agent_host_close(self.token);
    }
}

impl SessionAgent {
    pub(crate) async fn listen_with_client(
        options: SessionAgentOptions,
        client: Option<PubkyHttpClient>,
    ) -> JsResult<SessionAgent> {
        for origin in &options.allowed_origins {
            validate_origin(origin)?;
        }
        let scope = crate::wrappers::capabilities::parse_capabilities(&options.capabilities)?;
        let client = match client {
            Some(client) => client,
            None => Client::new(None)?.0,
        };
        let unavailable = !JsFuture::from(js_store_is_available())
            .await
            .ok()
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let host: SharedHost = Rc::new(RefCell::new(HostState {
            client,
            scope,
            unavailable,
            served: None,
        }));
        let token_cell = Rc::new(Cell::new(0u32));
        let callbacks = HostCallbacks::new(&host, &token_cell);
        let origins = options.allowed_origins.iter().map(JsValue::from).collect();
        let token = js_agent_listen(
            PROTOCOL_VERSION,
            origins,
            callbacks.status.as_ref(),
            callbacks.bearer.as_ref(),
            callbacks.signout.as_ref(),
            callbacks.on_session_change.as_ref(),
        )
        .map_err(|error| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                js_error_message(&error, "Starting the session agent failed."),
            )
        })?;
        token_cell.set(token);
        Ok(SessionAgent {
            token,
            host,
            _callbacks: callbacks,
        })
    }
}

impl Drop for SessionAgent {
    /// The JS side must not call into freed closures.
    fn drop(&mut self) {
        js_agent_host_close(self.token);
    }
}

async fn broadcast(token: u32) -> JsResult<()> {
    JsFuture::from(js_agent_broadcast(token))
        .await
        .map(|_| ())
        .map_err(|error| {
            PubkyError::new(
                PubkyErrorName::ClientStateError,
                js_error_message(&error, "Notifying connected apps failed."),
            )
        })
}

async fn served(session: PubkySession) -> JsResult<Served> {
    let grant = session.as_grant().ok_or_else(|| {
        PubkyError::new(
            PubkyErrorName::InvalidInput,
            "Session agents can only serve grant-backed sessions.",
        )
    })?;
    let homeserver = grant.session_info().await.homeserver;
    Ok(Served {
        session,
        homeserver,
    })
}

/// Answer a bearer request from an app asking for `requested` capabilities.
async fn lend(
    host: SharedHost,
    requested: &str,
    rejected: Option<String>,
) -> Result<JsValue, AgentFailure> {
    let served = host.borrow().lender(requested)?;
    let grant = served
        .session
        .as_grant()
        .ok_or_else(|| AgentFailure::new("error", "Served session is not grant-backed."))?;
    let lent: LentBearer = grant.lend_bearer(rejected.as_deref()).await?;
    serde_wasm_bindgen::to_value(&lent)
        .map_err(|error| AgentFailure::new("error", format!("Encoding the bearer failed: {error}")))
}

async fn sign_out(host: SharedHost) -> Result<(), AgentFailure> {
    let served = host
        .borrow()
        .served
        .clone()
        .ok_or_else(AgentFailure::signed_out)?;
    served
        .session
        .signout()
        .await
        .map_err(|(error, _)| AgentFailure::from(error))?;
    host.borrow_mut().served = None;
    Ok(())
}

/// Keep the served session in step with the browser store: a session saved
/// in any tab is picked up, a removed one is dropped.
async fn follow_store(host: SharedHost, token: u32, detail: JsValue) {
    let Ok(change) = serde_wasm_bindgen::from_value::<SessionChange>(detail) else {
        return;
    };
    let current_id = served_id(&host).await;
    let changed = match (change.action.as_str(), change.id) {
        ("saved", Some(id)) if current_id.as_ref() != Some(&id) => adopt_saved(&host, id).await,
        ("removed", Some(id)) if current_id.as_ref() == Some(&id) => {
            host.borrow_mut().served = None;
            true
        }
        ("cleared", _) if current_id.is_some() => {
            host.borrow_mut().served = None;
            true
        }
        _ => false,
    };
    if changed {
        let _ = broadcast(token).await;
    }
}

/// Store id of the served session, if any.
async fn served_id(host: &SharedHost) -> Option<String> {
    let served = host.borrow().served.clone()?;
    let grant = served.session.as_grant()?;
    Some(stored_session_id(&grant.session_info().await))
}

/// Restore and serve a session another frame just saved, if it fits the scope.
async fn adopt_saved(host: &SharedHost, id: String) -> bool {
    let client = host.borrow().client.clone();
    let store = BrowserSessionStore(pubky::Pubky::with_client(client));
    let Ok(session) = store.restore(id.clone()).await else {
        return false;
    };
    // The page may have served this very session with `setSession` while
    // the restore ran; keep that one rather than a second copy of the grant.
    if served_id(host).await.as_deref() == Some(&id) {
        return false;
    }
    if host.borrow().validate(&session.0).is_err() {
        return false;
    }
    match served(session.0).await {
        Ok(served) => {
            host.borrow_mut().served = Some(served);
            true
        }
        Err(_) => false,
    }
}
