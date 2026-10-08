//! Session agent client: borrow a session from an agent frame.
//!
//! The app owns the iframe whose `src` is the agent page and passes it to
//! `SessionAgentClient.connect`. The client completes the hello handshake,
//! tracks the agent's `status` messages, sizes the frame from its `ui`
//! messages, and exposes a `Session` that borrows the agent's bearer through
//! [`pubky::BearerSource`]. The protocol is documented in `docs/sso-agent.md`.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::Arc,
};

use pubky::{BearerSource, LentBearer, PubkyHttpClient, PubkySession, SessionInfo};
use pubky_common::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::session::Session;
use super::session_agent_protocol::{
    AgentSessionInfo, AgentState, AgentStatus, PROTOCOL_VERSION, validate_origin,
};
use crate::client::constructor::Client;
use crate::js_error::{JsResult, PubkyError, PubkyErrorName, deserialize_ts, serialize_ts};

#[wasm_bindgen(typescript_custom_section)]
const TS_SESSION_AGENT_EVENTS: &str = r#"
/** Dispatched by `SessionAgentClient` as `change`; `detail` is the new status. */
export type SessionAgentChangeEvent = CustomEvent<AgentStatus>;"#;

#[wasm_bindgen(inline_js = r#"
const PUBKY_AGENT_CLIENT_HELLO = "pubky-agent/hello";
const PUBKY_AGENT_HANDSHAKE_RETRY_MS = 250;
// A bearer request may wait for the agent's grant exchange behind other tabs.
const PUBKY_AGENT_REQUEST_TIMEOUT_MS = 30000;
const PUBKY_AGENT_CLOSED = "Session agent connection is closed.";
const pubkyAgentClients = new Map();
let nextPubkyAgentClient = 0;

const pubkyAgentSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function pubkyAgentError(code, message) {
  const error = new Error(message ?? `Session agent replied ${code}.`);
  error.code = code;
  return error;
}

/**
 * Complete the hello handshake. The agent installs its listener only once it
 * knows its session state, so silence means "still starting" and the hello
 * is repeated until the deadline. The first reply is a status or an error.
 */
export async function __pubkyAgentConnect(frame, agentOrigin, hello, timeoutMs, onStatus) {
  if (!globalThis.document || !globalThis.MessageChannel) {
    throw new Error("Session agents require a browser document.");
  }
  const origin = new URL(agentOrigin).origin;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const channel = new MessageChannel();
    const first = new Promise((resolve) => {
      channel.port1.onmessage = (event) => resolve(event.data);
    });
    frame.contentWindow?.postMessage({ type: PUBKY_AGENT_CLIENT_HELLO, ...hello }, origin, [channel.port2]);
    const reply = await Promise.race([first, pubkyAgentSleep(PUBKY_AGENT_HANDSHAKE_RETRY_MS)]);
    if (reply?.type === "status") return openClient(frame, channel.port1, reply, onStatus);
    channel.port1.close();
    if (reply?.type === "error") throw pubkyAgentError(reply.code);
  }
  throw new Error(`Session agent at ${origin} did not answer.`);
}

function openClient(frame, port, first, onStatus) {
  const token = ++nextPubkyAgentClient;
  const client = {
    port, status: statusOf(first), pending: new Map(), nextId: 0, events: new EventTarget(), open: true,
  };
  pubkyAgentClients.set(token, client);
  port.onmessage = (event) => {
    const data = event.data ?? {};
    if (data.type === "status") {
      client.status = statusOf(data);
      onStatus(client.status);
      client.events.dispatchEvent(new CustomEvent("change", { detail: client.status }));
    } else if (data.type === "ui") {
      if (typeof data.height === "number") frame.style.height = `${data.height}px`;
    } else {
      settle(client, data.id, (request) => {
        if (data.ok) request.resolve(data);
        else request.reject(pubkyAgentError(data.code, data.message));
      });
    }
  };
  // Browsers that support it close the port when the agent document goes
  // away (frame removed or navigated); elsewhere the request timeout catches it.
  port.addEventListener("close", () => closeClient(token));
  return token;
}

function settle(client, id, finish) {
  const request = client.pending.get(id);
  if (!request) return;
  client.pending.delete(id);
  clearTimeout(request.timer);
  finish(request);
}

function closeClient(token) {
  const client = pubkyAgentClients.get(token);
  if (!client) return;
  client.open = false;
  client.port.close();
  for (const id of Array.from(client.pending.keys())) {
    settle(client, id, (request) => request.reject(new Error(PUBKY_AGENT_CLOSED)));
  }
  pubkyAgentClients.delete(token);
}

function statusOf(message) {
  return message.info ? { state: message.state, info: message.info } : { state: message.state };
}

function requireClient(token) {
  const client = pubkyAgentClients.get(token);
  if (!client?.open) throw new Error(PUBKY_AGENT_CLOSED);
  return client;
}

export function __pubkyAgentRequest(token, message) {
  // Reject rather than throw: the import has no `catch`, and the Rust caller
  // only handles a settled promise.
  const client = pubkyAgentClients.get(token);
  if (!client?.open) return Promise.reject(new Error(PUBKY_AGENT_CLOSED));
  const id = ++client.nextId;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => settle(client, id, (request) => {
      request.reject(new Error(`Session agent did not answer within ${PUBKY_AGENT_REQUEST_TIMEOUT_MS} ms.`));
    }), PUBKY_AGENT_REQUEST_TIMEOUT_MS);
    client.pending.set(id, { resolve, reject, timer });
    client.port.postMessage({ id, ...message });
  });
}
export function __pubkyAgentStatus(token) { return requireClient(token).status; }
export function __pubkyAgentEvents(token) { return requireClient(token).events; }
export function __pubkyAgentClientClose(token) { closeClient(token); }
"#)]
extern "C" {
    #[wasm_bindgen(js_name = __pubkyAgentConnect)]
    fn js_agent_connect(
        frame: &JsValue,
        agent_origin: &str,
        hello: JsValue,
        timeout_ms: f64,
        on_status: &JsValue,
    ) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyAgentRequest)]
    fn js_agent_request(token: u32, message: JsValue) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyAgentStatus, catch)]
    fn js_agent_status(token: u32) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = __pubkyAgentEvents, catch)]
    fn js_agent_events(token: u32) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = __pubkyAgentClientClose)]
    fn js_agent_client_close(token: u32);
}

const DEFAULT_CONNECT_TIMEOUT_MS: f64 = 5_000.0;

/// Options for `SessionAgentClient.connect`.
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SessionAgentClientOptions {
    /// Origin of the agent page, e.g. `"https://auth.pubky.app"`.
    pub(crate) agent_origin: String,
    /// Capabilities this app needs from the shared session.
    #[tsify(type = "Capabilities")]
    pub(crate) capabilities: String,
    /// Same-origin URL Ring returns to after a mobile approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[tsify(optional, type = "string | null")]
    pub(crate) return_url: Option<String>,
    /// How long to wait for the agent to answer the handshake, in
    /// milliseconds. Defaults to 5000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[tsify(optional, type = "number | null")]
    pub(crate) timeout_ms: Option<f64>,
}

/// Body of the hello handshake, after `type`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Hello<'a> {
    v: u32,
    capabilities: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    return_url: Option<&'a str>,
}

/// A request sent over the port, before the `id` the transport adds.
#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Request<'a> {
    Bearer {
        #[serde(skip_serializing_if = "Option::is_none")]
        rejected: Option<&'a str>,
    },
    Signout,
}

/// A successful bearer reply.
#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct BearerReply {
    bearer: LentBearer,
}

/// The app side of a connection, used by the borrowed session.
#[derive(Debug)]
struct AgentSource {
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    token: u32,
}

#[cfg(target_arch = "wasm32")]
impl AgentSource {
    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        request: Request<'_>,
    ) -> pubky::Result<T> {
        let message =
            serde_wasm_bindgen::to_value(&request).map_err(|error| failure(error.to_string()))?;
        let reply = JsFuture::from(js_agent_request(self.token, message))
            .await
            .map_err(|error| {
                failure(crate::js_error::js_error_message(
                    &error,
                    "Session agent request failed.",
                ))
            })?;
        serde_wasm_bindgen::from_value(reply).map_err(|error| failure(error.to_string()))
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
impl BearerSource for AgentSource {
    async fn bearer(&self, rejected: Option<&str>) -> pubky::Result<LentBearer> {
        let reply: BearerReply = self.request(Request::Bearer { rejected }).await?;
        Ok(reply.bearer)
    }

    async fn status(&self) -> pubky::Result<Option<SessionInfo>> {
        let status = js_agent_status(self.token).map_err(|error| {
            failure(crate::js_error::js_error_message(
                &error,
                "Session agent connection is closed.",
            ))
        })?;
        let status: AgentStatus =
            serde_wasm_bindgen::from_value(status).map_err(|error| failure(error.to_string()))?;
        match (status.state, status.info) {
            (AgentState::SignedIn, Some(info)) => Ok(Some(session_identity(&info)?.1)),
            _ => Ok(None),
        }
    }

    async fn signout(&self) -> pubky::Result<()> {
        let _: serde::de::IgnoredAny = self.request(Request::Signout).await?;
        Ok(())
    }
}

// Native workspace checks compile the bindings, but cannot call browser APIs.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl BearerSource for AgentSource {
    async fn bearer(&self, _: Option<&str>) -> pubky::Result<LentBearer> {
        Err(failure("Session agents require a WASM browser build."))
    }
    async fn status(&self) -> pubky::Result<Option<SessionInfo>> {
        Err(failure("Session agents require a WASM browser build."))
    }
    async fn signout(&self) -> pubky::Result<()> {
        Err(failure("Session agents require a WASM browser build."))
    }
}

fn failure(message: impl Into<String>) -> pubky::Error {
    pubky::errors::AuthError::Validation(message.into()).into()
}

/// Homeserver and session info from the agent's public metadata.
fn session_identity(info: &AgentSessionInfo) -> pubky::Result<(PublicKey, SessionInfo)> {
    let pubky = PublicKey::try_from_z32(&info.pubky).map_err(|error| failure(error.to_string()))?;
    let homeserver =
        PublicKey::try_from_z32(&info.homeserver).map_err(|error| failure(error.to_string()))?;
    let capabilities = info
        .capabilities
        .iter()
        .map(|cap| {
            cap.parse()
                .map_err(|error: pubky_common::capabilities::CapabilityParseError| {
                    failure(error.to_string())
                })
        })
        .collect::<pubky::Result<Vec<_>>>()?;
    Ok((homeserver, SessionInfo::new(pubky, capabilities)))
}

struct ClientState {
    client: PubkyHttpClient,
    status: AgentStatus,
    session: Option<PubkySession>,
}

type SharedClient = Rc<RefCell<ClientState>>;

impl ClientState {
    /// Follow a status message: a `signed-in` status gets a borrowed session.
    /// A repeated status keeps the session and its cached bearer.
    fn apply(&mut self, status: AgentStatus, token: u32) {
        if status == self.status {
            return;
        }
        self.session = match (&status.state, &status.info) {
            (AgentState::SignedIn, Some(info)) => {
                session_identity(info).ok().map(|(homeserver, info)| {
                    PubkySession::from_bearer_source(
                        self.client.clone(),
                        Arc::new(AgentSource { token }),
                        homeserver,
                        info,
                    )
                })
            }
            _ => None,
        };
        self.status = status;
    }
}

/// The JS status callback. `token` is filled in once `connect` returns it.
fn status_tracker(state: &SharedClient, token: &Rc<Cell<u32>>) -> Closure<dyn FnMut(JsValue)> {
    let (state, token) = (state.clone(), token.clone());
    Closure::new(move |status: JsValue| {
        if let Ok(status) = serde_wasm_bindgen::from_value::<AgentStatus>(status) {
            state.borrow_mut().apply(status, token.get());
        }
    })
}

/// A connection to a session agent frame.
///
/// `status` and `session` follow the agent's status messages; `change`
/// events fire after each update. Show the frame while the state is
/// `signed-out` so the user can sign in there. Keep the client referenced
/// and the frame mounted for as long as its session is used: dropping the
/// client closes the connection, and removing or navigating the frame makes
/// the session's requests fail once the agent stops answering.
#[wasm_bindgen]
pub struct SessionAgentClient {
    token: u32,
    state: SharedClient,
    _on_status: Closure<dyn FnMut(JsValue)>,
}

#[wasm_bindgen]
impl SessionAgentClient {
    /// Connect through `frame` with a new DHT client.
    /// Prefer `pubky.connectSessionAgent()` to reuse a facade client.
    ///
    /// @param {HTMLIFrameElement} frame An iframe whose `src` is the agent page.
    /// @param {SessionAgentClientOptions} options `{ agentOrigin, capabilities, returnUrl?, timeoutMs? }`.
    /// @returns {Promise<SessionAgentClient>}
    /// @throws {PubkyError} `{ name: "ClientStateError" }` when the agent refuses
    /// this origin, speaks another protocol version, or does not answer.
    /// `error.data.code` carries the agent's code when it sent one.
    #[wasm_bindgen(js_name = "connect")]
    pub async fn connect(
        #[wasm_bindgen(unchecked_param_type = "HTMLIFrameElement")] frame: JsValue,
        options: Ts<SessionAgentClientOptions>,
    ) -> JsResult<SessionAgentClient> {
        let options = deserialize_ts(&options)?;
        Self::connect_with_client(frame, options, None).await
    }

    /// The agent's latest status.
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> JsResult<Ts<AgentStatus>> {
        serialize_ts(&self.state.borrow().status)
    }

    /// A session borrowing the agent's bearer, while `signed-in`.
    #[wasm_bindgen(getter)]
    pub fn session(&self) -> Option<Session> {
        self.state.borrow().session.clone().map(Session)
    }

    /// Listen for `change` events (`SessionAgentChangeEvent`).
    #[wasm_bindgen(js_name = "addEventListener")]
    pub fn add_event_listener(&self, kind: &str, listener: &js_sys::Function) -> JsResult<()> {
        self.events()?
            .add_event_listener_with_callback(kind, listener);
        Ok(())
    }

    /// Stop listening for events.
    #[wasm_bindgen(js_name = "removeEventListener")]
    pub fn remove_event_listener(&self, kind: &str, listener: &js_sys::Function) -> JsResult<()> {
        self.events()?
            .remove_event_listener_with_callback(kind, listener);
        Ok(())
    }

    /// Close the connection. The borrowed session fails as soon as it next
    /// needs the agent: at once without a cached bearer, otherwise when that
    /// bearer is rejected or near expiry.
    #[wasm_bindgen]
    pub fn close(&self) {
        js_agent_client_close(self.token);
    }
}

impl SessionAgentClient {
    pub(crate) async fn connect_with_client(
        frame: JsValue,
        options: SessionAgentClientOptions,
        client: Option<PubkyHttpClient>,
    ) -> JsResult<SessionAgentClient> {
        validate_origin(&options.agent_origin)?;
        crate::wrappers::capabilities::parse_capabilities(&options.capabilities).map(drop)?;
        let client = match client {
            Some(client) => client,
            None => Client::new(None)?.0,
        };
        let state: SharedClient = Rc::new(RefCell::new(ClientState {
            client,
            status: AgentStatus {
                state: AgentState::SignedOut,
                info: None,
            },
            session: None,
        }));
        let token_cell = Rc::new(Cell::new(0u32));
        let on_status = status_tracker(&state, &token_cell);

        let hello = serde_wasm_bindgen::to_value(&Hello {
            v: PROTOCOL_VERSION,
            capabilities: &options.capabilities,
            return_url: options.return_url.as_deref(),
        })
        .map_err(|error| PubkyError::new(PubkyErrorName::InternalError, error.to_string()))?;
        let timeout = options.timeout_ms.unwrap_or(DEFAULT_CONNECT_TIMEOUT_MS);
        let token = JsFuture::from(js_agent_connect(
            &frame,
            &options.agent_origin,
            hello,
            timeout,
            on_status.as_ref(),
        ))
        .await
        .map_err(connect_error)?
        .as_f64()
        .ok_or_else(|| {
            PubkyError::new(
                PubkyErrorName::InternalError,
                "Session agent connect returned no token.",
            )
        })? as u32;
        token_cell.set(token);

        // The handshake's own status arrived before the token existed.
        let first = js_agent_status(token).map_err(connect_error)?;
        let first = serde_wasm_bindgen::from_value::<AgentStatus>(first)
            .map_err(|error| PubkyError::new(PubkyErrorName::InternalError, error.to_string()))?;
        state.borrow_mut().apply(first, token);

        Ok(SessionAgentClient {
            token,
            state,
            _on_status: on_status,
        })
    }

    fn events(&self) -> JsResult<web_sys_event_target::EventTarget> {
        js_agent_events(self.token)
            .map_err(connect_error)
            .map(web_sys_event_target::EventTarget::from)
    }
}

impl Drop for SessionAgentClient {
    /// The JS side must not call into freed closures.
    fn drop(&mut self) {
        js_agent_client_close(self.token);
    }
}

/// Minimal `EventTarget` binding; the bindings crate does not depend on `web-sys`.
mod web_sys_event_target {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = EventTarget)]
        pub type EventTarget;
        #[wasm_bindgen(method, js_name = addEventListener)]
        pub fn add_event_listener_with_callback(
            this: &EventTarget,
            kind: &str,
            listener: &js_sys::Function,
        );
        #[wasm_bindgen(method, js_name = removeEventListener)]
        pub fn remove_event_listener_with_callback(
            this: &EventTarget,
            kind: &str,
            listener: &js_sys::Function,
        );
    }
}

fn connect_error(value: JsValue) -> PubkyError {
    let message =
        crate::js_error::js_error_message(&value, "Connecting to the session agent failed.");
    let code = js_sys::Reflect::get(&value, &JsValue::from_str("code"))
        .ok()
        .and_then(|code| code.as_string());
    let error = PubkyError::new(PubkyErrorName::ClientStateError, message);
    match code {
        Some(code) => error.with_data(serde_json::json!({ "code": code })),
        None => error,
    }
}
