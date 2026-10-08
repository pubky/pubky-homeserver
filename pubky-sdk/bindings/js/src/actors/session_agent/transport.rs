//! `postMessage` transport between an app and its agent frame.
//!
//! Connect handshake: the app posts `{ protocol, type: "connect" }` to the
//! agent window with one end of a `MessageChannel`. The agent replies on that
//! port with `{ type: "hello" }` or `{ type: "refused", error }`. Requests then
//! flow over the port as `{ id, method, params }` and are answered with
//! `{ id, ok, value | error }`.

use wasm_bindgen::prelude::*;

#[wasm_bindgen(inline_js = r#"
const PUBKY_AGENT_PROTOCOL = "pubky-session-agent/1";
const HANDSHAKE_RETRY_MS = 250;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ---- App side ----------------------------------------------------------

const agentFrames = new Map();
const agentConnections = new Map();
let nextAgentConnection = 0;

/** Hidden iframe for an agent URL, created on first use and shared afterwards. */
function agentFrame(url) {
  let entry = agentFrames.get(url.href);
  if (entry) return entry;
  const frame = document.createElement("iframe");
  frame.hidden = true;
  frame.setAttribute("aria-hidden", "true");
  // Until the agent document loads the frame is about:blank on our own
  // origin, and a post targeted at the agent origin would be dropped.
  const loaded = new Promise((resolve) => frame.addEventListener("load", resolve, { once: true }));
  frame.src = url.href;
  (document.body ?? document.documentElement).appendChild(frame);
  entry = { frame, loaded };
  agentFrames.set(url.href, entry);
  return entry;
}

/** One handshake attempt: the agent's reply and the port it answered on, or undefined. */
async function handshake(frame, origin) {
  const channel = new MessageChannel();
  const answered = new Promise((resolve) => {
    channel.port1.onmessage = (event) => resolve(event.data);
  });
  frame.contentWindow.postMessage(
    { protocol: PUBKY_AGENT_PROTOCOL, type: "connect" }, origin, [channel.port2],
  );
  const reply = await Promise.race([answered, sleep(HANDSHAKE_RETRY_MS)]);
  if (reply) return { reply, port: channel.port1 };
  channel.port1.close();
  return undefined;
}

/** Register an accepted port and return the token Rust uses to address it. */
function openConnection(port) {
  const token = ++nextAgentConnection;
  const pending = new Map();
  let nextRequest = 0;
  port.onmessage = (event) => {
    const { id, ok, value, error } = event.data ?? {};
    const request = pending.get(id);
    if (!request) return;
    pending.delete(id);
    if (ok) request.resolve(value);
    else request.reject(new Error(error ?? "Session agent request failed."));
  };
  agentConnections.set(token, { port, pending, nextId: () => ++nextRequest });
  return token;
}

export async function __pubkyAgentConnect(agentUrl, timeoutMs) {
  if (!globalThis.document || !globalThis.MessageChannel) {
    throw new Error("Session agents require a browser document.");
  }
  const url = new URL(agentUrl, location.href);
  const deadline = Date.now() + timeoutMs;
  const { frame, loaded } = agentFrame(url);
  await Promise.race([loaded, sleep(timeoutMs)]);
  // The agent installs its listener only once it knows its session state, so
  // silence means "still starting" and the handshake repeats until the deadline.
  while (Date.now() < deadline) {
    const answer = await handshake(frame, url.origin);
    if (!answer) continue;
    if (answer.reply.type === "hello") return openConnection(answer.port);
    answer.port.close();
    throw new Error(answer.reply.error ?? "Session agent refused the connection.");
  }
  throw new Error(`Session agent at ${url.href} did not answer.`);
}

export function __pubkyAgentRequest(token, method, params) {
  const connection = agentConnections.get(token);
  if (!connection) return Promise.reject(new Error("Session agent connection is closed."));
  const id = connection.nextId();
  return new Promise((resolve, reject) => {
    connection.pending.set(id, { resolve, reject });
    connection.port.postMessage({ id, method, params });
  });
}

export function __pubkyAgentClose(token) {
  const connection = agentConnections.get(token);
  if (!connection) return;
  agentConnections.delete(token);
  connection.port.close();
  for (const request of connection.pending.values()) {
    request.reject(new Error("Session agent connection is closed."));
  }
}

// ---- Agent side --------------------------------------------------------

/**
 * Answer connect handshakes from allowlisted origins and route requests to
 * `handler(method, params)`. `onSessionChange(detail)` receives the SDK's
 * `pubky-session-changed` events so a session revoked elsewhere stops being
 * served. Returns a function that detaches both listeners.
 */
export function __pubkyAgentServe(allowedOrigins, handler, onSessionChange) {
  if (typeof globalThis.addEventListener !== "function") {
    throw new Error("Session agents require a browser window.");
  }
  const allowed = new Set(allowedOrigins);
  const onConnect = (event) => {
    const data = event.data;
    if (!data || data.protocol !== PUBKY_AGENT_PROTOCOL || data.type !== "connect") return;
    const port = event.ports?.[0];
    if (!port) return;
    if (!allowed.has(event.origin)) {
      port.postMessage({ type: "refused", error: `Origin ${event.origin} may not use this session agent.` });
      port.close();
      return;
    }
    port.onmessage = async (message) => {
      const { id, method, params } = message.data ?? {};
      try {
        port.postMessage({ id, ok: true, value: await handler(method, params ?? null) });
      } catch (error) {
        port.postMessage({ id, ok: false, error: error?.message ?? String(error) });
      }
    };
    port.postMessage({ type: "hello" });
  };
  const onChange = (event) => onSessionChange(event.detail);
  addEventListener("message", onConnect);
  addEventListener("pubky-session-changed", onChange);
  return () => {
    removeEventListener("message", onConnect);
    removeEventListener("pubky-session-changed", onChange);
  };
}
"#)]
extern "C" {
    /// Resolves to a connection token once the agent accepted the handshake.
    #[wasm_bindgen(js_name = __pubkyAgentConnect)]
    pub(super) fn connect_frame(agent_url: &str, timeout_ms: f64) -> js_sys::Promise;
    /// Resolves to the agent's reply value or rejects with its error.
    #[wasm_bindgen(js_name = __pubkyAgentRequest)]
    pub(super) fn request(token: u32, method: JsValue, params: JsValue) -> js_sys::Promise;
    #[wasm_bindgen(js_name = __pubkyAgentClose)]
    pub(super) fn close(token: u32);
    /// Returns the function that stops serving. Throws outside a browser window.
    #[wasm_bindgen(js_name = __pubkyAgentServe, catch)]
    pub(super) fn serve(
        allowed_origins: js_sys::Array,
        handler: &JsValue,
        on_session_change: &JsValue,
    ) -> Result<js_sys::Function, JsValue>;
}
