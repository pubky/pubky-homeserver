# SSO across first-party origins with a session agent

A user signs in once on any app of a site, and every other app on that site is signed in too.

A small page on a dedicated origin, the *agent*, holds the user's single grant session. Each app embeds that page in an iframe and borrows its short-lived bearer over `postMessage`. Apps then call the homeserver directly with the normal SDK. The homeserver protocol, Ring and Passport do not change.

## How it works

- **The agent** runs at a dedicated origin such as `https://auth.pubky.app/agent`. It holds the only grant, its non-extractable PoP key and the current bearer through `browserSessionStore`. Its `client_id` is its own hostname. Browsers do not partition storage for a same-site frame, so every agent frame on the site shares one IndexedDB and one set of Web Locks, and the [tab coordination](grant-session-lifecycle.md) works unchanged.
- **The client** is the SDK in each app. It completes a handshake with the agent frame and exposes a `Session` whose credential borrows bearers from the agent. Storage, events and locks work as usual because they all go through the session credential.

| Situation | Behaviour |
|---|---|
| The user is signed in | The handshake returns `signed-in` with `{ pubky, capabilities, homeserver }`. The first request asks the agent for a bearer; requests then go straight to the homeserver with `Authorization: Bearer`. |
| The user is signed out | The handshake returns `signed-out` and the app shows the frame. The agent runs the grant flow for the shared scope, shows the QR code or the Ring link, saves the session with `browserSessionStore`, and sends `signed-in` to every connected app. The app hides the frame. |
| The bearer rotated | A request gets a 401, so the client asks the agent again and names the rejected bearer. The agent exchanges the grant only if that bearer is still current, exactly as tabs do today. The client retries once if the request body can be cloned. |
| The user signs out | Sign-out starts on the agent page or from an app's `session.signout()`, which forwards it. The agent revokes the grant and removes the stored session; every agent frame sees `pubky-session-changed` and sends `signed-out` to its app. |

### Browser support

Chrome, Firefox and Safari all leave a same-site frame unpartitioned, so first-party apps share the agent's store in each of them (WebKit's [tracking prevention](https://webkit.org/tracking-prevention/) partitions only frames with a cross-site context in the chain). A cross-site embedder gets a partitioned store in every browser, and Safari also makes that store ephemeral. Where the store cannot persist, the agent answers `unavailable` and the app runs its own grant flow.

## SDK API

Agent origin:

```js
const agent = await pubky.listenSessionAgent({
  allowedOrigins: ["https://pubky.app", "https://shop.pubky.app"],
  capabilities: "/pub/pubky.app/:rw",
});
// Sessions saved with browserSessionStore in any tab are picked up; or:
await agent.setSession(session);
```

`listen` probes the browser store and refuses to serve a session that is root or exceeds `capabilities`. `agent.returnUrl` is where the connected app wants Ring to return after a mobile approval; pass it as `xSuccess` when starting the grant flow.

App origin:

```js
const frame = document.querySelector("iframe#agent"); // src: https://auth.pubky.app/agent
const client = await pubky.connectSessionAgent(frame, {
  agentOrigin: "https://auth.pubky.app",
  capabilities: "/pub/pubky.app/:rw",
  returnUrl: location.href,
});
frame.hidden = client.status.state !== "signed-out";
client.addEventListener("change", (event) => {
  frame.hidden = event.detail.state !== "signed-out";
  render(client.session);
});
```

`client.session` is a normal `Session` while the state is `signed-in`, and `undefined` otherwise. `Session.grant` is `undefined` for a borrowed session. Keep the client referenced and the frame mounted for as long as its session is used: closing or dropping the client ends the connection, and a removed or navigated frame stops answering. The session then fails as soon as it next needs the agent, which is at once without a cached bearer and otherwise when that bearer is rejected or near expiry; a request to a frame that has gone away fails at once where the browser closes the port and after a 30 second timeout elsewhere. Hide the frame rather than unmounting it.

A `signed-in` status names the user. If the agent starts serving another user (someone signed in on another tab), the client replaces `client.session`, and a `Session` object the app kept for the previous user refuses the new bearer instead of acting as the new user.

## Protocol (v1)

The handshake uses `window.postMessage`. All later messages go over a dedicated `MessagePort`.

1. The app sends `{ type: "pubky-agent/hello", v: 1, capabilities, returnUrl }` to the agent origin and transfers a port.
2. The agent replies only if `event.origin` exactly matches the allowlist and `event.source === window.parent`. Otherwise it replies `{ type: "error", code: "origin-not-allowed" }`. An agent that does not support `v` replies `{ type: "error", code: "unsupported-version" }`. A frame serves one connection: a new hello replaces the previous one.
3. Whenever its state changes, the agent sends `{ type: "status", state, info? }` on the port. `state` is one of `signed-in`, `signed-out`, `insufficient-scope` or `unavailable`.

| Message | Direction | Reply |
|---|---|---|
| `{ type: "bearer", id, rejected? }` | App to agent | `{ id, ok: true, bearer }` or `{ id, ok: false, code, message }` |
| `{ type: "signout", id }` | App to agent | `{ id, ok }` |
| `{ type: "ui", height }` | Agent to app | None. The client resizes the frame. |

`bearer` is `{ token, expires_at, pubky, capabilities, homeserver }`. The agent never sends the grant JWS, the grant id or the key. A `rejected` bearer that is still current makes the agent exchange the grant, which invalidates the bearer every other app holds; apps only name a bearer the homeserver actually refused.

Error codes on a reply: `signed-out`, `insufficient-scope`, `unavailable`, `unsupported-message`, or `error` with a message.

## Origin rules

- Allowed origins are exact: scheme, host and port, no path and no default port. A sibling subdomain that is not listed is refused even though it is same-site.
- Only the frame's direct parent may connect: a popup, a sibling frame or a frame inside the agent is refused. An allowlisted app that is itself embedded by a same-site page still connects, since only its own origin is checked.
- `returnUrl` in the hello is used only if it is on the connecting app's own origin; otherwise the agent ignores it.
- Cross-site embedders get a partitioned, empty agent and see `signed-out`. Sharing with other sites is out of scope.

## Scope

The agent serves one grant, so every app gets the same capabilities. Keep the shared scope to what every first-party app needs, and keep private and payment scopes on each app's own grant. An app that asks for more than the shared scope receives `insufficient-scope` and should use its own grant flow.

Every allowlisted app can read and write the shared scope with the borrowed bearer, and so can an XSS attack in any of them. Only team-run apps belong on the allowlist.

## Deployment requirements for the agent page

| Setting | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src https:; frame-ancestors <exact allowlist>; base-uri 'none'; form-action 'none'`. `connect-src` is `https:` because users can be on any homeserver. |
| Other headers | `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` |
| Scripts | No third-party scripts or analytics |

To cut off an app, remove its origin from the allowlist and from `frame-ancestors`, then redeploy. Bearers it already holds expire within an hour; a forced refresh invalidates them immediately.

## Versioning

`v` in the hello is the protocol version. A change to message shapes or to the meaning of a state bumps it; an agent that does not support the requested version answers `unsupported-version` and the client reports a `ClientStateError` whose `data.code` carries that code.

## Tests

`npm run test-browser:sso` in `pubky-sdk/bindings/js/pkg` runs the Electron regression with five origins (ports stand in for hostnames: every `localhost:<port>` is one site, `127.0.0.1` another). It covers in-frame sign-in, silent second-origin sign-in, bearer rotation and retry, allowlist and sibling-frame refusal, `insufficient-scope`, cross-site partitioning, the raw protocol replies, a user switch, sign-out propagation and a cleared store. The `unavailable` state has no automated coverage: Electron offers no profile where IndexedDB and Web Locks are missing.
