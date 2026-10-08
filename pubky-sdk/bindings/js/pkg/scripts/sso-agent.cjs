// One browser profile, five origins: the acceptance test for SSO through a
// session agent. Sign in once, inside the agent frame of one app, then every
// allowlisted same-site origin is signed in with zero interaction and no
// grant exchange of its own.
//
// Ports stand in for hostnames. Every `localhost:<port>` is a distinct origin
// of one site, like `pubky.app` and `shop.pubky.app`; `127.0.0.1` is another
// site, like `example.com`.
const { app, BrowserWindow } = require("electron");
const { createServer } = require("node:http");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const assert = require("node:assert/strict");
const { once } = require("node:events");

// Browsers ship third-party storage partitioning on; make sure Electron does too,
// because the cross-site step depends on it.
app.commandLine.appendSwitch("enable-features", "ThirdPartyStoragePartitioning");

const bundle = readFileSync(join(__dirname, "../dist/sso-agent.bundle.js"));
const servers = [];
const windows = [];

async function serve(hostname) {
  const server = createServer((req, res) => {
    res.setHeader("Content-Type", req.url === "/bundle.js" ? "text/javascript" : "text/html");
    res.end(req.url === "/bundle.js" ? bundle : '<!doctype html><body><script src="/bundle.js"></script></body>');
  });
  servers.push(server);
  server.listen(0);
  await once(server, "listening");
  return `http://${hostname}:${server.address().port}`;
}

function callIn(target, method, args) {
  return target.executeJavaScript(`(async () => {
    try { return { ok: true, value: await harness.${method}(...${JSON.stringify(args)}) }; }
    catch (error) { return { ok: false, error: error.message || String(error) }; }
  })()`, true).then((result) => {
    if (!result.ok) throw new Error(`${method}: ${result.error}`);
    return result.value;
  });
}
const call = (window, method, ...args) => callIn(window.webContents, method, args);
/** Call into the agent iframe embedded in an app window. */
function callAgent(window, agentOrigin, method, ...args) {
  const frame = window.webContents.mainFrame.frames.find((f) => f.url.startsWith(agentOrigin));
  assert.ok(frame, "app window embeds the agent frame");
  return callIn(frame, method, args);
}

async function open(url) {
  const window = new BrowserWindow({ show: false, webPreferences: {
    nodeIntegration: false, contextIsolation: true, partition: "pubky-sso-agent-test",
  }});
  windows.push(window);
  window.webContents.on("console-message", (event) => {
    if (event.level === "error") console.error(String(event.message).slice(0, 1200));
  });
  await window.loadURL(url);
  await call(window, "ready");
  return window;
}

async function until(check) {
  for (let i = 0; i < 150; i++) {
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("Browser condition did not settle");
}

async function scenario() {
  const origins = {
    agent: await serve("localhost"),
    app: await serve("localhost"),
    shop: await serve("localhost"),
    uninvited: await serve("localhost"),
    crossSite: await serve("127.0.0.1"),
  };
  const allowed = [origins.app, origins.shop, origins.crossSite].join(",");
  const appUrl = (origin, caps) => {
    const url = new URL("/app", origin);
    url.searchParams.set("agent", origins.agent);
    url.searchParams.set("allow", allowed);
    if (caps) url.searchParams.set("caps", caps);
    return url.href;
  };
  const port = (origin) => new URL(origin).port;
  const state = async (window) => (await call(window, "status"))?.state;

  // Fresh profile: both apps connect and are told to show the sign-in frame,
  // sized by the agent's `ui` message.
  let appWindow = await open(appUrl(origins.app));
  assert.deepEqual(await call(appWindow, "ready"), { status: { state: "signed-out" } });
  assert.equal(await call(appWindow, "frameVisible"), true);
  assert.equal(await call(appWindow, "whoami"), undefined);
  await until(async () => /px$/.test(await call(appWindow, "frameHeight")));
  const shop = await open(appUrl(origins.shop));
  assert.equal((await call(shop, "ready")).status.state, "signed-out");

  // The agent speaks one protocol version and refuses root sessions.
  assert.deepEqual(await call(appWindow, "rawHello", 99), { type: "error", code: "unsupported-version" });

  // Sign in inside the first app's frame. Both apps flip to signed-in without
  // a reload: the shop's frame picks the saved session up from the store.
  assert.equal(await callAgent(appWindow, origins.agent, "returnUrl"), appUrl(origins.app));
  const user = await callAgent(appWindow, origins.agent, "signin");
  await until(async () => (await state(appWindow)) === "signed-in");
  assert.equal(await call(appWindow, "whoami"), user);
  assert.equal(await call(appWindow, "frameVisible"), false);
  assert.equal((await call(appWindow, "changes")).at(-1).state, "signed-in");
  assert.equal(await callAgent(appWindow, origins.agent, "rejectsRootSession"), "InvalidInput");
  assert.equal(await callAgent(appWindow, origins.agent, "rejectsScopedSession"), "InvalidInput");
  await call(appWindow, "write", "hello from app");
  assert.equal((await call(appWindow, "counts")).exchanges, 0, "apps never exchange a grant");

  await until(async () => (await state(shop)) === "signed-in");
  assert.equal(await call(shop, "whoami"), user);
  assert.equal(await call(shop, "frameVisible"), false);
  assert.equal(await call(shop, "read", port(origins.app)), "hello from app");
  await call(shop, "write", "hello from shop");
  assert.equal(await call(appWindow, "read", port(origins.shop)), "hello from shop");
  assert.equal((await call(shop, "counts")).exchanges, 0);

  // One grant backs every app.
  assert.equal(await callAgent(appWindow, origins.agent, "grantCount"), 1);

  // The agent rotates its bearer; each app recovers from the 401 with one retry.
  // Public reads succeed with a stale bearer, so writes are what show the retry.
  await callAgent(appWindow, origins.agent, "rotate");
  await call(appWindow, "write", "after rotation");
  assert.deepEqual(await call(appWindow, "counts"), { exchanges: 0, unauthorized: 1 });
  await call(shop, "write", "shop after rotation");
  assert.deepEqual(await call(shop, "counts"), { exchanges: 0, unauthorized: 1 });
  assert.equal(await call(appWindow, "read", port(origins.shop)), "shop after rotation");

  // The raw protocol, from a window whose SDK connection the hand-made hello
  // replaces. A foreign return URL is ignored, an unknown message is refused,
  // and the bearer carries no grant material. Naming the current bearer as
  // rejected forces one exchange; doing it again inside the throttle window
  // returns the bearer just minted instead of exchanging once more.
  const raw = await open(appUrl(origins.app));
  const rawStatus = await call(raw, "rawHello", 1, "http://evil.example/back");
  assert.equal(rawStatus.state, "signed-in");
  assert.equal(await callAgent(raw, origins.agent, "returnUrl"), undefined);
  assert.equal((await call(raw, "rawRequest", { type: "bogus" })).code, "unsupported-message");
  const lent = (await call(raw, "rawRequest", { type: "bearer" })).bearer;
  assert.deepEqual(Object.keys(lent).sort(), ["capabilities", "expires_at", "homeserver", "pubky", "token"]);
  assert.equal(lent.pubky, user);
  const forced = (await call(raw, "rawRequest", { type: "bearer", rejected: lent.token })).bearer;
  assert.notEqual(forced.token, lent.token, "a rejected current bearer is replaced");
  const throttled = (await call(raw, "rawRequest", { type: "bearer", rejected: forced.token })).bearer;
  assert.equal(throttled.token, forced.token, "a second forced replacement within the window is refused");
  assert.deepEqual(await call(raw, "siblingHello"), { type: "error", code: "origin-not-allowed" });
  raw.destroy();

  // A same-site origin that is not allowlisted is refused.
  const uninvited = await open(appUrl(origins.uninvited));
  assert.equal((await call(uninvited, "ready")).code, "origin-not-allowed");

  // An app asking for more than the shared scope gets no session.
  const greedy = await open(appUrl(origins.app, "/pub/other.test/:rw"));
  assert.deepEqual(await call(greedy, "ready"), { status: { state: "insufficient-scope" } });
  assert.equal(await call(greedy, "whoami"), undefined);

  // A cross-site embedder gets a partitioned, empty agent.
  const crossSite = await open(appUrl(origins.crossSite));
  assert.equal((await call(crossSite, "ready")).status.state, "signed-out");

  // Another tab of the first app shares the session.
  const tab = await open(appUrl(origins.app));
  assert.equal((await call(tab, "ready")).status.state, "signed-in");
  assert.equal((await call(tab, "counts")).exchanges, 0);

  // Closing the client fails the borrowed session as soon as it needs the
  // agent; this one has not borrowed a bearer yet, so that is its first write.
  const closing = await open(appUrl(origins.app));
  assert.equal((await call(closing, "ready")).status.state, "signed-in");
  await call(closing, "closeClient");
  await assert.rejects(call(closing, "write", "after close"), /connection is closed/);
  closing.destroy();

  // Signing out from one app signs out everywhere: the agent revokes the
  // grant, every frame drops it, and the apps are told to show sign-in again.
  await call(shop, "hold");
  await call(shop, "signout");
  await until(async () => (await state(appWindow)) === "signed-out");
  assert.equal(await call(appWindow, "frameVisible"), true);
  assert.equal(await callAgent(appWindow, origins.agent, "hasSession"), false);
  assert.equal(await call(appWindow, "whoami"), undefined);
  await until(async () => (await state(tab)) === "signed-out");
  appWindow.destroy();
  appWindow = await open(appUrl(origins.app));
  assert.deepEqual(await call(appWindow, "ready"), { status: { state: "signed-out" } });

  // A second user signs in. Every app follows, and the session object the
  // shop kept for the first user refuses the new user's bearer rather than
  // writing as the second user.
  const second = await callAgent(appWindow, origins.agent, "signin");
  assert.notEqual(second, user);
  await until(async () => (await call(shop, "whoami")) === second);
  assert.equal(await call(appWindow, "whoami"), second);
  await assert.rejects(call(shop, "writeHeld", "as the first user"), /another user/);

  // Clearing the agent's store signs every app out.
  await callAgent(appWindow, origins.agent, "clearStore");
  await until(async () => (await state(appWindow)) === "signed-out" && (await state(shop)) === "signed-out");
  assert.equal(await callAgent(shop, origins.agent, "hasSession"), false);

  console.log("PASS: one in-frame sign-in signs in every allowlisted same-site origin");
}

const timeout = setTimeout(() => { console.error("SSO agent tests timed out"); app.exit(1); }, 300000);
app.on("window-all-closed", () => {});
app.whenReady().then(scenario).then(() => {
  clearTimeout(timeout);
  servers.forEach((server) => server.close());
  app.exit(0);
}).catch((error) => {
  console.error(error);
  clearTimeout(timeout);
  for (const window of windows) if (!window.isDestroyed()) window.destroy();
  servers.forEach((server) => server.close());
  app.exit(1);
});
