// One browser profile, five origins: the R1 acceptance test for the session
// agent. Approve once on the agent origin, then every allowlisted same-site
// origin is signed in with zero interaction and no grant exchange of its own.
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

const bundle = readFileSync(join(__dirname, "../dist/session-agent.bundle.js"));
const servers = [];
const windows = [];

async function serve(hostname) {
  const server = createServer((req, res) => {
    res.setHeader("Content-Type", req.url === "/bundle.js" ? "text/javascript" : "text/html");
    res.end(req.url === "/bundle.js" ? bundle : '<!doctype html><script src="/bundle.js"></script>');
  });
  servers.push(server);
  server.listen(0);
  await once(server, "listening");
  return `http://${hostname}:${server.address().port}`;
}

function call(window, method, ...args) {
  return window.webContents.executeJavaScript(`(async () => {
    try { return { ok: true, value: await harness.${method}(...${JSON.stringify(args)}) }; }
    catch (error) { return { ok: false, error: error.message || String(error) }; }
  })()`, true).then((result) => {
    if (!result.ok) throw new Error(`${method}: ${result.error}`);
    return result.value;
  });
}

async function open(url) {
  const window = new BrowserWindow({ show: false, webPreferences: {
    nodeIntegration: false, contextIsolation: true, partition: "pubky-session-agent-test",
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
  for (let i = 0; i < 100; i++) {
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
  const allowed = [origins.app, origins.shop, origins.crossSite];
  const agentUrl = `${origins.agent}/agent?allow=${encodeURIComponent(allowed.join(","))}`;
  const appUrl = (origin) => `${origin}/app?agent=${encodeURIComponent(agentUrl)}`;
  const port = (origin) => new URL(origin).port;

  // Fresh profile: nobody is signed in anywhere.
  let appWindow = await open(appUrl(origins.app));
  assert.deepEqual(await call(appWindow, "ready"), { user: undefined });

  // Approve once, on the agent origin.
  const agent = await open(agentUrl);
  assert.equal(await call(agent, "hasSession"), false);
  const user = await call(agent, "signin");

  // The first app is signed in on reload with no prompt and no exchange of its own.
  appWindow.destroy();
  appWindow = await open(appUrl(origins.app));
  assert.deepEqual(await call(appWindow, "ready"), { user });
  await call(appWindow, "write", "hello from app");
  assert.equal((await call(appWindow, "counts")).exchanges, 0, "apps never exchange a grant");

  // A second origin is signed in with zero interaction and shares the data.
  const shop = await open(appUrl(origins.shop));
  assert.deepEqual(await call(shop, "ready"), { user });
  assert.equal(await call(shop, "read", port(origins.app)), "hello from app");
  await call(shop, "write", "hello from shop");
  assert.equal(await call(appWindow, "read", port(origins.shop)), "hello from shop");
  assert.equal((await call(shop, "counts")).exchanges, 0);

  // One grant backs every app.
  assert.equal(await call(agent, "grantCount"), 1);

  // The agent rotates its bearer; each app recovers from the 401 with one retry.
  // Public reads succeed with a stale bearer, so writes are what show the retry.
  await call(agent, "rotate");
  await call(appWindow, "write", "after rotation");
  assert.deepEqual(await call(appWindow, "counts"), { exchanges: 0, unauthorized: 1 });
  await call(shop, "write", "shop after rotation");
  assert.deepEqual(await call(shop, "counts"), { exchanges: 0, unauthorized: 1 });
  assert.equal(await call(appWindow, "read", port(origins.shop)), "shop after rotation");

  // A same-site origin that is not allowlisted is refused.
  const uninvited = await open(appUrl(origins.uninvited));
  assert.match((await call(uninvited, "ready")).error, /may not use this session agent/);

  // A cross-site embedder gets a partitioned, empty agent.
  const crossSite = await open(appUrl(origins.crossSite));
  assert.deepEqual(await call(crossSite, "ready"), { user: undefined });

  // Another tab of the first app shares the session.
  const tab = await open(appUrl(origins.app));
  assert.deepEqual(await call(tab, "ready"), { user });
  assert.equal((await call(tab, "counts")).exchanges, 0);

  // Signing out from one app revokes the grant for every app, and the agent
  // page learns about it through the browser store.
  await call(shop, "signout");
  await until(async () => !(await call(agent, "hasSession")));
  await assert.rejects(call(appWindow, "write", "after signout"));
  appWindow.destroy();
  appWindow = await open(appUrl(origins.app));
  assert.deepEqual(await call(appWindow, "ready"), { user: undefined });

  console.log("PASS: one approval on the agent signs in every allowlisted same-site origin");
}

const timeout = setTimeout(() => { console.error("Session agent tests timed out"); app.exit(1); }, 300000);
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
