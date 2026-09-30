// Real browser contexts share IndexedDB but have separate JS memory.
const { app, BrowserWindow } = require("electron");
const { createServer } = require("node:http");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const assert = require("node:assert/strict");
const { once } = require("node:events");

const bundle = readFileSync(join(__dirname, "../dist/session-tabs.bundle.js"));
const windows = [];
const server = createServer((req, res) => {
  res.setHeader("Content-Type", req.url === "/bundle.js" ? "text/javascript" : "text/html");
  res.end(req.url === "/bundle.js" ? bundle : '<!doctype html><script src="/bundle.js"></script>');
});
let base;
function call(window, method, ...args) {
  return window.webContents.executeJavaScript(`(async () => {
    try { return { ok: true, value: await tabs.${method}(...${JSON.stringify(args)}) }; }
    catch (error) { return { ok: false, error: error.message || String(error) }; }
  })()`, true).then(result => {
    if (!result.ok) throw new Error(`${method}: ${result.error}`);
    return result.value;
  });
}
async function windowAtOrigin() {
  const window = new BrowserWindow({ show: false, webPreferences: {
    nodeIntegration: false, contextIsolation: true, partition: "pubky-session-tabs-test",
  }});
  windows.push(window);
  window.webContents.on("console-message", event => {
    if (event.level === "error") console.error(String(event.message).slice(0, 1200));
  });
  await window.loadURL(base);
  return window;
}
async function reload(window) {
  const loaded = once(window.webContents, "did-finish-load");
  window.reload();
  await loaded;
}
async function until(check) {
  for (let i = 0; i < 100; i++) {
    if (await check()) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error("Browser condition did not settle");
}
async function scenario(delegated) {
  let a = await windowAtOrigin();
  const { id, slot } = await call(a, "create", delegated);
  const b = await windowAtOrigin();
  assert.equal(await call(b, "restore", id), slot);
  assert.equal(await call(b, "exchangeCount"), 0, "restore reuses a valid bearer");
  await assert.rejects(call(b, "restoreWithoutSlots"), /does not advertise grant-session-slots/);
  assert.equal(await call(b, "exchangeCount"), 0, "unsupported restore does not issue a bearer");
  await Promise.all([call(a, "write"), call(b, "write")]);
  assert.equal(await call(a, "restoreTogether", id), slot);

  // Revalidation distinguishes rejected credentials from transient refresh failures.
  for (const [status, error] of [
    [0, /HTTP transport error/],
    [429, /429 Too Many Requests/],
    [500, /500 Internal Server Error/],
    [401, /Browser session is no longer valid/],
    [404, /Browser session is no longer valid/],
  ]) {
    await call(a, "expire");
    await call(a, "failExchange", status);
    await assert.rejects(call(a, "restore", id), error);
    assert.equal(await call(a, "restore", id), slot);
  }

  // With a one-slot cap, even one extra allocation fails.
  for (let i = 0; i < 3; i++) {
    const tab = await windowAtOrigin();
    assert.equal(await call(tab, "restore", id), slot);
    assert.equal(await call(tab, "exchangeCount"), 0);
    await call(tab, "write");
    tab.destroy();
  }
  await reload(a);
  assert.equal(await call(a, "restore", id), slot);
  assert.equal(await call(a, "exchangeCount"), 0);

  // Ordinary writes share the lock; a refresh waits for an in-flight write.
  await call(a, "holdWrite");
  const write = call(a, "write");
  await until(() => call(a, "held"));
  await call(b, "write");
  await call(b, "expire");
  const before = await call(b, "exchangeCount");
  let finished = false;
  const refresh = call(b, "write").then(() => { finished = true; });
  await new Promise(resolve => setTimeout(resolve, 100));
  assert.equal(finished, false);
  assert.equal(await call(b, "exchangeCount"), before);
  await call(a, "release");
  await Promise.all([write, refresh]);
  assert.equal(await call(b, "exchangeCount"), before + 1);
  await call(a, "write");

  // Tabs competing to refresh send just one exchange.
  await call(a, "expire");
  const counts = await Promise.all([call(a, "exchangeCount"), call(b, "exchangeCount")]);
  await Promise.all([call(a, "write"), call(b, "write")]);
  assert.equal((await call(a, "exchangeCount")) + (await call(b, "exchangeCount")), counts[0] + counts[1] + 1);

  for (const failure of ["loseNext", "failNextPersist"]) {
    await call(a, "expire");
    await call(a, failure);
    await assert.rejects(call(a, "write"));
    assert.equal((await call(b, "shared")).pending, true);
    await call(b, "write");
    assert.equal((await call(b, "shared")).pending, false);
    assert.equal((await call(b, "shared")).slot, slot);
    await call(a, "write");
  }

  await call(a, "staleBearer");
  await call(b, "write");
  await call(a, "write");

  // The server accepted a refresh, but its tab disappears before persisting it.
  await call(a, "expire");
  await call(a, "holdExchange");
  call(a, "write").catch(() => {});
  await until(() => call(a, "held"));
  a.destroy();
  await call(b, "write");
  assert.equal((await call(b, "shared")).pending, false);
  a = await windowAtOrigin();
  assert.equal(await call(a, "restore", id), slot);

  // A different origin cannot borrow the first origin's bearer or slot.
  if (!delegated) {
    const other = await windowAtOrigin();
    await other.loadURL(base.replace("127.0.0.1", "localhost"));
    await assert.rejects(call(other, "importRecord", await call(a, "exportRecord")), /409/);
    const otherGrant = await call(other, "create");
    assert.notEqual(otherGrant.id, id);
    await Promise.all([call(other, "write"), call(a, "write")]);
    await call(other, "logout");
    other.destroy();
  }

  // A lost logout response blocks restoration, then retries revocation on reload.
  await call(a, "expire");
  await call(a, "loseLogout");
  await assert.rejects(call(a, "logout"));
  assert.equal((await call(b, "shared")).logout, true);
  await assert.rejects(call(b, "write"));
  await reload(a);
  await assert.rejects(call(a, "restore", id));
  assert.equal(await call(b, "shared"), undefined);
  await until(async () => (await call(b, "changes")).some(change => change.id === id && change.action === "removed"));
  await assert.rejects(call(b, "write"));

  // Forgetting persistence stops saved handles without revoking unrelated grants.
  const second = await call(a, "create", delegated);
  await call(b, "restore", second.id);
  await call(a, "remove");
  await assert.rejects(call(b, "write"));
  await assert.rejects(call(b, "restore", second.id));
  assert.equal(await call(b, "shared"), undefined);
  await call(b, "logout");
  const third = await call(a, "create", delegated);
  await call(b, "restore", third.id);
  await call(a, "forgetAll");
  await assert.rejects(call(b, "write"));
  await assert.rejects(call(b, "restore", third.id));
  await call(b, "logout");

  const revoked = await call(a, "create", delegated);
  await call(b, "restore", revoked.id);
  await call(a, "revoke");
  await assert.rejects(call(b, "restore", revoked.id), /Browser session is no longer valid/);
  await call(a, "expire");
  await assert.rejects(call(b, "restore", revoked.id), /Browser session is no longer valid/);
  await call(a, "logout");
  await call(b, "logout");
  await call(a, "logout");

  const concurrent = await call(a, "create", delegated);
  await call(b, "restore", concurrent.id);
  await Promise.all([call(a, "logout"), call(b, "logout")]);
  assert.equal(await call(b, "shared"), undefined);
  await Promise.all([call(a, "logout"), call(b, "logout")]);
  await assert.rejects(call(a, "write"));
  await assert.rejects(call(b, "write"));
  a.destroy(); b.destroy();
  console.log(`PASS ${delegated ? "delegated" : "local secret"}: shared slot, tab reopen/reload, concurrent writes/refresh, interrupted exchanges, logout, removal`);
}

const timeout = setTimeout(() => { console.error("Browser session tests timed out"); app.exit(1); }, 300000);
app.on("window-all-closed", () => {});
app.whenReady().then(async () => {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  base = `http://127.0.0.1:${server.address().port}`;
  await scenario(false);
  await scenario(true);
}).then(() => {
  clearTimeout(timeout); server.close(); app.exit(0);
}).catch(error => {
  console.error(error); clearTimeout(timeout);
  for (const window of windows) if (!window.isDestroyed()) window.destroy();
  server.close(); app.exit(1);
});
