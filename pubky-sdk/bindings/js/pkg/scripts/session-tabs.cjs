// Real browser contexts share IndexedDB but have separate JS memory/sessionStorage.
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
async function scenario(delegated) {
  const a = await windowAtOrigin();
  const { id, slot } = await call(a, "create", delegated);
  assert.ok(slot);
  const b = await windowAtOrigin();
  const bSlot = await call(b, "restore", id);
  assert.notEqual(slot, bSlot);
  await call(a, "write");
  await call(b, "write");
  const exchanges = await call(a, "exchangeCount");
  assert.equal(await call(a, "restoreTogether", id), slot);
  assert.equal(await call(a, "exchangeCount"), exchanges);

  // Opening through an opener copies its sessionStorage, just like tab duplication.
  a.webContents.setWindowOpenHandler(() => ({ action: "allow", overrideBrowserWindowOptions: { show: false } }));
  const opened = once(a.webContents, "did-create-window");
  await a.webContents.executeJavaScript("window.open(location.href); undefined", true);
  const [duplicate] = await opened;
  windows.push(duplicate);
  if (duplicate.webContents.isLoading()) await once(duplicate.webContents, "did-finish-load");
  assert.equal(await duplicate.webContents.executeJavaScript(
    `sessionStorage.getItem(${JSON.stringify(`pubky-session-slot:${id}`)})`
  ), slot, "opener sessionStorage was copied before SDK restore");
  const duplicateSlot = await call(duplicate, "restore", id);
  assert.notEqual(duplicateSlot, slot);
  assert.notEqual(duplicateSlot, bSlot);
  await call(a, "write");

  // More reloads than the default cap, while another tab keeps writing.
  for (let i = 0; i < 21; i++) {
    await reload(a);
    assert.equal(await call(a, "restore", id), slot);
    await call(a, "write");
    await call(b, "write");
  }
  await reload(a);
  await call(a, "loseNext");
  await assert.rejects(call(a, "restore", id));
  assert.equal(await call(a, "restore", id), slot);
  await call(b, "write");

  await reload(a);
  await call(a, "expireNext");
  await call(a, "restore", id);
  const beforeRefresh = await call(a, "exchangeCount");
  await call(a, "restoreTogether", id);
  await call(a, "write");
  assert.equal(await call(a, "exchangeCount"), beforeRefresh + 1);
  await call(b, "write");

  // Logout from a session with an expired cached bearer must revoke every slot.
  await reload(a);
  await call(a, "expireNext");
  await call(a, "restore", id);
  await call(a, "logout");
  await assert.rejects(call(b, "write"));
  await assert.rejects(call(duplicate, "write"));
  await assert.rejects(call(b, "restore", id));
  a.destroy(); b.destroy(); duplicate.destroy();
  console.log(`PASS ${delegated ? "delegated" : "local secret"}: independent tabs, duplicate, 21 reloads, concurrent restore, lost response, refresh, expired-bearer logout`);
}

const timeout = setTimeout(() => { console.error("Browser session tests timed out"); app.exit(1); }, 180000);
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
