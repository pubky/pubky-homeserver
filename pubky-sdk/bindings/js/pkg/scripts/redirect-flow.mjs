// Redirect sign-in across real HTTPS origins: Accounts holds a parent grant, and
// two apps sign in through it. Runs in Chromium, Firefox and WebKit against the
// static testnet. Ring is played by the SDK in Node, so its approvals can be counted.
//
// PUBKY_REDIRECT_BROWSERS picks browsers (default: all three). A browser whose
// build isn't installed fails the run unless PUBKY_REDIRECT_ALLOW_MISSING=1.
//
// Callback URLs carry encrypted approvals, so nothing here prints one.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer } from "node:https";
import { request as httpRequest } from "node:http";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import * as playwright from "playwright-core";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
require("../node-header.cjs");
const { GrantManager, Keypair, Pubky, PublicKey } = require("../index.cjs");

const HOMESERVER = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";
const CHAT_CAPS = "/pub/chat/:rw,/priv/chat/:rwe";
const certs = join(here, "../../../../src/client/test_certs");
const tls = { cert: readFileSync(join(certs, "server.pem")), key: readFileSync(join(certs, "server.key")) };
const bundle = readFileSync(join(here, "../dist/redirect-pages.bundle.js"));

/** An HTTPS origin that serves the page bundle for every path. */
async function origin() {
  const site = { attributes: {} };
  site.server = createServer(tls, (request, response) => {
    // Keep browser traffic HTTPS; WebKit blocks direct HTTP testnet requests.
    const proxy = request.url.match(/^\/testnet\/(6286|15411|15412)(\/.*)$/);
    if (proxy) {
      const upstream = httpRequest(`http://127.0.0.1:${proxy[1]}${proxy[2]}`, {
        method: request.method,
        headers: { ...request.headers, host: `127.0.0.1:${proxy[1]}` },
      }, incoming => {
        response.writeHead(incoming.statusCode, incoming.headers);
        incoming.pipe(response);
      });
      upstream.on("error", () => { response.writeHead(502); response.end(); });
      request.pipe(upstream);
      return;
    }
    if (request.url === "/bundle.js") {
      response.setHeader("Content-Type", "text/javascript");
      response.end(bundle);
      return;
    }
    const attributes = Object.entries(site.attributes)
      .map(([name, value]) => `data-${name}="${String(value).replaceAll("&", "&amp;").replaceAll('"', "&quot;")}"`)
      .join(" ");
    response.setHeader("Content-Type", "text/html");
    response.end(`<!doctype html><html ${attributes}><head><meta charset="utf-8"></head><body><script src="/bundle.js"></script></body></html>`);
  });
  site.server.listen(0, "localhost");
  await once(site.server, "listening");
  site.url = `https://localhost:${site.server.address().port}`;
  return site;
}

async function call(page, path, ...args) {
  const result = await page.evaluate(async ([path, args]) => {
    const [area, method] = path.split(".");
    try {
      return { ok: true, value: await globalThis.harness[area][method](...args) };
    } catch (error) {
      return { ok: false, error: { name: error?.name, message: String(error?.message ?? error), data: error?.data ?? null } };
    }
  }, [path, args]);
  if (!result.ok) {
    const error = new Error(`${path}: ${result.error.message}`);
    Object.assign(error, { pubky: result.error });
    throw error;
  }
  return result.value;
}

async function ready(page) {
  await page.waitForFunction(() => globalThis.harness !== undefined);
}

async function open(context, url) {
  const page = await context.newPage();
  await page.goto(url);
  await ready(page);
  return page;
}

/** Follow a URL to the app's callback page and read the sign-in result there. */
async function complete(page, url) {
  // Leave the current document, so a URL that differs only in its fragment loads anew.
  await page.goto("about:blank");
  await page.goto(url, { waitUntil: "commit" });
  await page.waitForURL(target => target.pathname.startsWith("/auth/callback"));
  await ready(page);
  return call(page, "app.result");
}

/** A failed result's denial code, or its reason. */
function reason(result) {
  return result.error?.data?.denial ?? result.error?.data?.reason;
}

function withFragment(url, change) {
  const parsed = new URL(url);
  const params = new URLSearchParams(parsed.hash.slice(1));
  change(params);
  parsed.hash = params.toString();
  return parsed.toString();
}

/** A signed-up user and their Ring, which counts its approvals. */
async function ring() {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  const token = await (await fetch("http://127.0.0.1:6288/generate_signup_token", {
    headers: { "X-Admin-Password": "admin" },
  })).text();
  await signer.signup(PublicKey.from(HOMESERVER), token);
  let approvals = 0;
  return {
    get approvals() { return approvals; },
    async approve(url, capabilities) {
      approvals++;
      await signer.approveAuthWithCapabilities(url, capabilities);
    },
    /** Active child grants for an app, as the homeserver lists them. */
    async children(callback) {
      const root = await signer.signin("redirect-harness.root");
      const grants = await new GrantManager(root).list();
      return grants.filter(grant => grant.kind === "child" && grant.clientId === callback).length;
    },
  };
}

async function scenario(browserType, origins) {
  const { accounts: ACCOUNTS, chat: CHAT, shop: SHOP } = origins;
  const CHAT_CALLBACK = `${CHAT}/auth/callback`;
  const SHOP_CALLBACK = `${SHOP}/auth/callback`;
  const browser = await browserType.launch();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const logs = [];
  context.on("page", page => {
    page.on("console", message => logs.push(message.text()));
    page.on("pageerror", error => logs.push(String(error)));
  });
  try {
    // One Ring approval gives Accounts a parent. The user shares keys for
    // `/priv/` only.
    const user = await ring();
    const accounts = await open(context, `${ACCOUNTS}/`);
    await user.approve(await call(accounts, "accounts.startParent"), "/pub/:rw,/priv/:rwe");
    await call(accounts, "accounts.finishParent");

    // Queue the first sign-in behind an upgrade held open by an older tab.
    const olderTab = await open(context, `${CHAT}/`);
    await olderTab.evaluate(() => new Promise((resolve, reject) => {
      const open = indexedDB.open("pubky-auth", 1);
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const db = open.result;
        addEventListener("pagehide", () => db.close(), { once: true });
        db.onversionchange = () => resolve();
        globalThis.harness.app.list().catch(reject);
      };
    }));
    let chat = await open(context, `${CHAT}/`);
    await assert.rejects(call(chat, "app.start", CHAT_CAPS), error =>
      error.pubky?.name === "ClientStateError" &&
      /key store timed out.*close or reload other tabs/i.test(error.pubky.message));
    await olderTab.close();
    let started = await call(chat, "app.start", CHAT_CAPS);

    // Starting again replaces an unanswered request, even from another tab.
    const pending = await call(chat, "app.rawFlow");
    assert.equal(pending.status, "awaitingCallback");
    assert.ok(!started.authorizationUrl.includes(pending.approvalKeySecret));
    const [superseded] = await call(accounts, "accounts.issueTwice", started.authorizationUrl);
    const restarting = await open(context, `${CHAT}/`);
    started = await call(restarting, "app.start", CHAT_CAPS);
    await restarting.close();
    const replacement = await call(chat, "app.rawFlow");
    assert.notEqual(replacement.state, pending.state);
    assert.notEqual(replacement.keyId, pending.keyId);
    assert.ok(!(await call(chat, "app.rawKeyIds")).includes(pending.keyId));
    const stale = await context.newPage();
    assert.equal((await complete(stale, superseded)).ok, false);
    await stale.close();
    assert.equal((await call(chat, "app.pending")).authorizationUrl, started.authorizationUrl);
    await assert.rejects(call(chat, "app.start", CHAT_CAPS, { callbackUrl: SHOP_CALLBACK }), /this page's origin/);

    // Chat signs in through real redirects, and the fragment is gone before
    // any other code runs.
    const signedIn = await complete(chat, started.authorizationUrl);
    assert.equal(signedIn.ok, true, JSON.stringify(signedIn.error));
    assert.equal(signedIn.hashAfterCapture, "");
    assert.ok(!signedIn.href.includes("#"));
    assert.deepEqual(signedIn.scopes, ["/priv/chat/"]);
    const chatId = signedIn.id;
    await call(chat, "app.write", "/pub/chat/hello");
    await call(chat, "app.encrypt", "/priv/chat/note", "secret note");
    const chatKey = await call(chat, "app.keyHex", "/priv/chat/note");
    const finished = await call(chat, "app.rawFlow");
    assert.equal(finished.status, "complete");
    for (const secret of ["approvalKeySecret", "signedApproval", "keyId", "authorizationUrl"]) {
      assert.ok(!(secret in finished), `a finished flow keeps no ${secret}`);
    }

    // A reload doesn't complete again; the saved session restores in this tab
    // and another one.
    await chat.reload();
    await ready(chat);
    assert.equal(reason(await call(chat, "app.result")), "RedirectCallbackMissing");
    await call(chat, "app.restore", chatId);
    assert.equal(await call(chat, "app.keyHex", "/priv/chat/note"), chatKey);
    const chatTab = await open(context, `${CHAT}/`);
    await call(chatTab, "app.restore", chatId);
    assert.equal(await call(chatTab, "app.decrypt", "/priv/chat/note"), "secret note");

    // Each app holds only its scopes: no sibling, ancestor or declined keys.
    for (const path of ["/priv/shop/order", "/priv/other", "/pub/chat/hello"]) {
      assert.equal(await call(chat, "app.canDerive", path), false, path);
    }

    // Invalid callbacks leave the request waiting; concurrent and repeated
    // callbacks can't select competing children.
    const shop = await open(context, `${SHOP}/`);
    const shopStart = await call(shop, "app.start", "/pub/shop/:rw");
    const [first, second] = await call(accounts, "accounts.issueTwice", shopStart.authorizationUrl);
    const approval = new URLSearchParams(new URL(first).hash.slice(1)).get("approval");
    const invalid = [
      withFragment(first, params => params.set("state", "other")),
      withFragment(first, params => params.set("approval", `${approval.slice(0, 40)}${approval[40] === "A" ? "B" : "A"}${approval.slice(41)}`)),
      withFragment(first, params => params.set("next", "/home")),
      first.replace("/auth/callback#", "/auth/callback/other#"),
      withFragment(second, params => params.set("approval", new URLSearchParams(
        new URL(started.authorizationUrl).search).get("epk"))),
    ];
    for (const url of invalid) {
      const page = await context.newPage();
      const result = await complete(page, url);
      assert.equal(result.ok, false);
      assert.ok(!result.error.message.includes(approval.slice(10, 50)), "errors never hold the approval");
      await page.close();
    }
    assert.equal((await call(shop, "app.pending")).status, "awaitingCallback");
    const tabs = await Promise.all([context.newPage(), context.newPage()]);
    const results = await Promise.all([complete(tabs[0], first), complete(tabs[1], second)]);
    const winners = results.filter(result => result.ok);
    assert.equal(winners.length, 1, JSON.stringify(results.map(reason)));
    const loser = results.find(result => !result.ok);
    assert.equal(reason(loser), "RedirectCallbackHandled", `${loser.error.name}: ${loser.error.message}`);
    assert.equal(reason(await complete(tabs[0], first)), "RedirectCallbackHandled");
    await Promise.all(tabs.map(tab => tab.close()));
    assert.deepEqual(winners[0].scopes, [], "storage-only approvals deliver no keys");
    await call(shop, "app.restore", winners[0].id);
    await call(shop, "app.write", "/pub/shop/order");
    assert.equal(await user.children(SHOP_CALLBACK), 1);

    // Keys the parent doesn't hold, or permissions outside the catalog, end
    // in an explicit denial and never in another Ring approval.
    for (const [caps, denial] of [["/pub/shop/:rwe", "insufficient_permissions"], ["/priv/shop/:rw", "access_denied"]]) {
      const request = await call(shop, "app.start", caps);
      const result = await complete(shop, request.authorizationUrl);
      assert.equal(reason(result), denial);
      assert.ok((await call(shop, "app.pending")) == null);
    }
    assert.equal(user.approvals, 1);

    // Signing out deletes the keys and approval at once. A failed revocation
    // keeps only what retrying needs, and stale handles can't bring them back.
    const beforeLogout = await call(chat, "app.start", CHAT_CAPS);
    const [afterLogout] = await call(accounts, "accounts.issueTwice", beforeLogout.authorizationUrl);
    await call(chat, "app.arm", "failLogout");
    await assert.rejects(call(chat, "app.signOut"));
    // Check fields without printing the record: it may hold secrets.
    const logoutOnly = await call(chat, "app.rawSession", chatId);
    assert.ok(!("signedApproval" in logoutOnly), "sign-out deleted the approval");
    assert.ok(logoutOnly.logoutPending === true, "the record is logout-only");
    assert.ok((await call(chat, "app.pending")) == null);
    const staleCallback = await context.newPage();
    assert.equal(reason(await complete(staleCallback, afterLogout)), "RedirectCallbackHandled");
    await staleCallback.close();
    await assert.rejects(call(chat, "app.restoreKeys", chatId), /signed out/);
    await assert.rejects(call(chatTab, "app.write", "/pub/chat/stale"));
    await assert.rejects(call(chatTab, "app.save"));
    await assert.rejects(call(chat, "app.restore", chatId), /signed out/);
    assert.ok((await call(chat, "app.rawSession", chatId)) === undefined, "the record is gone");
    assert.equal(await user.children(CHAT_CALLBACK), 0);
    await call(shop, "app.restore", winners[0].id);
    await call(shop, "app.write", "/pub/shop/after-chat-sign-out");

    // Signing in again restores the same keys. A lost exchange response and a
    // closed tab resume with the same child, without another approval.
    await call(chat, "app.arm", "loseExchange");
    const again = await call(chat, "app.start", CHAT_CAPS);
    assert.equal((await complete(chat, again.authorizationUrl)).ok, false);
    assert.equal((await call(chat, "app.pending")).status, "exchangePending");
    await assert.rejects(call(chat, "app.start", CHAT_CAPS), error =>
      error.pubky.data?.reason === "RedirectAuthFlowPending");
    await chat.close();
    chat = await open(context, `${CHAT}/auth/callback`);
    const resumed = await call(chat, "app.result");
    assert.equal(resumed.ok, true, JSON.stringify(resumed.error));
    assert.equal(await call(chat, "app.keyHex", "/priv/chat/note"), chatKey);
    assert.equal(await call(chat, "app.decrypt", "/priv/chat/note"), "secret note");
    assert.equal(await user.children(CHAT_CALLBACK), 1);

    // A failed save keeps the accepted child for an explicit resume.
    await call(chat, "app.arm", "failCommit");
    const retry = await call(chat, "app.start", CHAT_CAPS);
    assert.equal((await complete(chat, retry.authorizationUrl)).ok, false);
    assert.equal((await call(chat, "app.pending")).status, "exchangePending");
    await call(chat, "app.resume");
    assert.equal(await call(chat, "app.keyHex", "/priv/chat/note"), chatKey);
    assert.equal(await user.children(CHAT_CALLBACK), 1);

    // Cancelling before the callback deletes the request's keys, and a late
    // callback can't revive it. After the exchange may have happened,
    // cancelling revokes the child like a sign-out.
    const keysBefore = await call(shop, "app.rawKeyIds");
    const cancelled = await call(shop, "app.start", "/pub/shop/:rw");
    const flowKey = (await call(shop, "app.rawFlow")).keyId;
    const [late] = await call(accounts, "accounts.issueTwice", cancelled.authorizationUrl);
    await call(shop, "app.cancel");
    assert.ok((await call(shop, "app.pending")) == null);
    assert.ok(!(await call(shop, "app.rawKeyIds")).includes(flowKey));
    assert.deepEqual((await call(shop, "app.rawKeyIds")).sort(), keysBefore.sort());
    const lateTab = await context.newPage();
    assert.equal(reason(await complete(lateTab, late)), "RedirectCallbackHandled");
    await lateTab.close();
    await call(shop, "app.arm", "loseExchange");
    const interrupted = await call(shop, "app.start", "/pub/shop/:rw");
    assert.equal((await complete(shop, interrupted.authorizationUrl)).ok, false);
    await call(shop, "app.arm", "failLogout");
    await assert.rejects(call(shop, "app.cancel"), error => error.pubky.name === "RequestError");
    const cancelledChild = await call(shop, "app.rawFlow");
    assert.equal(cancelledChild.status, "cancelled");
    assert.ok((await call(shop, "app.list")).includes(cancelledChild.sessionId));

    // Old revocation failures don't block a new login; cleanup remains retryable.
    await call(shop, "app.arm", "failLogout");
    const afterCancellation = await call(shop, "app.start", "/pub/shop/:rw");
    const newSession = await complete(shop, afterCancellation.authorizationUrl);
    assert.equal(newSession.ok, true, JSON.stringify(newSession.error));
    assert.notEqual(newSession.id, cancelledChild.sessionId);
    const pendingLogout = await call(shop, "app.rawSession", cancelledChild.sessionId);
    assert.ok(pendingLogout.logoutPending && !pendingLogout.signedApproval);
    await assert.rejects(call(shop, "app.restore", cancelledChild.sessionId), error =>
      error.pubky.name === "RequestError");
    await assert.rejects(call(shop, "app.restore", cancelledChild.sessionId), /signed out/);
    assert.equal(await call(shop, "app.rawSession", cancelledChild.sessionId), undefined);
    await call(shop, "app.write", "/pub/shop/after-cleanup");
    assert.equal(await user.children(SHOP_CALLBACK), 1);
    await call(shop, "app.signOut");
    assert.equal(await user.children(SHOP_CALLBACK), 0);
    assert.deepEqual((await call(shop, "app.list")).filter(id => id !== winners[0].id), []);

    // Sign-out wins even after an exchange reached the homeserver.
    const logoutTab = await open(context, `${CHAT}/`);
    await call(logoutTab, "app.restore", await call(chat, "app.save"));
    await call(chat, "app.arm", "holdExchange");
    const racing = await call(chat, "app.start", CHAT_CAPS);
    const completing = complete(chat, racing.authorizationUrl);
    completing.catch(() => {});
    await chat.waitForFunction(() => globalThis.harness?.app.exchangeHeld());
    const signingOut = call(logoutTab, "app.signOut");
    signingOut.catch(() => {});
    let cancelledExchange;
    for (let attempt = 0; attempt < 100; attempt++) {
      cancelledExchange = await call(logoutTab, "app.rawFlow");
      if (cancelledExchange.status === "cancelled") break;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.equal(cancelledExchange.status, "cancelled");
    assert.ok(!cancelledExchange.signedApproval && !cancelledExchange.approvalKeySecret);
    const revoking = await call(logoutTab, "app.rawSession", cancelledExchange.sessionId);
    assert.ok(revoking.logoutPending && !revoking.signedApproval && !revoking.sharedSession);
    await call(chat, "app.releaseExchange");
    assert.equal((await completing).ok, false);
    await signingOut;
    assert.equal(await user.children(CHAT_CALLBACK), 0);
    await logoutTab.close();

    // Local removal also invalidates callbacks and their temporary keys.
    for (const action of ["remove", "clear", "clearAll"]) {
      const login = await call(chat, "app.start", CHAT_CAPS);
      const active = await complete(chat, login.authorizationUrl);
      assert.equal(active.ok, true);
      const waiting = await call(chat, "app.start", CHAT_CAPS);
      const pendingKey = (await call(chat, "app.rawFlow")).keyId;
      const [late] = await call(accounts, "accounts.issueTwice", waiting.authorizationUrl);
      await call(chat, `app.${action}`, active.id);
      assert.ok(!(await call(chat, "app.rawKeyIds")).includes(pendingKey));
      assert.equal((await complete(chat, late)).ok, false);
    }

    // Nothing logged an approval.
    for (const line of logs) {
      assert.ok(!line.includes(approval.slice(10, 50)) && !line.includes("approval="), "logs hold no approval");
    }
    return logs.length;
  } finally {
    await browser.close();
  }
}

const servers = [];
const timeout = setTimeout(() => {
  console.error("Redirect sign-in tests timed out");
  process.exit(1);
}, 600_000);
try {
  const [accounts, chat, shop] = await Promise.all([origin(), origin(), origin()]);
  servers.push(accounts.server, chat.server, shop.server);
  accounts.attributes = {
    role: "accounts",
    "parent-client": `${accounts.url}/auth/callback`,
    // Each app's exact callback and what it may request.
    catalog: JSON.stringify({
      [`${chat.url}/auth/callback`]: CHAT_CAPS.split(","),
      [`${shop.url}/auth/callback`]: ["/pub/shop/:rw", "/pub/shop/:rwe"],
    }),
  };
  for (const app of [chat, shop]) {
    app.attributes = { role: "app", accounts: `${accounts.url}/authorize` };
  }

  const names = (process.env.PUBKY_REDIRECT_BROWSERS ?? "chromium,firefox,webkit").split(",");
  const ran = [];
  for (const name of names) {
    const browserType = playwright[name];
    try {
      await scenario(browserType, { accounts: accounts.url, chat: chat.url, shop: shop.url });
    } catch (error) {
      const missing = /Executable doesn't exist/.test(String(error?.message));
      if (!missing || process.env.PUBKY_REDIRECT_ALLOW_MISSING !== "1") throw error;
      console.log(`SKIP ${name}: browser build not installed`);
      continue;
    }
    ran.push(name);
    console.log(`PASS ${name}: redirect sign-in, persistence, rejection, interruption, permissions, isolation, sign-out, re-authentication`);
  }
  assert.ok(ran.length > 0, "no browser ran");
  clearTimeout(timeout);
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  clearTimeout(timeout);
  for (const server of servers) server.close();
}
