import test from "tape";
import { Keypair, Pubky, PublicKey, type GrantRevocation } from "../index.js";
import { createSignupToken, assertPubkyError } from "./utils.js";

const HOMESERVER = PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo");
const PATH = "/auth/grant/session-revocation";
function operationId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function sessionFixture() {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  await signer.signup(HOMESERVER, await createSignupToken());
  const session = await signer.signin("captured.test");
  return { sdk, signer, session, grant: session.grant! };
}
function receipt(operation: GrantRevocation) {
  return { disposition: "original_bearer_revoked_v1", operation_id: operation.operationId,
    homeserver: operation.homeserver, grant_id: operation.grantId,
    pubky: operation.pubky, client_id: operation.clientId };
}
function intercept(handler: (request: Request) => Promise<Response> | Response) {
  const upstream = globalThis.fetch;
  const seen: Request[] = [];
  let otherAuth = 0;
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === PATH) { seen.push(request); return handler(request); }
    if (path.startsWith("/auth/")) otherAuth++;
    return upstream(input, init);
  };
  return { seen, otherAuth: () => otherAuth, restore: () => { globalThis.fetch = upstream; } };
}

test("captured revocation: actual server acknowledgement, one-use and no local erasure", async t => {
  const { sdk, grant } = await sessionFixture();
  const secret = await grant.exportLocalSecret();
  const operation = await grant.prepareRevocation(operationId());
  const expected = receipt(operation);
  const promise = operation.execute();
  t.throws(() => operation.execute(), "a concurrent execution cannot reuse the consumed handle");
  const result = await promise;
  t.equal(result.operationId, expected.operation_id);
  t.equal(result.grantId, expected.grant_id);
  t.equal(result.pubky, expected.pubky);
  t.equal(result.clientId, expected.client_id);
  t.equal(result.homeserver, expected.homeserver);
  t.equal(result.disposition, expected.disposition);
  t.ok(await grant.exportLocalSecret() === secret, "caller still owns local cleanup");
  try { await sdk.restoreSession(secret); t.fail("revoked grant restored"); }
  catch (error) { assertPubkyError(t, error); t.equal(error.name, "RequestError"); }
  t.end();
});

test("captured revocation: rotation cannot adopt replacement authority", async t => {
  const { sdk, grant } = await sessionFixture();
  const operation = await grant.prepareRevocation(operationId());
  const replacement = await sdk.restoreSession(await grant.exportLocalSecret());
  const originalFetch = globalThis.fetch;
  const monitor = intercept(request => originalFetch(request));
  try {
    try { await operation.execute(); t.fail("stale authority acknowledged"); }
    catch (error) { assertPubkyError(t, error); t.equal(error.name, "RequestError"); }
    t.equal(monitor.seen.length, 1, "one SDK mutation attempt");
    t.equal(monitor.otherAuth(), 0, "no refresh call");
    await replacement.grant!.account();
    t.pass("replacement session survives old capture");
  } finally { monitor.restore(); }
  t.end();
});

test("captured revocation: strict request and receipt, no fallback on rejection", async t => {
  const { grant } = await sessionFixture();
  for (const mode of ["success", "empty", "mismatch", "unknown-field", "version", "401", "307", "overflow", "lost"]) {
    const operation = await grant.prepareRevocation(operationId());
    const valid = receipt(operation);
    let cancelled = false;
    const monitor = intercept(request => {
      t.equal(request.method, "POST");
      t.equal(request.redirect, "error", "reject redirects before forwarding bearer");
      t.equal(request.credentials, "omit", "ambient cookies are excluded");
      t.equal(request.headers.get("pubky-host"), valid.pubky);
      t.ok(request.headers.get("authorization")?.startsWith("Bearer "), "captured bearer present, not printed");
      if (mode === "401" || mode === "307") return new Response(null, { status: Number(mode), headers: { location: "/must-not-follow" } });
      if (mode === "empty") return new Response("");
      if (mode === "mismatch") valid.operation_id = operationId();
      if (mode === "unknown-field") Object.assign(valid, { extra: true });
      if (mode === "version") valid.disposition = "revoked_v2";
      if (mode === "overflow") return new Response(new ReadableStream({
        start(controller) { controller.enqueue(new Uint8Array(4097)); },
        cancel() { cancelled = true; },
      }));
      if (mode === "lost") return new Response(new ReadableStream({
        start(controller) { controller.enqueue(new TextEncoder().encode('{"disposition":')); controller.error(new Error("lost acknowledgement")); },
      }));
      return new Response(JSON.stringify(valid));
    });
    try {
      try {
        const result = await operation.execute();
        t.equal(mode, "success", "only complete matching receipt acknowledges success");
        t.equal(result.operationId, valid.operation_id);
      } catch (error) {
        t.notEqual(mode, "success");
        assertPubkyError(t, error);
        t.equal(error.message, "Captured grant revocation was not acknowledged");
        if (mode === "401" || mode === "307") t.equal((error.data as {statusCode: number}).statusCode, Number(mode));
      }
      t.equal(monitor.seen.length, 1, "no second invocation");
      t.equal(monitor.otherAuth(), 0, "no refresh/legacy cleanup");
      t.throws(() => operation.execute(), "failure never restores the handle");
      if (mode === "overflow") t.ok(cancelled, "bounded reader cancels oversized stream");
    } finally { monitor.restore(); }
  }
  t.end();
});

test("captured revocation: explicit cancellation before and after dispatch consumes handle", async t => {
  const { grant } = await sessionFixture();
  const controller = new AbortController();
  controller.abort();
  const operation = await grant.prepareRevocation(operationId());
  const early = intercept(() => { throw new Error("pre-aborted mutation sent"); });
  try {
    try { await operation.execute(controller.signal); t.fail("pre-aborted execution acknowledged"); }
    catch (error) { assertPubkyError(t, error); }
    t.equal(early.seen.length, 0, "no mutation Fetch call after pre-abort");
    t.throws(() => operation.execute(), "aborted operation stays consumed");
  } finally { early.restore(); }

  const lateController = new AbortController();
  const lateOperation = await grant.prepareRevocation(operationId());
  let entered!: () => void;
  const received = new Promise<void>(resolve => { entered = resolve; });
  const late = intercept(request => new Response(new ReadableStream({
    start(stream) {
      request.signal.addEventListener("abort", () => stream.error(new DOMException("aborted", "AbortError")), { once: true });
      stream.enqueue(new TextEncoder().encode('{"disposition":'));
      entered();
    },
  })));
  try {
    const promise = lateOperation.execute(lateController.signal);
    await received;
    lateController.abort();
    try { await promise; t.fail("partial cancelled response acknowledged"); }
    catch (error) { assertPubkyError(t, error); t.equal(error.message, "Captured grant revocation was not acknowledged"); }
    t.equal(late.seen.length, 1);
    t.equal(late.otherAuth(), 0);
    t.throws(() => lateOperation.execute(), "late abort stays consumed");
  } finally { late.restore(); }
  t.end();
});

function readSharedRecord(id: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("pubky-auth", 1);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction("storedSessions", "readonly");
      const read = tx.objectStore("storedSessions").get(id);
      read.onsuccess = () => resolve(read.result);
      read.onerror = () => reject(read.error);
      tx.oncomplete = () => db.close();
      tx.onabort = () => { db.close(); reject(tx.error); };
    };
  });
}

test("captured revocation: browser shared replacement is neither adopted nor removed", async t => {
  if (typeof indexedDB === "undefined") {
    t.comment("Shared-record case requires the browser run; not executed in Node");
    t.end(); return;
  }
  const { sdk, session, grant } = await sessionFixture();
  const store = sdk.browserSessionStore;
  const saved = await store.save(session);
  try {
    const original = await store.restore(saved.id);
    const operation = await original.grant!.prepareRevocation(operationId());
    const oldRecord = await readSharedRecord(saved.id);
    const replacement = await sdk.restoreSession(await grant.exportLocalSecret());
    await store.save(replacement);
    // Saving deliberately preserves the existing coordinated response. An
    // authenticated read refreshes that stale response before the test starts.
    await replacement.grant!.account();
    const before = await readSharedRecord(saved.id);
    const token = (record: unknown) => (record as { sharedSession: { response: { token: string } } }).sharedSession.response.token;
    t.ok(token(before) !== token(oldRecord), "fixture installs a genuinely newer shared bearer without printing it");
    const originalFetch = globalThis.fetch;
    const monitor = intercept(request => originalFetch(request));
    try {
      try { await operation.execute(); t.fail("adopted replacement bearer"); }
      catch (error) { assertPubkyError(t, error); t.equal(error.message, "Captured grant revocation was not acknowledged"); }
      t.equal(monitor.seen.length, 1);
      t.equal(monitor.otherAuth(), 0, "no shared refresh/exchange/legacy cleanup");
      // Compare only booleans so a failed assertion cannot print stored secrets.
      t.ok(JSON.stringify(await readSharedRecord(saved.id)) === JSON.stringify(before), "replacement record stays byte-equivalent");
    } finally { monitor.restore(); }
  } finally { await store.remove(saved.id); }
  t.end();
});
