// Pages for the redirect sign-in harness. Every origin loads this bundle: the
// Accounts origin holds a parent grant, and each app origin signs in through it.
// `scripts/redirect-flow.mjs` drives the pages with real HTTPS navigation.
import {
  AuthFlowKind,
  ChildGrantRequest,
  Pubky,
  type Capabilities,
  type GrantAuthFlow,
  type Path,
  type RedirectAuthResult,
  type Session,
} from "../../index.js";

const CALLBACK_PREFIX = "/auth/callback";
const root = document.documentElement.dataset;
const sdk = Pubky.testnet();

// The callback page finishes the sign-in first, so nothing below sees the fragment.
let completion: Promise<RedirectAuthResult> | undefined;
if (root.role === "app" && location.pathname.startsWith(CALLBACK_PREFIX)) {
  completion = sdk.completeRedirectAuthFlow();
}
const hashAfterCapture = location.hash;

// Faults the test arms on this origin before a navigation. Each fires once.
function takeFault(name: string): boolean {
  if (localStorage.getItem(`fault:${name}`) === null) return false;
  localStorage.removeItem(`fault:${name}`);
  return true;
}
const realFetch = globalThis.fetch;
let releaseExchange: (() => void) | undefined;
globalThis.fetch = async (input, init) => {
  const request = input instanceof Request ? input : new Request(input, init);
  const isSession = new URL(request.url).pathname === "/auth/grant/session";
  if (isSession && request.method === "DELETE" && takeFault("failLogout")) {
    throw new TypeError("Simulated failed sign-out request");
  }
  const url = new URL(request.url);
  const response = url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname)
    ? await realFetch(`${location.origin}/testnet/${url.port}${url.pathname}${url.search}`, {
      method: request.method,
      headers: request.headers,
      // Firefox reads request bytes but doesn't expose Request.body.
      body: ["GET", "HEAD"].includes(request.method) ? undefined : await request.arrayBuffer(),
      credentials: request.credentials,
      signal: request.signal,
    })
    : await realFetch(input, init);
  if (isSession && request.method === "POST" && response.ok && takeFault("holdExchange")) {
    await new Promise<void>(resolve => { releaseExchange = resolve; });
    releaseExchange = undefined;
  }
  if (isSession && request.method === "POST" && response.ok && takeFault("loseExchange")) {
    throw new TypeError("Simulated lost exchange response");
  }
  return response;
};
const realPut = IDBObjectStore.prototype.put;
IDBObjectStore.prototype.put = function (value: any, key?: IDBValidKey) {
  if (this.name === "storedSessions" && value?.version === "pubky-session-v3" && value?.sharedSession && takeFault("failCommit")) {
    throw new DOMException("Simulated persistence failure", "QuotaExceededError");
  }
  return key === undefined ? realPut.call(this, value) : realPut.call(this, value, key);
};

function describeError(error: any) {
  return { name: error?.name, message: String(error?.message ?? error), data: error?.data ?? null };
}

async function capture<T>(promise: Promise<T>) {
  try {
    return { ok: true as const, value: await promise };
  } catch (error) {
    return { ok: false as const, error: describeError(error) };
  }
}

function hex(bytes: Uint8Array) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

/** Read records straight from IndexedDB, as the browser stores them. */
async function rawStore(store: string, key?: string) {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open("pubky-auth");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise<any>((resolve, reject) => {
      const tx = db.transaction(store);
      const request = key === undefined ? tx.objectStore(store).getAll() : tx.objectStore(store).get(key);
      tx.oncomplete = () => resolve(request.result);
      tx.onerror = () => reject(tx.error);
    });
  } finally { db.close(); }
}

// --- Accounts ---

const catalog: Record<string, string[]> = JSON.parse(root.catalog ?? "{}");
let parentFlow: GrantAuthFlow | undefined;

async function handleAuthorize() {
  let request: ChildGrantRequest;
  try {
    request = ChildGrantRequest.parse(location.href);
  } catch {
    document.body.dataset.state = "invalid-request";
    return;
  }
  const allowed = catalog[request.clientId];
  // Never redirect to a callback outside the catalog.
  if (!allowed) {
    document.body.dataset.state = "unknown-app";
    return;
  }
  if (!request.capabilities.every(cap => allowed.includes(cap))) {
    location.replace(request.declinedUrl("access_denied"));
    return;
  }
  const [saved] = await sdk.parentGrantStore.list();
  const parent = await sdk.parentGrantStore.restore(saved.id);
  try {
    location.replace(await parent.issueChild(request));
  } catch (error: any) {
    if (!error?.data?.denial) throw error;
    location.replace(request.declinedUrl(error.data.denial));
  }
}

const accounts = {
  async startParent() {
    parentFlow = await sdk.startGrantAuthFlow(
      "/pub/:rwe,/priv/:rwe" as Capabilities,
      AuthFlowKind.signin(),
      { clientId: root.parentClient!, relay: "http://localhost:15412/inbox", parentGrant: true },
    );
    return parentFlow.authorizationUrl;
  },
  async finishParent() {
    const parent = await parentFlow!.awaitParentGrant();
    return { id: (await sdk.parentGrantStore.save(parent)).id, capabilities: parent.capabilities };
  },
  /** Answer one request twice, as a holder replaying it would, without navigating. */
  async issueTwice(authorizationUrl: string) {
    const request = ChildGrantRequest.parse(authorizationUrl);
    const [saved] = await sdk.parentGrantStore.list();
    const parent = await sdk.parentGrantStore.restore(saved.id);
    return [await parent.issueChild(request), await parent.issueChild(request)];
  },
};

if (root.role === "accounts" && location.pathname === "/authorize") {
  handleAuthorize().catch(error => {
    document.body.dataset.state = "failed";
    document.body.dataset.error = String(error?.message ?? error);
  });
}

// --- Apps ---

const callbackUrl = `${location.origin}${CALLBACK_PREFIX}`;
let current: Session | undefined;

function keysOf(session: Session) {
  return session.grant!.encryptionKeys!;
}

async function aesKey(path: string) {
  const bytes = keysOf(current!).deriveForPath(path);
  try {
    return await crypto.subtle.importKey("raw", bytes as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
  } finally { bytes.fill(0); }
}

const app = {
  /** Start a sign-in; the test navigates to the returned URL. */
  async start(capabilities: string, options: { callbackUrl?: string; accountsUrl?: string } = {}) {
    const request = await sdk.startRedirectAuthFlow(capabilities as Capabilities, {
      accountsUrl: options.accountsUrl ?? root.accounts!,
      callbackUrl: options.callbackUrl ?? callbackUrl,
    });
    return { authorizationUrl: request.authorizationUrl, status: request.status, expiresAt: request.expiresAt };
  },
  /** Start a sign-in and navigate the way an app does. */
  async signIn(capabilities: string) {
    const request = await sdk.startRedirectAuthFlow(capabilities as Capabilities, {
      accountsUrl: root.accounts!, callbackUrl,
    });
    setTimeout(() => location.assign(request.authorizationUrl));
  },
  async result() {
    if (!completion) throw new Error("This page didn't complete a sign-in.");
    const outcome = await capture(completion);
    if (!outcome.ok) return { ok: false, error: outcome.error, hashAfterCapture, href: location.href };
    const { session, storedSession } = outcome.value;
    current = session;
    return {
      ok: true,
      hashAfterCapture,
      href: location.href,
      id: storedSession.id,
      clientId: storedSession.clientId,
      grantId: await session.grant!.grantId(),
      scopes: keysOf(session).scopes,
    };
  },
  pending: async () => {
    const request = await sdk.redirectAuthFlow(callbackUrl);
    return request && { status: request.status, authorizationUrl: request.authorizationUrl };
  },
  resume: async () => {
    const { session, storedSession } = await sdk.resumeRedirectAuthFlow(callbackUrl);
    current = session;
    return { id: storedSession.id, grantId: await session.grant!.grantId() };
  },
  cancel: () => sdk.cancelRedirectAuthFlow(callbackUrl),
  async restore(id: string) {
    current = await sdk.browserSessionStore.restore(id);
    return { grantId: await current.grant!.grantId(), scopes: keysOf(current).scopes };
  },
  restoreKeys: async (id: string) => (await sdk.browserSessionStore.restoreEncryptionKeys(id))?.scopes,
  list: async () => (await sdk.browserSessionStore.list()).map(info => info.id),
  write: (path: string) => current!.storage.putText(path as Path, "hi"),
  keyHex(path: string) {
    const bytes = keysOf(current!).deriveForPath(path);
    try { return hex(bytes); } finally { bytes.fill(0); }
  },
  canDerive(path: string) {
    try {
      keysOf(current!).deriveForPath(path).fill(0);
      return true;
    } catch {
      return false;
    }
  },
  async encrypt(path: string, text: string) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(path), new TextEncoder().encode(text));
    await current!.storage.putBytes(path as Path, new Uint8Array([...iv, ...new Uint8Array(sealed)]));
  },
  async decrypt(path: string) {
    const sealed = await current!.storage.getBytes(path as Path);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.slice(0, 12) }, await aesKey(path), sealed.slice(12));
    return new TextDecoder().decode(plain);
  },
  signOut: () => current!.signout(),
  remove: (id: string) => sdk.browserSessionStore.remove(id),
  clear: () => sdk.browserSessionStore.clear(),
  clearAll: () => sdk.browserSessionStore.clearAll(),
  exchangeHeld: () => releaseExchange !== undefined,
  releaseExchange: () => releaseExchange?.(),
  /** Save the in-memory session again, as a stale tab would. */
  save: async () => (await sdk.browserSessionStore.save(current!)).id,
  arm: (fault: string) => localStorage.setItem(`fault:${fault}`, "1"),
  rawFlow: () => rawStore("redirectFlows", callbackUrl),
  rawSession: (id: string) => rawStore("storedSessions", id),
  rawKeyIds: async () => (await rawStore("delegatedGrantKeys")).map((key: any) => key.keyId),
};

const harness = { accounts, app, capture: <T>(promise: Promise<T>) => capture(promise) };
Object.assign(globalThis, { harness });
