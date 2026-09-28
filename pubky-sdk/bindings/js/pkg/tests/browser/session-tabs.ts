// Each Electron window loads its own SDK instance against shared browser storage.
import { Pubky, Keypair, PublicKey, Session, AuthFlowKind } from "../../index.js";
import { createSignupToken } from "../utils.js";

const sdk = Pubky.testnet();
const store = sdk.browserSessionStore;
let current: Session;
let savedId: string;
let exchanges = 0;
let hideSlots = false;
let loseExchange = false;
let loseLogout = false;
let failPersist = false;
let holdWrite = false;
let holdExchange = false;
let releaseFetch: (() => void) | undefined;
const changes: unknown[] = [];
addEventListener("pubky-session-changed", event => changes.push((event as CustomEvent).detail));

const realPut = IDBObjectStore.prototype.put;
IDBObjectStore.prototype.put = function(value, key) {
  if (failPersist && value.sharedSession && !value.sharedSession.refresh_pending) {
    failPersist = false;
    throw new DOMException("Simulated persistence failure", "QuotaExceededError");
  }
  return key === undefined ? realPut.call(this, value) : realPut.call(this, value, key);
};
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const request = input instanceof Request ? input : new Request(input, init);
  if (hideSlots && new URL(request.url).pathname === "/info") {
    const response = Response.json({ features: [] });
    Object.defineProperty(response, "url", { value: request.url });
    return response;
  }
  if (holdWrite && request.method === "PUT") {
    holdWrite = false;
    await new Promise<void>(resolve => { releaseFetch = resolve; });
  }
  const response = await realFetch(input, init);
  if (new URL(request.url).pathname === "/auth/grant/session" && response.ok) {
    if (request.method === "POST") {
      exchanges++;
      if (holdExchange) {
        holdExchange = false;
        await new Promise<void>(resolve => { releaseFetch = resolve; });
      }
      if (loseExchange) {
        loseExchange = false;
        throw new TypeError("Simulated lost exchange response");
      }
    }
    if (request.method === "DELETE" && loseLogout) {
      loseLogout = false;
      throw new TypeError("Simulated lost logout response");
    }
  }
  return response;
};

async function record(update?: (value: any) => any) {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open("pubky-auth");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise<any>((resolve, reject) => {
      const tx = db.transaction("storedSessions", update ? "readwrite" : "readonly");
      const records = tx.objectStore("storedSessions");
      const request = records.get(savedId);
      let value: any;
      request.onsuccess = () => {
        value = request.result;
        if (update) records.put(update(value));
      };
      tx.oncomplete = () => resolve(value);
      tx.onerror = tx.onabort = () => reject(tx.error);
    });
  } finally { db.close(); }
}
async function identity() { return (await current.grant!.sessionInfo()).sessionId; }

const tabs = {
  async create(delegated = false) {
    const signer = sdk.signer(Keypair.random());
    await signer.signup(PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo"), await createSignupToken());
    if (delegated) {
      const flow = await sdk.startGrantAuthFlow("/pub/tabs.test/:rw", AuthFlowKind.signin(), {
        clientId: "tabs.test", relay: "http://localhost:15412/inbox",
      });
      await signer.approveAuthRequest(flow.authorizationUrl);
      current = await flow.awaitApproval();
    } else {
      current = await signer.signin("tabs.test");
    }
    const storage = current.storage;
    const saved = await store.save(current);
    savedId = saved.id;
    await storage.putText("/pub/tabs.test/before-save-handle", "ok");
    return { id: saved.id, slot: await identity() };
  },
  async restore(id: string) {
    savedId = id;
    current = await store.restore(id);
    return identity();
  },
  async restoreWithoutSlots() {
    hideSlots = true;
    try { await Pubky.testnet().browserSessionStore.restore(savedId); }
    finally { hideSlots = false; }
  },
  async restoreTogether(id: string) {
    const sessions = await Promise.all([store.restore(id), store.restore(id), store.restore(id)]);
    await current.storage.putText("/pub/tabs.test/original-handle", "ok");
    await Promise.all(sessions.map(session => session.storage.putText("/pub/tabs.test/concurrent", "ok")));
    return identity();
  },
  async write() { await current.storage.putText("/pub/tabs.test/value", "ok"); },
  async logout() { await current.signout(); },
  async remove() { await store.remove(savedId); },
  async forgetAll() { await store.clearAll(); },
  async expire() {
    await record(value => {
      value.sharedSession.response.session.token_expires_at = 0;
      return value;
    });
  },
  async staleBearer() {
    await record(value => {
      value.sharedSession.response.token = "invalid-cached-bearer";
      return value;
    });
  },
  async shared() {
    const value = await record();
    return value?.sharedSession && {
      slot: value.sharedSession.response.session.session_id,
      pending: value.sharedSession.refresh_pending,
      logout: value.sharedSession.logout_pending,
    };
  },
  async exportRecord() {
    const value = await record();
    delete value.sharedSession;
    return value;
  },
  async importRecord(value: any) {
    savedId = value.id;
    await store.isAvailable();
    await record(() => value);
    return tabs.restore(savedId);
  },
  loseNext() { loseExchange = true; },
  loseLogout() { loseLogout = true; },
  failNextPersist() { failPersist = true; },
  holdWrite() { holdWrite = true; },
  holdExchange() { holdExchange = true; },
  held() { return !!releaseFetch; },
  release() { releaseFetch?.(); releaseFetch = undefined; },
  exchangeCount() { return exchanges; },
  changes() { return changes; },
};
Object.assign(globalThis, { tabs });
