// Loaded in separate Electron browser windows by scripts/session-tabs.cjs.
import { Pubky, Keypair, PublicKey, Session, AuthFlowKind } from "../../index.js";
import { createSignupToken } from "../utils.js";

const sdk = Pubky.testnet();
const store = sdk.browserSessionStore;
let current: Session;
let expireNextExchange = false;
let loseNextExchange = false;
let exchanges = 0;
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const request = input instanceof Request ? input : new Request(input, init);
  const response = await realFetch(input, init);
  if (request.method === "POST" && new URL(request.url).pathname === "/auth/grant/session" && response.ok) {
    exchanges++;
    if (loseNextExchange) {
      loseNextExchange = false;
      throw new TypeError("Simulated lost exchange response");
    }
    if (expireNextExchange) {
      expireNextExchange = false;
      const body = await response.json();
      // Model a cached bearer reaching expiry, without changing the PoP clock.
      body.session.token_expires_at = 0;
      const expired = new Response(JSON.stringify(body), { status: response.status, headers: response.headers });
      Object.defineProperty(expired, "url", { value: response.url });
      return expired;
    }
  }
  return response;
};

async function identity() {
  const info = await current.grant!.sessionInfo();
  return info.sessionId;
}

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
    const saved = await store.save(current);
    return { id: saved.id, slot: await identity() };
  },
  async restore(id: string) {
    current = await store.restore(id);
    return identity();
  },
  async restoreTogether(id: string) {
    const sessions = await Promise.all([store.restore(id), store.restore(id), store.restore(id)]);
    await current.storage.putText("/pub/tabs.test/original-handle", "ok");
    for (const session of sessions) await session.storage.putText("/pub/tabs.test/concurrent", "ok");
    current = sessions[0];
    return identity();
  },
  async write() { await current.storage.putText("/pub/tabs.test/value", "ok"); },
  async logout() { await current.signout(); },
  expireNext() { expireNextExchange = true; },
  loseNext() { loseNextExchange = true; },
  exchangeCount() { return exchanges; },
};
Object.assign(globalThis, { tabs });
