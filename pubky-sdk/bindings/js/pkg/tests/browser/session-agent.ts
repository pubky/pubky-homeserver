// Each Electron window plays the agent or an app, chosen by its URL path.
// The agent's allowlist and the apps' agent URL arrive as query parameters.
import { AuthFlowKind, GrantManager, Keypair, Pubky, PublicKey, Session, Signer } from "../../index.js";
import { createSignupToken } from "../utils.js";

const sdk = Pubky.testnet();
const HOMESERVER = PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo");
const CLIENT_ID = "agent.test";
const NOTES = "/pub/agent.test/";
const query = new URLSearchParams(location.search);

// Requests made by this window's own realm; the agent iframe has its own.
const counts = { exchanges: 0, unauthorized: 0 };
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const request = input instanceof Request ? input : new Request(input, init);
  const response = await realFetch(input, init);
  if (request.method === "POST" && new URL(request.url).pathname === "/auth/grant/session") counts.exchanges++;
  if (response.status === 401) counts.unauthorized++;
  return response;
};

async function markSharedBearerExpired(id: string) {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open("pubky-auth");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("storedSessions", "readwrite");
      const records = tx.objectStore("storedSessions");
      const request = records.get(id);
      request.onsuccess = () => {
        const value = request.result;
        value.sharedSession.response.session.token_expires_at = 0;
        records.put(value);
      };
      tx.oncomplete = () => resolve();
      tx.onerror = tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

function agentRole() {
  const store = sdk.browserSessionStore;
  const allowed = query.get("allow")!.split(",");
  let signer: Signer | undefined;
  let session: Session | undefined;
  let savedId: string | undefined;
  // Restore before serving, so connecting apps wait instead of seeing "no session".
  const server = (async () => {
    const [record] = await store.list();
    if (record) {
      savedId = record.id;
      session = await store.restore(record.id);
    }
    const server = sdk.serveSessionAgent(allowed);
    if (session) server.setSession(session);
    return server;
  })();
  return {
    async ready() { await server; },
    // Stand-in for Ring: a throwaway account approves its own grant request.
    async signin() {
      signer = sdk.signer(Keypair.random());
      await signer.signup(HOMESERVER, await createSignupToken());
      const flow = await sdk.startGrantAuthFlow(`${NOTES}:rw`, AuthFlowKind.signin(), {
        clientId: CLIENT_ID, relay: "http://localhost:15412/inbox",
      });
      await signer.approveAuthRequest(flow.authorizationUrl);
      session = await flow.awaitApproval();
      savedId = (await store.save(session)).id;
      (await server).setSession(session);
      return session.info.publicKey.z32();
    },
    async hasSession() { return (await server).hasSession; },
    async grantCount() {
      const root = await signer!.signin("grant-audit.test");
      try {
        return (await new GrantManager(root).list()).filter((grant) => grant.clientId === CLIENT_ID).length;
      } finally { await root.signout(); }
    },
    // Rotate the shared bearer: expire it in the store, then let the agent's
    // own request refresh it. Bearers handed out before this are now dead.
    async rotate() {
      await markSharedBearerExpired(savedId!);
      await session!.storage.putText(`${NOTES}agent-heartbeat`, Date.now().toString());
    },
  };
}

function appRole() {
  const agentUrl = query.get("agent")!;
  let session: Session | undefined;
  async function connect() {
    session = await sdk.connectSessionAgent(agentUrl, { timeoutMs: 8000 });
    return session?.info.publicKey.z32();
  }
  const ready = connect().then((user) => ({ user }), (error) => ({ error: error.message as string }));
  return {
    ready: () => ready,
    connect,
    whoami: () => session?.info.publicKey.z32(),
    async write(text: string) { await session!.storage.putText(`${NOTES}${location.port}`, text); },
    async read(port: string) { return session!.storage.getText(`${NOTES}${port}`); },
    async signout() { await session!.signout(); session = undefined; },
    counts: () => counts,
  };
}

Object.assign(globalThis, { harness: location.pathname === "/agent" ? agentRole() : appRole() });
