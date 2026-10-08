// Each Electron window plays the agent or an app, chosen by its URL path.
// The agent's allowlist, and the apps' agent origin and capabilities, arrive
// as query parameters so the harness can pick free ports.
import {
  AuthFlowKind, GrantManager, Keypair, Pubky, PublicKey, Session, SessionAgent,
  SessionAgentClient, Signer, type AgentStatus, type Capabilities,
} from "../../index.js";
import { createSignupToken } from "../utils.js";

const sdk = Pubky.testnet();
const HOMESERVER = PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo");
const RELAY = "http://localhost:15412/inbox";
const CLIENT_ID = "auth.test";
const SHARED_SCOPE = "/pub/sso.test/:rw";
const NOTES = "/pub/sso.test/";
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

/** The agent page: restores a stored session, then serves it to its parent. */
function agentRole() {
  const store = sdk.browserSessionStore;
  let signer: Signer | undefined;
  let session: Session | undefined;
  const agent: Promise<SessionAgent> = (async () => {
    const [record] = await store.list();
    if (record) session = await store.restore(record.id);
    const agent = await sdk.listenSessionAgent({
      allowedOrigins: query.get("allow")!.split(","), capabilities: SHARED_SCOPE,
    });
    if (session) await agent.setSession(session);
    return agent;
  })();
  return {
    async ready() { await agent; },
    // In-frame sign-in. A throwaway account approves its own grant request,
    // standing in for the QR code and Ring. Saving the session is what makes
    // the agent (this frame and every other) start serving it.
    async signin() {
      const returnUrl = (await agent).returnUrl;
      signer = sdk.signer(Keypair.random());
      await signer.signup(HOMESERVER, await createSignupToken());
      const flow = await sdk.startGrantAuthFlow(SHARED_SCOPE, AuthFlowKind.signin(), {
        clientId: CLIENT_ID, relay: RELAY, xCallback: returnUrl ? { xSuccess: returnUrl } : undefined,
      });
      await signer.approveAuthRequest(flow.authorizationUrl);
      session = await flow.awaitApproval();
      await store.save(session);
      return session.info.publicKey.z32();
    },
    async hasSession() { return (await agent).hasSession; },
    async returnUrl() { return (await agent).returnUrl; },
    // A root session must never be served, whatever the page tries.
    async rejectsRootSession() {
      const root = await signer!.signin("root-check.test");
      try {
        await (await agent).setSession(root);
        return "accepted";
      } catch (error) {
        return (error as Error).name;
      } finally { await root.signout(); }
    },
    // A session within the scope for one capability but outside it for
    // another is refused as a whole.
    async rejectsScopedSession() {
      const flow = await sdk.startGrantAuthFlow(`${SHARED_SCOPE},/pub/other.test/:r`, AuthFlowKind.signin(), {
        clientId: "scope-check.test", relay: RELAY,
      });
      await signer!.approveAuthRequest(flow.authorizationUrl);
      const scoped = await flow.awaitApproval();
      try {
        await (await agent).setSession(scoped);
        return "accepted";
      } catch (error) {
        return (error as Error).name;
      } finally { await scoped.signout(); }
    },
    async clearStore() { await store.clear(); },
    async grantCount() {
      const root = await signer!.signin("grant-audit.test");
      try {
        return (await new GrantManager(root).list()).filter((grant) => grant.clientId === CLIENT_ID).length;
      } finally { await root.signout(); }
    },
    // Rotate the shared bearer: expire it in the store, then let the agent's
    // own request refresh it. Bearers lent before this are now dead.
    async rotate() {
      const [record] = await store.list();
      await markSharedBearerExpired(record.id);
      await session!.storage.putText(`${NOTES}agent-heartbeat`, Date.now().toString());
    },
  };
}

/** An app page: owns the agent frame and borrows the session through it. */
function appRole() {
  const agentOrigin = query.get("agent")!;
  const frame = document.createElement("iframe");
  frame.src = `${agentOrigin}/agent?allow=${encodeURIComponent(query.get("allow")!)}`;
  frame.hidden = true;
  document.body.append(frame);
  const changes: AgentStatus[] = [];
  let client: SessionAgentClient | undefined;
  let held: Session | undefined;
  let rawPort: MessagePort | undefined;
  const show = (status: AgentStatus) => { frame.hidden = status.state !== "signed-out"; };
  const ready = sdk.connectSessionAgent(frame, {
    agentOrigin,
    capabilities: (query.get("caps") ?? SHARED_SCOPE) as Capabilities,
    returnUrl: location.href,
    timeoutMs: 8000,
  }).then((connected) => {
    client = connected;
    show(connected.status);
    connected.addEventListener("change", (event: Event) => {
      const status = (event as CustomEvent<AgentStatus>).detail;
      changes.push(status);
      show(status);
    });
    return { status: connected.status };
  }, (error) => ({ error: error.message as string, code: error.data?.code as string | undefined }));
  return {
    ready: () => ready,
    status: () => client?.status,
    whoami: () => client?.session?.info.publicKey.z32(),
    async write(text: string) { await client!.session!.storage.putText(`${NOTES}${location.port}`, text); },
    async read(port: string) { return client!.session!.storage.getText(`${NOTES}${port}`); },
    async signout() { await client!.session!.signout(); },
    counts: () => counts,
    changes: () => changes,
    frameVisible: () => !frame.hidden,
    frameHeight: () => frame.style.height,
    // Keep the current session object, as an app would across a user switch.
    hold() { held = client!.session; },
    async writeHeld(text: string) { await held!.storage.putText(`${NOTES}held`, text); },
    closeClient() { client!.close(); },
    // A hello sent by hand, bypassing the SDK: shows how the agent answers
    // other versions, a foreign return URL, and raw requests on the port.
    rawHello(v: number, returnUrl?: string) {
      const channel = new MessageChannel();
      const reply = new Promise((resolve) => { channel.port1.onmessage = (event) => resolve(event.data); });
      const hello = { type: "pubky-agent/hello", v, capabilities: SHARED_SCOPE, returnUrl };
      frame.contentWindow!.postMessage(hello, agentOrigin, [channel.port2]);
      rawPort = channel.port1;
      return reply;
    },
    rawRequest(message: Record<string, unknown>) {
      const reply = new Promise((resolve) => { rawPort!.onmessage = (event) => resolve(event.data); });
      rawPort!.postMessage({ id: 1, ...message });
      return reply;
    },
    // A same-origin sibling frame is not the agent's parent, so it is refused
    // even though its origin is allowlisted.
    siblingHello() {
      return new Promise((resolve) => {
        const sibling = document.createElement("iframe");
        sibling.srcdoc = `<script>
          const channel = new MessageChannel();
          channel.port1.onmessage = (event) => parent.postMessage({ siblingReply: event.data }, "*");
          parent.document.querySelector("iframe").contentWindow.postMessage(
            { type: "pubky-agent/hello", v: 1, capabilities: "" }, ${JSON.stringify(agentOrigin)}, [channel.port2]);
        </script>`;
        addEventListener("message", function onReply(event) {
          if (!event.data?.siblingReply) return;
          removeEventListener("message", onReply);
          sibling.remove();
          resolve(event.data.siblingReply);
        });
        document.body.append(sibling);
      });
    },
  };
}

Object.assign(globalThis, { harness: location.pathname === "/agent" ? agentRole() : appRole() });
