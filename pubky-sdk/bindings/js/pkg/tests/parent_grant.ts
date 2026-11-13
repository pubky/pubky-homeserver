import test from "tape";

import {
  AuthFlowKind,
  ChildGrantRequest,
  GrantAuthFlow,
  Keypair,
  ParentGrant,
  ParentGrantDeepLink,
  ParentGrantInfo,
  Pubky,
  PublicKey,
  type Capabilities,
} from "../index.js";
import { Assert, IsExact, assertPubkyError, createSignupToken } from "./utils.js";

const HOMESERVER_PUBLICKEY = PublicKey.from(
  "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo",
);
const TESTNET_HTTP_RELAY = "http://localhost:15412/inbox";
const ACCOUNTS = "https://accounts.example/auth/callback";
const AUTHORIZE = "https://accounts.example/authorize";
const CHAT = "https://chat.example/auth/callback";
const CHAT_CAPS = "/pub/chat/:rw,/priv/chat/:rwe" as Capabilities;

type Facade = ReturnType<typeof Pubky.testnet>;
type _DelegationSupport = Assert<
  IsExact<
    ReturnType<Facade["grantDelegationSupport"]>,
    Promise<"supported" | "unsupported" | "unknown">
  >
>;
type _ListParents = Assert<
  IsExact<ReturnType<Facade["parentGrantStore"]["list"]>, Promise<ParentGrantInfo[]>>
>;
type _RestoreParent = Assert<
  IsExact<ReturnType<Facade["parentGrantStore"]["restore"]>, Promise<ParentGrant>>
>;

function childRequestUrl(overrides: Record<string, string> = {}) {
  const url = new URL(AUTHORIZE);
  const params = {
    cid: CHAT,
    caps: CHAT_CAPS,
    cpk: Keypair.random().publicKey.z32(),
    epk: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
    state: "state-1",
    ...overrides,
  };
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return url.toString();
}

function assertRejects(t: test.Test, error: unknown, name: string, pattern: RegExp) {
  assertPubkyError(t, error);
  const { name: actual, message } = error as { name: string; message: string };
  t.equal(actual, name, `error is ${name}`);
  t.ok(pattern.test(message), `"${message}" matches ${pattern}`);
}

async function expectRejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("Expected the promise to reject");
}

async function userWithParent(capabilities?: string) {
  const sdk = Pubky.testnet();
  const user = Keypair.random();
  const signer = sdk.signer(user);
  await signer.signup(HOMESERVER_PUBLICKEY, await createSignupToken());
  const flow = await sdk.startGrantAuthFlow(
    "/pub/:rwe,/priv/:rwe" as Capabilities,
    AuthFlowKind.signin(),
    { clientId: ACCOUNTS, relay: TESTNET_HTTP_RELAY, parentGrant: true },
  );
  const link = ParentGrantDeepLink.parse(flow.authorizationUrl);
  const approved = flow.awaitParentGrant();
  if (capabilities === undefined) {
    await signer.approveAuthRequest(link.toString());
  } else {
    await signer.approveAuthWithCapabilities(link.toString(), capabilities);
  }
  return { sdk, user, parent: await approved };
}

/** Issue a child for a fresh request and return the delivered callback URL. */
async function issue(parent: ParentGrant, caps: Capabilities = CHAT_CAPS) {
  return new URL(await parent.issueChild(ChildGrantRequest.parse(childRequestUrl({ caps }))));
}

test("ChildGrantRequest: reads a request and rejects inexact callbacks", (t) => {
  const request = ChildGrantRequest.parse(childRequestUrl());
  t.equal(request.clientId, CHAT);
  t.deepEqual(request.capabilities, CHAT_CAPS.split(","));

  const declined = new URL(request.declinedUrl("insufficient_permissions"));
  t.equal(`${declined.origin}${declined.pathname}${declined.search}`, CHAT);
  t.ok(declined.hash.includes("error=insufficient_permissions"));
  t.ok(declined.hash.includes("state=state-1"));

  for (const cid of ["chat.example", "http://chat.example/cb", "https://CHAT.example/cb"]) {
    t.throws(() => ChildGrantRequest.parse(childRequestUrl({ cid })), `rejects ${cid}`);
  }
  t.throws(() => ChildGrantRequest.parse(childRequestUrl({ state: "" })), "rejects empty state");
  t.throws(() => request.declinedUrl("nonsense"), "rejects unknown reasons");
  t.end();
});

test("ParentGrantDeepLink: rejects requests a parent can never hold", (t) => {
  const link = (caps: string, cid: string) =>
    `pubkyauth://parent_grant?caps=${caps}&relay=${TESTNET_HTTP_RELAY}&cid=${cid}` +
    `&cpk=${Keypair.random().publicKey.z32()}&epk=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc`;
  const parsed = ParentGrantDeepLink.parse(link("/pub/:rwe,/priv/:rwe", ACCOUNTS));
  t.equal(parsed.clientId, ACCOUNTS);
  t.equal(parsed.ephemeralPublicKey.length, 32);
  t.throws(() => ParentGrantDeepLink.parse(link("/:rw", ACCOUNTS)), "rejects /:rw");
  t.throws(() => ParentGrantDeepLink.parse(link("/pub/:rw", "accounts.example")), "rejects inexact client");
  t.end();
});

test("parent grant: needs a browser-held key, with no local fallback", async (t) => {
  if (typeof indexedDB !== "undefined") {
    t.comment("browser runtime has delegated keys; Node-only check skipped");
    t.end();
    return;
  }
  const error = await expectRejection(
    Pubky.testnet().startGrantAuthFlow("/pub/:rwe" as Capabilities, AuthFlowKind.signin(), {
      clientId: ACCOUNTS,
      relay: TESTNET_HTTP_RELAY,
      parentGrant: true,
    }),
  );
  assertRejects(t, error, "ClientStateError", /secure browser context|WebCrypto/);
  t.end();
});

test("parent grant: the standalone local flow refuses to hold one", (t) => {
  const error = (() => {
    try {
      GrantAuthFlow.start("/pub/:rwe" as Capabilities, AuthFlowKind.signin(), {
        clientId: ACCOUNTS,
        relay: TESTNET_HTTP_RELAY,
        parentGrant: true,
      });
    } catch (error) {
      return error;
    }
    throw new Error("Expected GrantAuthFlow.start to throw");
  })();
  assertRejects(t, error, "ClientStateError", /browser-held key/);
  t.end();
});

test("grantDelegationSupport: tells supported homeservers from unknown ones", async (t) => {
  const sdk = Pubky.testnet();
  const user = Keypair.random();
  await sdk.signer(user).signup(HOMESERVER_PUBLICKEY, await createSignupToken());
  t.equal(await sdk.grantDelegationSupport(user.publicKey), "supported");
  t.equal(await sdk.grantDelegationSupport(Keypair.random().publicKey), "unknown");
  t.end();
});

test("parent grant: issues children within its limits only", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only parent test skipped without IndexedDB");
    t.end();
    return;
  }
  const { parent } = await userWithParent();
  t.deepEqual(parent.capabilities, ["/pub/:rwe", "/priv/:rwe"]);
  t.deepEqual(parent.encryptionKeys.scopes, ["/pub/", "/priv/"]);

  const delivered = await issue(parent);
  t.equal(`${delivered.origin}${delivered.pathname}${delivered.search}`, CHAT);
  t.ok(delivered.hash.includes("approval="), "the approval travels in the fragment");
  t.ok(delivered.hash.includes("state=state-1"));

  const { parent: storageOnly } = await userWithParent("/pub/:rw,/priv/:rw");
  t.deepEqual(storageOnly.encryptionKeys.scopes, [], "the user declined keys");
  const declined = await expectRejection(
    storageOnly.issueChild(ChildGrantRequest.parse(childRequestUrl())),
  );
  assertRejects(t, declined, "AuthenticationError", /insufficient_permissions/);
  t.deepEqual(
    (declined as { data?: unknown }).data,
    { reason: "RedirectDeclined", denial: "insufficient_permissions" },
    "the denial code is machine-readable",
  );
  await issue(storageOnly, "/pub/chat/:rw" as Capabilities);
  t.end();
});

test("ParentGrantStore: survives a restart and hides secrets from listings", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only store test skipped without IndexedDB");
    t.end();
    return;
  }
  const { sdk, parent } = await userWithParent();
  const info = await sdk.parentGrantStore.save(parent);
  t.equal(info.grantId, parent.grantId);
  t.equal(info.logoutPending, false);

  const listed = (await sdk.parentGrantStore.list()).find((item) => item.id === info.id)!;
  t.deepEqual(listed.capabilities, ["/pub/:rwe", "/priv/:rwe"]);

  for (const secret of ["signedApproval", "parentGrant", "keyId"]) {
    t.notOk(secret in listed, `listings leave out ${secret}`);
  }

  const restarted = Pubky.testnet();
  const restored = await restarted.parentGrantStore.restore(info.id);
  t.deepEqual(restored.encryptionKeys.scopes, ["/pub/", "/priv/"]);
  await issue(restored);
  t.end();
});

test("ParentGrantStore: clearing browser sessions keeps saved parents usable", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only store test skipped without IndexedDB");
    t.end();
    return;
  }
  const { sdk, parent } = await userWithParent();
  const { id } = await sdk.parentGrantStore.save(parent);
  await sdk.browserSessionStore.clearAll();

  const restored = await sdk.parentGrantStore.restore(id);
  await issue(restored);
  await sdk.parentGrantStore.reconnectApp(id, CHAT);
  assertRejects(
    t,
    await expectRejection(sdk.parentGrantStore.reconnectApp(id, "")),
    "InvalidInput",
    /./,
  );
  await sdk.parentGrantStore.signOut(id);
  t.notOk((await sdk.parentGrantStore.list()).some((item) => item.id === id), "the record is gone");
  t.end();
});

test("ParentGrantStore: signing out retries and leaves delivered keys alone", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only store test skipped without IndexedDB");
    t.end();
    return;
  }
  const { sdk, parent } = await userWithParent();
  const { id } = await sdk.parentGrantStore.save(parent);
  const keys = parent.encryptionKeys;
  // Another tab restored the parent just before the sign-out.
  const otherTab = await Pubky.testnet().parentGrantStore.restore(id);

  // The revocation request is lost, so sign-out stays pending.
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    if (request.method === "DELETE" && new URL(request.url).pathname === "/auth/grant/session") {
      throw new TypeError("Simulated connection failure");
    }
    return await realFetch(input, init);
  };
  try {
    // A save racing the sign-out can't undo it, whichever of the two lands first.
    const racingSave = sdk.parentGrantStore.save(parent).catch(() => {});
    await expectRejection(sdk.parentGrantStore.signOut(id));
    await racingSave;
  } finally {
    globalThis.fetch = realFetch;
  }
  const pending = (await sdk.parentGrantStore.list()).find((item) => item.id === id)!;
  t.equal(pending.logoutPending, true);

  // Parents already in memory stop issuing, though the key is kept for the retry.
  for (const held of [parent, otherTab]) {
    assertRejects(t, await expectRejection(issue(held)), "ClientStateError", /signed out/);
  }

  // Saving again can't bring the parent back while its sign-out is pending.
  assertRejects(t, await expectRejection(sdk.parentGrantStore.save(parent)), "ClientStateError", /signed out/);

  // Restoring finishes the sign-out instead of enabling issuance.
  assertRejects(t, await expectRejection(sdk.parentGrantStore.restore(id)), "ClientStateError", /signed out/);
  t.notOk((await sdk.parentGrantStore.list()).some((item) => item.id === id), "the record is gone");
  assertPubkyError(t, await expectRejection(issue(parent)), "the parent's key is deleted");

  // Keys already handed out can't be taken back.
  t.ok(keys.deriveForPath("/priv/chat/message"));
  t.end();
});

test("ParentGrantStore: rejects missing keys and corrupted records", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only store test skipped without IndexedDB");
    t.end();
    return;
  }
  const { sdk, parent } = await userWithParent();
  const { id } = await sdk.parentGrantStore.save(parent);

  const edit = (dbName: string, storeName: string, change: (store: IDBObjectStore) => void) =>
    new Promise<void>((resolve, reject) => {
      const open = indexedDB.open(dbName);
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const tx = open.result.transaction(storeName, "readwrite");
        change(tx.objectStore(storeName));
        tx.oncomplete = () => {
          open.result.close();
          resolve();
        };
        tx.onerror = () => reject(tx.error);
      };
    });
  const tamper = (mutate: (record: Record<string, unknown>) => void) =>
    edit("pubky-delegated-auth", "parentGrants", (store) => {
      const get = store.get(id);
      get.onsuccess = () => {
        mutate(get.result);
        store.put(get.result);
      };
    });

  // A changed approval fails its signature check, and no issuance is enabled.
  let original = "";
  await tamper((record) => {
    original = record.signedApproval as string;
    const [header, payload, signature] = original.split(".");
    record.signedApproval = `${header}.${payload}x.${signature}`;
  });
  assertPubkyError(t, await expectRejection(sdk.parentGrantStore.restore(id)));

  // A record that names another identity is rejected too.
  await tamper((record) => {
    record.signedApproval = original;
    record.publicKey = Keypair.random().publicKey.z32();
  });
  assertRejects(t, await expectRejection(sdk.parentGrantStore.restore(id)), "ClientStateError", /Invalid stored parent grant/);

  // A missing signing key can't be used, and the record can still be removed.
  await tamper((record) => {
    record.publicKey = parent.publicKey.z32();
    record.keyId = "missing-key";
  });
  assertRejects(t, await expectRejection(sdk.parentGrantStore.restore(id)), "ClientStateError", /not found/);
  await sdk.parentGrantStore.remove(id);
  assertRejects(t, await expectRejection(sdk.parentGrantStore.restore(id)), "ClientStateError", /not found/);

  // A record this version can't read is left out of listings instead of breaking them.
  await edit("pubky-delegated-auth", "parentGrants", (store) => store.put({ id: "unreadable" }));
  t.notOk((await sdk.parentGrantStore.list()).some((item) => item.id === "unreadable"));
  await edit("pubky-delegated-auth", "parentGrants", (store) => store.delete("unreadable"));
  t.end();
});
