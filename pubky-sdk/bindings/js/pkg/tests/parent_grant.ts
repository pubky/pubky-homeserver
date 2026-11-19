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
const PARENTS = "parentGrants";
const APPROVAL_KEYS = "approvalKeys";

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

/** Inspect or edit the actual IndexedDB records, waiting for the transaction to commit. */
async function parentStoreRequest<T>(
  name: string, mode: IDBTransactionMode, operation: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const open = indexedDB.open("pubky-delegated-auth");
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(name, mode);
      const request = operation(tx.objectStore(name));
      tx.oncomplete = () => resolve(request.result);
      tx.onabort = tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

function readStored(name: string, id: string) {
  return parentStoreRequest(name, "readonly", store => store.get(id));
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

  const { sdk, parent: approved } = await userWithParent("/pub/:rw,/priv/:rw");
  const { id } = await sdk.parentGrantStore.save(approved);
  const record = await readStored(PARENTS, id);
  t.ok(record.encryptedApproval.ciphertext.byteLength > 0, "approvals without e are encrypted too");
  t.notOk("signedApproval" in record);
  const storageOnly = await sdk.parentGrantStore.restore(id);
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

test("ParentGrantStore: encrypts the approval and restores its scoped keys after a restart", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only store test skipped without IndexedDB");
    t.end();
    return;
  }
  const { sdk, parent } = await userWithParent();
  const info = await sdk.parentGrantStore.save(parent);
  t.equal(info.grantId, parent.grantId);
  t.equal(info.logoutPending, false);

  const record = await readStored(PARENTS, info.id);
  t.notOk("signedApproval" in record, "the record has no plaintext approval");
  t.notOk("key" in record || "key" in record.encryptedApproval, "the approval key is stored separately");
  const { iv, ciphertext } = record.encryptedApproval;
  t.equal(iv.byteLength, 12);
  t.ok(ciphertext instanceof ArrayBuffer && ciphertext.byteLength > 0);
  const key: CryptoKey = await readStored(APPROVAL_KEYS, info.id);
  t.deepEqual(key.algorithm, { name: "AES-GCM", length: 256 });
  t.equal(key.extractable, false);
  const cipher = { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(info.id) };
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(cipher, key, ciphertext));
  t.ok(plaintext.byteLength > 0, "the parent ID authenticates the encrypted approval");
  plaintext.fill(0);

  await sdk.parentGrantStore.save(parent);
  const replacement = await readStored(PARENTS, info.id);
  t.notDeepEqual(replacement.encryptedApproval.iv, iv, "each save uses a fresh IV");
  const replacementKey: CryptoKey = await readStored(APPROVAL_KEYS, info.id);
  const wrongKey = await expectRejection(crypto.subtle.decrypt(cipher, replacementKey, ciphertext));
  t.equal((wrongKey as DOMException).name, "OperationError", "each save uses a fresh AES key");

  const listed = (await sdk.parentGrantStore.list()).find((item) => item.id === info.id)!;
  t.deepEqual(listed.capabilities, ["/pub/:rwe", "/priv/:rwe"]);

  for (const secret of ["signedApproval", "encryptedApproval", "parentGrant", "keyId"]) {
    t.notOk(secret in listed, `listings leave out ${secret}`);
  }

  const restarted = Pubky.testnet();
  const restored = await restarted.parentGrantStore.restore(info.id);
  t.deepEqual(restored.encryptionKeys.scopes, ["/pub/", "/priv/"]);
  t.deepEqual(restored.encryptionKeys.deriveForPath("/priv/chat/message"),
    parent.encryptionKeys.deriveForPath("/priv/chat/message"), "the restored file key matches");
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
  t.end();
});

test("ParentGrantStore: sign-out waits for a save that already checked the signing key", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only store test skipped without IndexedDB");
    t.end();
    return;
  }
  const { sdk, parent } = await userWithParent();
  const { id } = await sdk.parentGrantStore.save(parent);
  const encrypt = crypto.subtle.encrypt;
  let signOut: Promise<void> | undefined;
  crypto.subtle.encrypt = async function(...args) {
    // Pause save after its signing-key check until sign-out queues for final deletion.
    const request = navigator.locks.request;
    const queued = new Promise<string>(resolve => {
      navigator.locks.request = function(name: string, ...options: unknown[]) {
        const result = Reflect.apply(request, this, [name, ...options]);
        resolve(name);
        return result;
      };
    });
    try {
      signOut = sdk.parentGrantStore.signOut(id);
      const lockName = await Promise.race([queued, signOut]);
      const { pending } = await navigator.locks.query();
      t.ok(lockName && pending?.some(lock => lock.name === lockName), "final deletion waits for the save's lock");
    } finally {
      navigator.locks.request = request;
    }
    return encrypt.apply(this, args);
  };
  try {
    assertRejects(t, await expectRejection(sdk.parentGrantStore.save(parent)), "ClientStateError", /signed out/);
  } finally {
    crypto.subtle.encrypt = encrypt;
    await signOut;
  }
  t.notOk((await sdk.parentGrantStore.list()).some((item) => item.id === id), "the record is gone");
  t.equal(await readStored(APPROVAL_KEYS, id), undefined, "a completed sign-out leaves no AES key");
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
      const record = await readStored(PARENTS, id);
      t.ok(record.logoutPending, "the parent is pending before network revocation");
      t.notOk("encryptedApproval" in record, "the ciphertext is already gone");
      t.equal(await readStored(APPROVAL_KEYS, id), undefined, "the AES key is already gone");
      throw new TypeError("Simulated connection failure");
    }
    return await realFetch(input, init);
  };
  try {
    await expectRejection(sdk.parentGrantStore.signOut(id));
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
  t.equal(await readStored(APPROVAL_KEYS, id), undefined, "the rejected save leaves no AES key");

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

  const original = await readStored(PARENTS, id);
  const put = (record: Record<string, unknown>) =>
    parentStoreRequest(PARENTS, "readwrite", store => store.put(record));
  const restoreError = () => expectRejection(sdk.parentGrantStore.restore(id));
  const changed = structuredClone(original);
  new Uint8Array(changed.encryptedApproval.ciphertext)[0] ^= 1;
  await put(changed);
  assertRejects(t, await restoreError(), "ClientStateError", /Invalid stored parent grant/);

  // A record that names another identity is rejected too.
  await put({ ...original, publicKey: Keypair.random().publicKey.z32() });
  assertRejects(t, await restoreError(), "ClientStateError", /Invalid stored parent grant/);

  // Each credential needs both its approval key and its signing key.
  await put(original);
  await parentStoreRequest(APPROVAL_KEYS, "readwrite", store => store.delete(id));
  assertRejects(t, await restoreError(), "ClientStateError", /Invalid stored parent grant/);
  await sdk.parentGrantStore.save(parent);
  const saved = await readStored(PARENTS, id);
  await put({ ...saved, keyId: "missing-key" });
  assertRejects(t, await restoreError(), "ClientStateError", /not found/);
  await put(saved);
  await sdk.parentGrantStore.remove(id);
  t.equal(await readStored(APPROVAL_KEYS, id), undefined, "removal deletes the approval key");
  assertRejects(t, await restoreError(), "ClientStateError", /not found/);

  // A record this version can't read is left out of listings instead of breaking them.
  await put({ id: "unreadable" });
  t.notOk((await sdk.parentGrantStore.list()).some((item) => item.id === "unreadable"));
  await parentStoreRequest(PARENTS, "readwrite", store => store.delete("unreadable"));
  t.end();
});
