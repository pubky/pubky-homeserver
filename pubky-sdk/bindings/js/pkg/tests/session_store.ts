import test from "tape";
import { assertServiceAuthCredentials, decodeClaims } from "./service_auth_helpers.js";

import {
  AuthFlowKind,
  BrowserSessionStore,
  GrantAuthFlow,
  Keypair,
  Pubky,
  PublicKey,
  Session,
  StoredSessionInfo,
  type Capabilities,
  type Path,
} from "../index.js";
import {
  Assert,
  IsExact,
  assertPubkyError,
  createSignupToken,
} from "./utils.js";

const HOMESERVER_PUBLICKEY = PublicKey.from(
  "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo",
);
const TESTNET_HTTP_RELAY = "http://localhost:15412/inbox";

type Facade = ReturnType<typeof Pubky.testnet>;
type Store = Facade["browserSessionStore"];

type _BrowserSessionStoreGetter = Assert<IsExact<Store, BrowserSessionStore>>;
type _StoreAvailable = Assert<
  IsExact<ReturnType<Store["isAvailable"]>, Promise<boolean>>
>;
type _StoreList = Assert<
  IsExact<ReturnType<Store["list"]>, Promise<StoredSessionInfo[]>>
>;
type _StoreClearAll = Assert<
  IsExact<ReturnType<Store["clearAll"]>, Promise<void>>
>;
type _StoreRestore = Assert<
  IsExact<ReturnType<Store["restore"]>, Promise<Session>>
>;
type _StoreSave = Assert<
  IsExact<ReturnType<Store["save"]>, Promise<StoredSessionInfo>>
>;
type _StoredCapabilities = Assert<
  IsExact<StoredSessionInfo["capabilities"], string[]>
>;
type _StoredStorageMode = Assert<
  IsExact<StoredSessionInfo["storageMode"], string>
>;
type _DelegatedResume = Assert<
  IsExact<ReturnType<Facade["resumeDelegatedGrantAuthFlow"]>, Promise<GrantAuthFlow>>
>;

test("BrowserSessionStore: Node runtime reports unavailable without IndexedDB", async (t) => {
  if (typeof indexedDB !== "undefined") {
    t.comment("browser runtime has IndexedDB; Node-only unavailable check skipped");
    t.end();
    return;
  }

  const sdk = Pubky.testnet();
  const store = sdk.browserSessionStore;

  t.equal(await store.isAvailable(), false, "store is unavailable without IndexedDB");
  t.deepEqual(await store.list(), [], "list is empty without IndexedDB");

  try {
    await store.restore("missing");
    t.fail("restore should reject without IndexedDB");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "ClientStateError", "restore maps to ClientStateError");
    t.ok(/IndexedDB/i.test(error.message), "restore message names IndexedDB");
  }

  try {
    await store.remove("missing");
    t.fail("remove should reject without IndexedDB");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "ClientStateError", "remove maps to ClientStateError");
    t.ok(/IndexedDB/i.test(error.message), "remove message names IndexedDB");
  }

  t.end();
});

test("BrowserSessionStore: browser store can be opened and cleared", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("Node runtime has no IndexedDB; browser availability check skipped");
    t.end();
    return;
  }

  const sdk = Pubky.testnet();
  const store = sdk.browserSessionStore;

  t.equal(await store.isAvailable(), true, "store is available with IndexedDB");
  await store.clear();
  t.deepEqual(await store.list(), [], "clear removes stored session records");
  const objectStores = await pubkyAuthObjectStores();
  t.deepEqual(
    objectStores,
    ["delegatedGrantKeys", "storedSessions"],
    "session persistence uses one pubky-auth database with separate stores",
  );

  const flow = await sdk.startGrantAuthFlow(
    "",
    AuthFlowKind.signin(),
    { clientId: "session-store-browser.test", relay: "http://127.0.0.1:9/inbox" },
  );
  t.ok(flow instanceof GrantAuthFlow, "facade starts a grant flow");

  t.end();
});

test("BrowserSessionStore: browser runner supports delegated grant keys", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("Node runtime has no IndexedDB; browser delegated-key check skipped");
    t.end();
    return;
  }

  await assertBrowserDelegationAvailable(t);

  t.end();
});

test("BrowserSessionStore: saves and restores a completed grant session", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only session persistence test skipped without IndexedDB");
    t.end();
    return;
  }

  const sdk = Pubky.testnet();
  const store = sdk.browserSessionStore;
  await store.clear();

  const signer = sdk.signer(Keypair.random());
  const user = signer.publicKey.z32();
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);

  const clientId = "session-store-save-restore.test";
  const session = await signer.signin(clientId);
  const stored = await store.save(session);

  t.equal(stored.publicKey, user, "stored record belongs to expected user");
  t.equal(stored.clientId, clientId, "stored record keeps client id");
  t.deepEqual(
    stored.capabilities,
    "/:rw".split(","),
    "stored record keeps capabilities",
  );
  t.ok(stored.grantId.length > 0, "stored record includes grant id");
  t.equal(
    stored.storageMode,
    "localSecret",
    "direct signer grant session is stored with local secret material",
  );

  const records = await store.list();
  t.equal(records.length, 1, "one stored session is listed");
  t.equal(records[0].id, stored.id, "listed record has the saved id");

  const restored = await store.restore(stored.id);
  t.equal(
    restored.info.publicKey.z32(),
    user,
    "restored session belongs to expected user",
  );

  const path = `/pub/pubky.app/session-store-${Date.now()}.txt` as Path;
  await restored.storage.putText(path, "restored session works");
  t.equal(
    await restored.storage.getText(path),
    "restored session works",
    "restored session can perform authenticated storage operations",
  );

  // Older SDKs saved grant material without the shared bearer state.
  await removeSharedSession(stored.id);
  const migrated = await Promise.all([store.restore(stored.id), store.restore(stored.id)]);
  for (const session of migrated) {
    t.equal(await session.grant!.grantId(), stored.grantId, "migration preserves the grant");
  }
  await Promise.all([restored, ...migrated].map(session => session.storage.putText(path, "migrated")));
  t.pass("existing and migrated handles adopt the shared bearer");

  t.end();
});

test("BrowserSessionStore: facade local fallback is stored with local secret material", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only local fallback test skipped without IndexedDB");
    t.end();
    return;
  }

  const sdk = Pubky.testnet();
  const store = sdk.browserSessionStore;
  await store.clear();

  const signer = sdk.signer(Keypair.random());
  const user = signer.publicKey.z32();
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);

  setBrowserDelegationOverride(false);
  try {
    const capabilities = "/pub/local-fallback/:rw";
    const flow = await sdk.startGrantAuthFlow(
      capabilities,
      AuthFlowKind.signin(),
      { clientId: "session-store-local-fallback.test", relay: TESTNET_HTTP_RELAY },
    );
    const savedUrl = flow.authorizationUrl;
    try {
      flow.saveDelegated();
      t.fail("forced local fallback should not save delegated state");
    } catch (error) {
      assertPubkyError(t, error);
      t.equal(error.name, "ClientStateError", "forced fallback flow is not delegated");
    }

    const savedState = flow.saveLocal();
    t.ok(savedState.length > 0, "forced fallback flow can save local state");
    flow.free();

    const resumed = sdk.resumeGrantAuthFlow(savedState);
    await signer.approveAuthRequest(savedUrl);
    const session = await resumed.awaitApproval();
    t.equal(session.info.publicKey.z32(), user, "local fallback session belongs to expected user");
    t.deepEqual(
      session.info.capabilities,
      capabilities.split(","),
      "local fallback session keeps capabilities",
    );

    const stored = await store.save(session);
    t.equal(
      stored.storageMode,
      "localSecret",
      "facade local fallback session is stored with local secret material",
    );

    const restored = await store.restore(stored.id);
    const path = `/pub/local-fallback/session-store-${Date.now()}.txt` as Path;
    await restored.storage.putText(path, "local fallback restored");
    t.equal(
      await restored.storage.getText(path),
      "local fallback restored",
      "restored local fallback session can perform authenticated storage operations",
    );
  } finally {
    setBrowserDelegationOverride(undefined);
  }

  t.end();
});

test("BrowserSessionStore: stores and restores multiple accounts", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only multi-account test skipped without IndexedDB");
    t.end();
    return;
  }

  const sdk = Pubky.testnet();
  const store = sdk.browserSessionStore;
  await store.clear();
  await assertBrowserDelegationAvailable(t);

  const alice = await grantSessionFor(
    sdk,
    "session-store-alice.test",
    "/pub/alice/:rw",
  );
  const bob = await grantSessionFor(
    sdk,
    "session-store-bob.test",
    "/pub/bob/:rw",
  );

  const aliceStored = await store.save(alice.session);
  const bobStored = await store.save(bob.session);
  t.equal(
    aliceStored.storageMode,
    "delegated",
    "Alice facade grant session is stored as delegated",
  );
  t.equal(
    bobStored.storageMode,
    "delegated",
    "Bob facade grant session is stored as delegated",
  );
  const records = await store.list();

  t.equal(records.length, 2, "two stored sessions are listed");
  t.deepEqual(
    records.map((record) => record.publicKey).sort(),
    [alice.publicKey, bob.publicKey].sort(),
    "stored sessions keep separate account identities",
  );
  t.notEqual(aliceStored.id, bobStored.id, "stored session ids are distinct");

  const restoredAlice = await store.restore(aliceStored.id);
  const restoredBob = await store.restore(bobStored.id);

  t.equal(
    restoredAlice.info.publicKey.z32(),
    alice.publicKey,
    "restored Alice session has Alice identity",
  );
  t.equal(
    restoredBob.info.publicKey.z32(),
    bob.publicKey,
    "restored Bob session has Bob identity",
  );

  const alicePath = `/pub/alice/session-store-alice-${Date.now()}.txt` as Path;
  const bobPath = `/pub/bob/session-store-bob-${Date.now()}.txt` as Path;
  await restoredAlice.storage.putText(alicePath, "alice");
  await restoredBob.storage.putText(bobPath, "bob");

  t.equal(await restoredAlice.storage.getText(alicePath), "alice", "Alice restored session works");
  t.equal(await restoredBob.storage.getText(bobPath), "bob", "Bob restored session works");
  t.end();
});

test("service auth: restored delegated grant signs concurrently with an expired bearer", async t => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only delegated signing test skipped without IndexedDB");
    t.end();
    return;
  }
  const sdk = Pubky.testnet();
  const { session } = await grantSessionFor(sdk, "service-auth-expired-bearer.test", "/pub/app/:rw");
  const stored = await sdk.browserSessionStore.save(session);
  t.equal(stored.storageMode, "delegated", "uses a non-extractable browser key");
  const restored = await sdk.browserSessionStore.restore(stored.id);
  await expireSharedBearer(stored.id);

  const originalFetch = globalThis.fetch;
  let requests = 0;
  globalThis.fetch = async () => {
    requests++;
    throw new Error("proof generation must be network-free");
  };
  try {
    const audience = " Inbox:é/生产 ";
    const proofs = await Promise.all(
      Array.from({ length: 8 }, () => restored.grant!.createServiceAuthProof(audience)),
    );
    const nonces = proofs.map(proof => decodeClaims<{ nonce: string }>(proof.pop).nonce);
    t.equal(new Set(nonces).size, 8, "concurrent proofs have fresh nonces");
    for (const proof of proofs) {
      await assertServiceAuthCredentials(t, proof, audience);
    }
    t.equal(requests, 0, "expired bearer does not trigger a network request");
  } finally {
    globalThis.fetch = originalFetch;
    await sdk.browserSessionStore.remove(stored.id);
  }
  t.end();
});

test("service auth: missing delegated key reports an actionable error", async t => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only missing-key test skipped without IndexedDB");
    t.end();
    return;
  }
  const sdk = Pubky.testnet();
  const { session } = await grantSessionFor(sdk, "service-auth-missing-key.test", "/pub/app/:rw");
  const stored = await sdk.browserSessionStore.save(session);
  t.equal(stored.storageMode, "delegated", "uses a browser-held key");
  await removeDelegatedKey(stored.id);
  try {
    await session.grant!.createServiceAuthProof("inbox");
    t.fail("missing browser key must fail");
  } catch (error) {
    assertPubkyError(t, error);
    t.deepEqual(error.data, { reason: "SigningKeyUnavailable" }, "missing key is distinguishable from signing failure");
    t.match(error.message, /key not found/i, "diagnostic retains the missing-key cause");
  } finally {
    await sdk.browserSessionStore.remove(stored.id);
  }
  t.end();
});

test("service auth: inaccessible key storage preserves the IndexedDB diagnostic", async t => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only key-storage failure test skipped without IndexedDB");
    t.end();
    return;
  }
  const sdk = Pubky.testnet();
  const { session } = await grantSessionFor(sdk, "service-auth-key-storage.test", "/pub/app/:rw");
  const originalOpen = indexedDB.open;
  indexedDB.open = () => {
    throw new DOMException("Test storage access denied", "SecurityError");
  };
  try {
    await session.grant!.createServiceAuthProof("inbox");
    t.fail("inaccessible browser key storage must fail");
  } catch (error) {
    assertPubkyError(t, error);
    t.deepEqual(error.data, { reason: "SigningKeyUnavailable" }, "storage failure identifies an unavailable key");
    t.match(error.message, /Test storage access denied/, "diagnostic retains the IndexedDB cause");
  } finally {
    indexedDB.open = originalOpen;
  }
  t.end();
});

test("service auth: removed browser session rejects a stale handle", async t => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only session removal test skipped without IndexedDB");
    t.end();
    return;
  }
  const sdk = Pubky.testnet();
  const { session } = await grantSessionFor(sdk, "service-auth-removed.test", "/pub/app/:rw");
  const stored = await sdk.browserSessionStore.save(session);
  const restored = await sdk.browserSessionStore.restore(stored.id);
  await sdk.browserSessionStore.remove(stored.id);
  try {
    await restored.grant!.createServiceAuthProof("inbox");
    t.fail("removed browser session must not create proofs");
  } catch (error) {
    assertPubkyError(t, error);
    t.match(error.message, /removed/i, "removed session is rejected locally");
  }

  t.end();
});

test("BrowserSessionStore: clear removes only keys referenced by stored sessions", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only delegated key cleanup test skipped without IndexedDB");
    t.end();
    return;
  }

  const sdk = Pubky.testnet();
  const store = sdk.browserSessionStore;
  await store.clear();
  await assertBrowserDelegationAvailable(t);

  const stored = await grantSessionFor(
    sdk,
    "session-store-clear-stored.test",
    "/pub/stored-clear/:rw",
  );
  const storedInfo = await store.save(stored.session);

  const ephemeral = await grantSessionFor(
    sdk,
    "session-store-clear-ephemeral.test",
    "/pub/ephemeral-clear/:rw",
  );
  await store.clear();

  try {
    await store.restore(storedInfo.id);
    t.fail("cleared stored session should not be restorable");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "ClientStateError", "cleared stored session is not restorable");
  }

  await ephemeral.session.storage.putText("/pub/ephemeral-clear/test.txt", "test");
  let content = await ephemeral.session.storage.getText("/pub/ephemeral-clear/test.txt");
  t.equal(content, "test", "session not saved to store is still functional after clear");

  t.end();
});

test("BrowserSessionStore: clearAll removes sessions and all delegated keys", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only full auth store cleanup test skipped without IndexedDB");
    t.end();
    return;
  }

  const sdk = Pubky.testnet();
  const store = sdk.browserSessionStore;
  await store.clearAll();
  await assertBrowserDelegationAvailable(t);

  const stored = await grantSessionFor(
    sdk,
    "session-store-clear-all-stored.test",
    "/pub/stored-clear-all/:rw",
  );
  const storedInfo = await store.save(stored.session);

  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);

  const flow = await sdk.startGrantAuthFlow(
    "/pub/pending-clear-all/:rw",
    AuthFlowKind.signin(),
    { clientId: "session-store-clear-all-pending.test", relay: TESTNET_HTTP_RELAY },
  );
  const delegatedState = flow.saveDelegated();
  flow.free();

  await store.clearAll();
  t.deepEqual(await store.list(), [], "clearAll removes stored session records");

  try {
    await store.restore(storedInfo.id);
    t.fail("clearAll should remove the stored delegated session record");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "ClientStateError", "stored delegated session is not restorable");
  }

  try {
    await sdk.resumeDelegatedGrantAuthFlow(delegatedState);
    t.fail("clearAll should remove the pending delegated flow key");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "ClientStateError", "pending delegated flow cannot resume without key");
  }

  t.end();
});

test("BrowserSessionStore: delegated browser pending flow can be resumed", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only pending-flow resume test skipped without IndexedDB");
    t.end();
    return;
  }

  await assertBrowserDelegationAvailable(t);

  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  const user = signer.publicKey.z32();
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);

  const capabilities = "/pub/pubky.app/:rw";
  const flow = await sdk.startGrantAuthFlow(
    capabilities,
    AuthFlowKind.signin(),
    { clientId: "session-store-delegated-resume.test", relay: TESTNET_HTTP_RELAY },
  );
  const savedUrl = flow.authorizationUrl;
  const delegatedState = flow.saveDelegated();
  t.ok(delegatedState.length > 0, "facade selected a delegated browser grant flow");

  flow.free();
  const resumed = await sdk.resumeDelegatedGrantAuthFlow(delegatedState);

  t.equal(
    resumed.authorizationUrl,
    savedUrl,
    "resumed pending flow has the same authorization URL",
  );

  await signer.approveAuthRequest(savedUrl);
  const session = await resumed.awaitApproval();
  t.equal(
    session.info.publicKey.z32(),
    user,
    "resumed grant session belongs to expected user",
  );
  t.deepEqual(
    session.info.capabilities,
    capabilities.split(","),
    "resumed pending session keeps capabilities",
  );
  t.pass("delegated browser pending flow was resumed");

  t.end();
});

test("BrowserSessionStore: delegated pending flow rejects mismatched stored public key", async (t) => {
  if (typeof indexedDB === "undefined") {
    t.comment("browser-only pending-flow resume test skipped without IndexedDB");
    t.end();
    return;
  }

  await assertBrowserDelegationAvailable(t);

  const sdk = Pubky.testnet();
  const flow = await sdk.startGrantAuthFlow(
    "/pub/pubky.app/:rw",
    AuthFlowKind.signin(),
    { clientId: "session-store-delegated-resume-mismatch.test", relay: TESTNET_HTTP_RELAY },
  );
  const delegatedState = flow.saveDelegated();
  const tamperedState = tamperClientPublicKey(delegatedState);
  flow.free();

  try {
    await sdk.resumeDelegatedGrantAuthFlow(tamperedState);
    t.fail("resume should reject when saved public key differs from IndexedDB key");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "ClientStateError", "mismatched delegated key rejects at resume");
    t.match(error.message, /does not match saved flow/i, "error explains key mismatch");
  }

  t.end();
});

/**
 * Assert that the browser runner can exercise real delegated grant keys.
 */
async function assertBrowserDelegationAvailable(t: test.Test): Promise<void> {
  t.equal(typeof indexedDB, "object", "browser runner exposes IndexedDB");
  t.equal(typeof crypto?.subtle, "object", "browser runner exposes WebCrypto");

  const keyPair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    false,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const publicKey = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const signature = await crypto.subtle.sign(
    { name: "Ed25519" },
    keyPair.privateKey,
    new TextEncoder().encode("pubky-delegated-browser-test"),
  );

  t.equal(publicKey.byteLength, 32, "WebCrypto exports 32-byte Ed25519 public keys");
  t.equal(signature.byteLength, 64, "WebCrypto produces 64-byte Ed25519 signatures");
}

/**
 * Create a fresh signed-up user and complete a facade grant auth flow.
 */
async function grantSessionFor(
  sdk: Pubky,
  clientId: string,
  capabilities: Capabilities,
): Promise<{ publicKey: string; session: Session }> {
  const signer = sdk.signer(Keypair.random());
  const publicKey = signer.publicKey.z32();
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);

  const flow = await sdk.startGrantAuthFlow(
    capabilities,
    AuthFlowKind.signin(),
    { clientId, relay: TESTNET_HTTP_RELAY },
  );
  await signer.approveAuthRequest(flow.authorizationUrl);
  const session = await flow.awaitApproval();
  return { publicKey, session };
}

/**
 * Force or clear the browser delegation probe result for fallback tests.
 */
function setBrowserDelegationOverride(value: boolean | undefined): void {
  const key = "__pubkyGrantCanUseDelegationOverride";
  if (value === undefined) {
    Reflect.deleteProperty(globalThis, key);
  } else {
    Reflect.set(globalThis, key, value);
  }
}

function tamperClientPublicKey(savedState: string): string {
  const state = JSON.parse(savedState) as { client_pk: string };
  state.client_pk = Keypair.random().publicKey.z32();
  return JSON.stringify(state);
}

/**
 * Read the object store names from the shared browser auth IndexedDB database.
 */
function pubkyAuthObjectStores(): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("pubky-auth", 1);
    request.onsuccess = () => {
      const db = request.result;
      const names = Array.from(db.objectStoreNames).sort();
      db.close();
      resolve(names);
    };
    request.onerror = () => reject(request.error);
  });
}

function removeSharedSession(id: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("pubky-auth", 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction("storedSessions", "readwrite");
      const store = tx.objectStore("storedSessions");
      const record = store.get(id);
      record.onsuccess = () => {
        delete record.result.sharedSession;
        store.put(record.result);
      };
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = tx.onabort = () => { db.close(); reject(tx.error); };
    };
  });
}

function expireSharedBearer(id: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("pubky-auth", 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction("storedSessions", "readwrite");
      const store = tx.objectStore("storedSessions");
      const record = store.get(id);
      record.onsuccess = () => {
        record.result.sharedSession.response.session.token_expires_at = 0;
        store.put(record.result);
      };
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = tx.onabort = () => { db.close(); reject(tx.error); };
    };
  });
}

function removeDelegatedKey(id: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("pubky-auth", 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction(["storedSessions", "delegatedGrantKeys"], "readwrite");
      const record = tx.objectStore("storedSessions").get(id);
      record.onsuccess = () => {
        const { keyId } = JSON.parse(record.result.credential);
        tx.objectStore("delegatedGrantKeys").delete(keyId);
      };
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = tx.onabort = () => { db.close(); reject(tx.error); };
    };
  });
}
