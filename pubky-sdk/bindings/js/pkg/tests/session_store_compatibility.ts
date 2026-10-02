import test from "tape";
import { AuthFlowKind, Keypair, Pubky, PublicKey, type Capabilities } from "../index.js";
import { createSignupToken } from "./utils.js";

// Read the same database version and object store as pre-encryption SDKs.
// Those SDKs reject their entire list if any row has a version other than V1.
async function legacySessionIds(): Promise<string[]> {
  const db = await openAuthDatabase();
  try {
    const records = await new Promise<any[]>((resolve, reject) => {
      const request = db.transaction("storedSessions").objectStore("storedSessions").getAll();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    for (const record of records) {
      if (record.version !== "pubky-session-v1") {
        throw new Error("Unsupported stored session version.");
      }
    }
    return records.map(record => record.id).sort();
  } finally { db.close(); }
}

function openAuthDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("pubky-auth", 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Reproduce a record saved by an earlier encryption draft, including its
// encrypted approval and wrapping key. Migration must not change its AAD.
async function moveToLegacyStore(id: string): Promise<void> {
  const db = await openAuthDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(["storedSessions", "delegatedGrantKeys"], "readwrite");
      const keys = tx.objectStore("delegatedGrantKeys");
      const request = keys.get(`session:${id}`);
      request.onsuccess = () => {
        const { keyId, ...record } = request.result;
        tx.objectStore("storedSessions").put(record);
        keys.delete(keyId);
      };
      tx.oncomplete = () => resolve();
      tx.onerror = tx.onabort = () => reject(tx.error);
    });
  } finally { db.close(); }
}

for (const delegated of [false, true]) {
  test(`BrowserSessionStore: Grant to V1 compatibility (${delegated ? "delegated" : "local"})`, async t => {
    if (typeof indexedDB === "undefined") {
      t.comment("browser-only compatibility test");
      t.end();
      return;
    }
    const sdk = Pubky.testnet();
    const store = sdk.browserSessionStore;
    await store.clearAll();
    Reflect.set(globalThis, "__pubkyGrantCanUseDelegationOverride", delegated);
    try {
      const signer = sdk.signer(Keypair.random());
      await signer.signup(
        PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo"),
        await createSignupToken(),
      );
      const clientId = "session-store-compatibility.test";
      async function authorize(approvalFormat: "grant" | "v1", capabilities: Capabilities = "/pub/compat/:rw") {
        const flow = await sdk.startGrantAuthFlow(capabilities, AuthFlowKind.signin(), {
          clientId, approvalFormat, relay: "http://localhost:15412/inbox",
        });
        await signer.approveAuthRequest(flow.authorizationUrl);
        return flow.awaitApproval();
      }

      const grant = await authorize("grant");
      const original = await store.save(grant);
      const restoredGrant = await store.restore(original.id);
      t.equal(restoredGrant.grant!.encryptionScopes, undefined, "Grant restores without keys");
      await store.save(restoredGrant);
      t.deepEqual(await legacySessionIds(), [original.id], "re-saving Grant keeps it visible to old SDKs");

      // V1 without e still retains a signed approval; old readers must not see
      // that V2 row even though the bundle is empty.
      const empty = await store.save(await authorize("v1"));
      t.deepEqual((await store.restore(empty.id)).grant!.encryptionScopes, [], "V1 without e restores an empty bundle");
      t.deepEqual(await legacySessionIds(), [original.id], "empty V1 approval does not break old session listing");

      const keyed = await authorize("v1", "/pub/compat/:rwe");
      const saved = await store.save(keyed);
      const key = keyed.grant!.deriveEncryptionKey("/pub/compat/value");
      t.notEqual(saved.id, original.id, "reauthorization creates a separate record");
      t.equal(saved.clientId, original.clientId, "both grants belong to the same client");
      t.equal(saved.storageMode, delegated ? "delegated" : "localSecret", "requested storage mode is exercised");
      t.deepEqual(await legacySessionIds(), [original.id], "key-bearing V1 does not break old session listing");
      const restored = await store.restore(saved.id);
      t.deepEqual(restored.grant!.deriveEncryptionKey("/pub/compat/value"), key, "V1 keys survive restore");
      await restored.storage.putText("/pub/compat/value", "shared storage");
      t.equal(await restoredGrant.storage.getText("/pub/compat/value"), "shared storage", "original Grant still reads storage");
      await store.save(restoredGrant);
      t.deepEqual((await store.restore(saved.id)).grant!.deriveEncryptionKey("/pub/compat/value"), key, "re-saving original Grant preserves V1 keys");

      await moveToLegacyStore(saved.id);
      t.equal((await store.list()).length, 3, "current SDK lists both formats after migration");
      t.deepEqual(await legacySessionIds(), [original.id], "migration removes V2 from the legacy list");
      t.deepEqual((await store.restore(saved.id)).grant!.deriveEncryptionKey("/pub/compat/value"), key, "migration preserves approval and content keys");
      t.deepEqual((await store.restoreEncryptionKeys(saved.id))!.deriveForPath("/pub/compat/value"), key, "migration preserves offline recovery");

      const later = await store.save(await authorize("grant"));
      t.deepEqual(await legacySessionIds(), [original.id, later.id].sort(), "Grant requested after V1 stays compatible");
      t.equal((await store.restore(original.id)).grant!.encryptionScopes, undefined, "original Grant never gains keys");
      await store.remove(saved.id);
      t.equal((await store.list()).length, 3, "removing V1 preserves the other grants");
      await store.clear();
      t.deepEqual(await store.list(), [], "clear removes both record formats");
      t.deepEqual(await legacySessionIds(), [], "legacy list is also cleared");
      key.fill(0);
    } finally {
      Reflect.deleteProperty(globalThis, "__pubkyGrantCanUseDelegationOverride");
      await store.clearAll();
    }
    t.end();
  });
}
