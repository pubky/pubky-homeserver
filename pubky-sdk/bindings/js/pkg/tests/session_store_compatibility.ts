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

for (const delegated of [false, true]) {
  test(`BrowserSessionStore: bare grant and signed approval compatibility (${delegated ? "delegated" : "local"})`, async t => {
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
      async function authorize(approvalFormat: "bareGrant" | "signedApprovalV1", capabilities: Capabilities = "/pub/compat/:rw") {
        const flow = await sdk.startGrantAuthFlow(capabilities, AuthFlowKind.signin(), {
          clientId, approvalFormat, relay: "http://localhost:15412/inbox",
        });
        await signer.approveAuthRequest(flow.authorizationUrl);
        return flow.awaitApproval();
      }

      const grant = await authorize("bareGrant");
      const original = await store.save(grant);
      const restoredGrant = await store.restore(original.id);
      t.equal(restoredGrant.grant!.encryptionKeys, undefined, "Grant restores without keys");
      await store.save(restoredGrant);
      t.deepEqual(await legacySessionIds(), [original.id], "re-saving a bare grant keeps it visible to old SDKs");

      // Signed approvals without e still use storage V2, even with an empty
      // bundle. Old readers must not see these records.
      const empty = await store.save(await authorize("signedApprovalV1"));
      const emptyKeys = (await store.restore(empty.id)).grant!.encryptionKeys!;
      t.deepEqual(emptyKeys.scopes, [], "signed approval without e restores an empty bundle");
      emptyKeys.free();
      t.deepEqual(await legacySessionIds(), [original.id], "empty signed approval does not break old session listing");

      const sessionWithKeys = await authorize("signedApprovalV1", "/pub/compat/:rwe");
      const saved = await store.save(sessionWithKeys);
      const keys = sessionWithKeys.grant!.encryptionKeys!;
      const key = keys.deriveForPath("/pub/compat/value");
      t.notEqual(saved.id, original.id, "reauthorization creates a separate record");
      t.equal(saved.clientId, original.clientId, "both grants belong to the same client");
      t.equal(saved.storageMode, delegated ? "delegated" : "localSecret", "requested storage mode is exercised");
      t.deepEqual(await legacySessionIds(), [original.id], "signed approval with keys does not break old session listing");
      const restored = await store.restore(saved.id);
      const restoredKeys = restored.grant!.encryptionKeys!;
      t.deepEqual(restoredKeys.deriveForPath("/pub/compat/value"), key, "scoped keys survive restore");
      await restored.storage.putText("/pub/compat/value", "shared storage");
      t.equal(await restoredGrant.storage.getText("/pub/compat/value"), "shared storage", "original bare grant still reads storage");
      await store.save(restoredGrant);
      const resavedKeys = (await store.restore(saved.id)).grant!.encryptionKeys!;
      t.deepEqual(resavedKeys.deriveForPath("/pub/compat/value"), key, "re-saving original bare grant preserves scoped keys");

      t.equal((await store.list()).length, 3, "current SDK lists both formats");
      const offlineKeys = (await store.restoreEncryptionKeys(saved.id))!;
      t.deepEqual(offlineKeys.deriveForPath("/pub/compat/value"), key, "signed approval preserves offline recovery");

      const later = await store.save(await authorize("bareGrant"));
      t.deepEqual(await legacySessionIds(), [original.id, later.id].sort(), "bare grant requested after signed approval stays compatible");
      t.equal((await store.restore(original.id)).grant!.encryptionKeys, undefined, "original bare grant never gains keys");
      await store.remove(saved.id);
      t.equal((await store.list()).length, 3, "removing a signed approval preserves the other grants");
      await store.clear();
      t.deepEqual(await store.list(), [], "clear removes both record formats");
      t.deepEqual(await legacySessionIds(), [], "legacy list is also cleared");
      key.fill(0);
      keys.free();
      restoredKeys.free();
      resavedKeys.free();
      offlineKeys.free();
    } finally {
      Reflect.deleteProperty(globalThis, "__pubkyGrantCanUseDelegationOverride");
      await store.clearAll();
    }
    t.end();
  });
}
