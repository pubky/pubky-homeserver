import test from "tape";
import { AuthFlowKind, Keypair, Pubky, PublicKey, type Capabilities } from "../index.js";
import { createSignupToken } from "./utils.js";

// Check the persisted layout as well as the public list API.
async function storedSessionIds(): Promise<string[]> {
  const db = await openAuthDatabase();
  try {
    const records = await new Promise<any[]>((resolve, reject) => {
      const request = db.transaction("storedSessions").objectStore("storedSessions").getAll();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
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
  test(`BrowserSessionStore: bare grants and signed approvals share session storage (${delegated ? "delegated" : "local"})`, async t => {
    if (typeof indexedDB === "undefined") {
      t.comment("browser-only session format test");
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
      const clientId = "session-store-formats.test";
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
      t.deepEqual(await storedSessionIds(), [original.id], "re-saving a bare grant keeps one stored record");

      // Signed approvals without e still use storage V2, even with an empty
      // bundle. All formats use the same session store.
      const empty = await store.save(await authorize("signedApprovalV1"));
      const emptyKeys = (await store.restore(empty.id)).grant!.encryptionKeys!;
      t.deepEqual(emptyKeys.scopes, [], "signed approval without e restores an empty bundle");
      emptyKeys.free();
      t.deepEqual(await storedSessionIds(), [original.id, empty.id].sort(), "bare grants and empty signed approvals use storedSessions");

      const sessionWithKeys = await authorize("signedApprovalV1", "/pub/compat/:rwe");
      const saved = await store.save(sessionWithKeys);
      const keys = sessionWithKeys.grant!.encryptionKeys!;
      const key = keys.deriveForPath("/pub/compat/value");
      t.notEqual(saved.id, original.id, "reauthorization creates a separate record");
      t.equal(saved.clientId, original.clientId, "both grants belong to the same client");
      t.equal(saved.storageMode, delegated ? "delegated" : "localSecret", "requested storage mode is exercised");
      t.deepEqual(await storedSessionIds(), [original.id, empty.id, saved.id].sort(), "signed approvals with keys also use storedSessions");
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
      t.ok((await store.list()).some(record => record.id === later.id), "current SDK lists a bare grant saved after signed approvals");
      t.deepEqual(await storedSessionIds(), [original.id, empty.id, saved.id, later.id].sort(), "later bare grants share the same store");
      t.equal((await store.restore(original.id)).grant!.encryptionKeys, undefined, "original bare grant never gains keys");
      await store.remove(saved.id);
      t.equal((await store.list()).length, 3, "removing a signed approval preserves the other grants");
      t.deepEqual(await storedSessionIds(), [original.id, empty.id, later.id].sort(), "removing one approval preserves the other stored records");
      await store.clear();
      t.deepEqual(await store.list(), [], "clear removes both record formats");
      t.deepEqual(await storedSessionIds(), [], "clear removes all persisted session records");
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
