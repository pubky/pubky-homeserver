import test from "tape";
import { Client, Keypair, Pubky, PublicKey, type Path, type StorageLock } from "../index.js";
import {
  type Assert,
  type IsExact,
  assertPubkyError,
  createSignupToken,
  getStatusCode,
  mockStreamingResponse,
} from "./utils.js";

const HOMESERVER = PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo");
const PATH: Path = "/priv/blob-upload/value.bin";

type Session = Awaited<ReturnType<ReturnType<Pubky["signer"]>["signin"]>>;
type _PutBlob = Assert<IsExact<Parameters<Session["storage"]["putBlob"]>, [Path, Blob]>>;
type _PutBlobLocked = Assert<IsExact<Parameters<Session["storage"]["putBlobLocked"]>, [StorageLock, Blob]>>;

for (const credential of ["cookie", "grant"]) {
  test(`putBlob uploads Blob and File with ${credential} authentication`, async (t) => {
    const sdk = Pubky.testnet();
    const signer = sdk.signer(Keypair.random());
    const token = await createSignupToken();
    const cookie = credential === "cookie" ? await signer.signupCookie(HOMESERVER, token) : undefined;
    if (credential === "grant") await signer.signup(HOMESERVER, token);
    const originalFetch = globalThis.fetch;
    let uploads = 0;
    let exchanges = 0;
    let requests = 0;
    globalThis.fetch = async (input, init) => {
      requests++;
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.method === "PUT") {
        uploads++;
        t.equal(request.credentials, "include", "cookie transport is preserved");
        t.equal(request.headers.has("authorization"), credential === "grant", "session authentication is preserved");
      }
      const response = await originalFetch(input, init);
      if (request.method === "POST" && new URL(request.url).pathname.endsWith("/auth/grant/session")) {
        if (exchanges++ === 0) {
          const body = await response.json();
          body.session.token_expires_at = 0;
          const expired = new Response(JSON.stringify(body), { status: response.status });
          Object.defineProperty(expired, "url", { value: request.url });
          return expired;
        }
      }
      return response;
    };
    try {
      const session = cookie ?? await signer.signin("blob-upload.test");
      const bodies = [
        new Blob([new Uint8Array([0, 128, 255])]),
        new File(["file contents"], "value.bin"),
        new Blob([]),
      ];
      for (const body of bodies) {
        await session.storage.putBlob(PATH, body);
        const response = await session.storage.get(PATH);
        t.deepEqual(
          new Uint8Array(await response.arrayBuffer()),
          new Uint8Array(await body.arrayBuffer()),
          "stored bytes match",
        );
      }
      t.equal(uploads, 3, "each upload sends one PUT");
      if (credential === "grant") t.equal(exchanges, 2, "expired bearer refreshes before upload");
      await session.storage.putText(PATH, "original contents");
      for (const body of [undefined, null, "not a Blob", new Uint8Array([1]), {}]) {
        const before = requests;
        try {
          // @ts-expect-error Exercise runtime validation for invalid JavaScript inputs.
          await session.storage.putBlob(PATH, body);
          t.fail("non-Blob body must reject");
        } catch (error) {
          assertPubkyError(t, error);
          t.equal(error.name, "InvalidInput", "non-Blob body rejects with InvalidInput");
        }
        t.equal(requests, before, "invalid body never sends a request");
        t.equal(await session.storage.getText(PATH), "original contents", "invalid body preserves the existing file");
      }
      await session.storage.delete(PATH);
      await session.signout();
      try {
        await session.storage.putBlob(PATH, new Blob(["revoked"]));
        t.fail("signed-out session must reject");
      } catch (error) {
        assertPubkyError(t, error);
        t.equal(getStatusCode(error), 401, "signed-out session rejects with HTTP 401");
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
    t.end();
  });

  test(`putBlobLocked uploads under a file lock with ${credential} authentication`, async (t) => {
    const sdk = Pubky.testnet();
    const signer = sdk.signer(Keypair.random());
    const token = await createSignupToken();
    const cookie = credential === "cookie" ? await signer.signupCookie(HOMESERVER, token) : undefined;
    if (credential === "grant") await signer.signup(HOMESERVER, token);
    const session = cookie ?? await signer.signin("blob-upload.test");
    const storage = session.storage;
    const lock = await storage.lock(PATH, 30);

    await storage.putBlob(PATH, new Blob(["unlocked write"])).then(
      () => t.fail("plain Blob upload to a locked path must reject"),
      (error) => { assertPubkyError(t, error); t.equal(getStatusCode(error), 423); },
    );
    for (const body of [
      new Blob([new Uint8Array([0, 128, 255])]),
      new File(["file contents"], "value.bin"),
      new Blob([]),
    ]) {
      await storage.putBlobLocked(lock, body);
      t.deepEqual(
        await storage.getBytes(PATH),
        new Uint8Array(await body.arrayBuffer()),
        "locked upload preserves contents",
      );
    }

    await storage.putTextLocked(lock, "original contents");
    const originalFetch = globalThis.fetch;
    let requests = 0;
    globalThis.fetch = (...args) => { requests++; return originalFetch(...args); };
    try {
      for (const body of [undefined, null, "not a Blob", new Uint8Array([1]), {}]) {
        // @ts-expect-error Exercise runtime validation for invalid JavaScript inputs.
        await storage.putBlobLocked(lock, body).then(
          () => t.fail("non-Blob body must reject"),
          (error) => { assertPubkyError(t, error); t.equal(error.name, "InvalidInput"); },
        );
      }
      t.equal(requests, 0, "invalid bodies never send a request");
    } finally {
      globalThis.fetch = originalFetch;
    }
    t.equal(await storage.getText(PATH), "original contents", "invalid bodies preserve the file");

    await storage.unlock(lock);
    await storage.putBlobLocked(lock, new Blob(["stale write"])).then(
      () => t.fail("released lock must reject"),
      (error) => { assertPubkyError(t, error); t.equal(getStatusCode(error), 412); },
    );
    t.equal(await storage.getText(PATH), "original contents", "stale lock preserves the file");
    await storage.delete(PATH);
    await session.signout();
    t.end();
  });
}

for (const limit of [0, 16]) {
  test(`putBlob preserves bounded HTTP errors and path validation: limit ${limit}`, async (t) => {
    const sdk = Pubky.withClient(new Client({
      maxErrorBodyBytes: limit,
      pkarr: { relays: ["http://localhost:15411/"] },
    }));
    const signer = sdk.signer(Keypair.random());
    await signer.signup(HOMESERVER, await createSignupToken());
    const session = await signer.signin("blob-upload.test");
    await session.storage.exists(PATH);
    let puts = 0;
    const response = mockStreamingResponse([new TextEncoder().encode("x".repeat(limit + 1))], {
      matches: (request) => request.method === "PUT",
      response: { status: 507 },
      onRequest: () => { puts++; },
    });
    try {
      try {
        await session.storage.putBlob(PATH, new Blob(["contents"]));
        t.fail("HTTP error must reject");
      } catch (error) {
        assertPubkyError(t, error);
        t.equal(getStatusCode(error), 507, "original HTTP status survives");
        t.equal(
          error.message,
          "Request failed: Server responded with an error: 507 Insufficient Storage - "
            + (limit === 0 ? "Insufficient Storage" : "x".repeat(limit) + `\n[response body truncated at ${limit} bytes]`),
          "error body follows the client limit",
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 0));
      t.ok(response.cancelled, "unread error body is cancelled");
      if (limit === 0) t.equal(response.pulls, 0, "zero limit does not read the body");
      // @ts-expect-error Exercise runtime validation with an invalid storage path.
      await session.storage.putBlob("", new Blob([])).then(
        () => t.fail("invalid path must reject"),
        (error) => { assertPubkyError(t, error); t.equal(error.name, "RequestError"); },
      );
      t.equal(puts, 1, "invalid path never sends a PUT");
    } finally {
      response.restore();
    }
    t.end();
  });
}
