import test, { type Test } from "tape";
import { Client, Keypair, Pubky, PublicKey, type Path } from "../index.js";
import { assertPubkyError, createSignupToken, getStatusCode } from "./utils.js";

const PATH: Path = "/priv/bounded-reader/value";
const ERROR_PREFIX = "Request failed: Server responded with an error: 500 Internal Server Error - ";

async function createSigner(maxErrorBodyBytes: number | undefined) {
  const sdk = Pubky.withClient(new Client({
    maxErrorBodyBytes,
    pkarr: { relays: ["http://localhost:15411/"] },
  }));
  const signer = sdk.signer(Keypair.random());
  const homeserver = PublicKey.from(
    "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo",
  );
  await signer.signup(homeserver, await createSignupToken());
  return signer;
}

async function assertServerError(t: Test, request: Promise<unknown>, message: string) {
  try {
    await request;
    t.fail("request must reject HTTP 500");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(getStatusCode(error), 500, "original status survives");
    t.equal(error.message, ERROR_PREFIX + message, "expected diagnostic message");
  }
}

for (const setting of [undefined, 16, 8192, 0]) {
  const label = setting ?? "default";
  const limit = setting ?? 4096;
  const overflowMessage = limit === 0
    ? "Internal Server Error"
    : "x".repeat(limit) + `\n[response body truncated at ${limit} bytes]`;

  test(`storage stops reading oversized errors: limit ${label}`, async (t) => {
    const signer = await createSigner(setting);
    const session = await signer.signin("bounded-reader.test");
    await session.storage.exists(PATH);
    const originalFetch = globalThis.fetch;
    const encoder = new TextEncoder();
    const chunkings = limit === 0
      ? [[]]
      : [["x".repeat(limit + 1)], ["x".repeat(limit), "y"]];

    for (const chunks of chunkings) {
      let cancelled = false;
      let pulls = 0;
      let timer: ReturnType<typeof setTimeout> | undefined;
      globalThis.fetch = async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        if (!new URL(request.url).pathname.endsWith(PATH)) return originalFetch(input, init);
        t.ok(request.headers.has("authorization"), "GET remains authenticated");
        const body = new ReadableStream<Uint8Array>({
          pull(controller) {
            const chunk = chunks[pulls++];
            if (chunk !== undefined) controller.enqueue(encoder.encode(chunk));
            // Withhold EOF to catch readers that drain the body.
          },
          cancel() { cancelled = true; },
        }, { highWaterMark: 0 });
        const response = new Response(body, { status: 500 });
        Object.defineProperty(response, "url", { value: request.url });
        return response;
      };

      try {
        const deadline = new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error("reader waited for EOF")), 5000);
        });
        await assertServerError(t, Promise.race([session.storage.get(PATH), deadline]), overflowMessage);
        await new Promise((resolve) => setTimeout(resolve, 0));
        t.ok(cancelled, "error reader releases the stream");
        if (limit === 0) t.equal(pulls, 0, "zero limit never polls the body");
      } finally {
        clearTimeout(timer);
        globalThis.fetch = originalFetch;
      }
    }
    t.end();
  });

  test(`storage preserves complete bodies: limit ${label}`, async (t) => {
    const signer = await createSigner(setting);
    const session = await signer.signin("bounded-reader.test");
    await session.storage.exists(PATH);
    const originalFetch = globalThis.fetch;
    const cases = [
      { status: 500, body: "" },
      { status: 500, body: "small" },
      { status: 500, body: "\ufeffhello" },
      { status: 500, body: "x".repeat(limit) },
      { status: 200, body: "successful body" },
    ];

    for (const { status, body } of cases) {
      globalThis.fetch = async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        if (!new URL(request.url).pathname.endsWith(PATH)) return originalFetch(input, init);
        t.ok(request.headers.has("authorization"), "GET remains authenticated");
        const response = new Response(body, { status });
        Object.defineProperty(response, "url", { value: request.url });
        return response;
      };

      try {
        if (status === 200) {
          const response = await session.storage.get(PATH);
          t.equal(await response.text(), body, "success body remains readable");
        } else {
          const message = limit === 0 ? "Internal Server Error" : body.replace(/^\ufeff/, "");
          await assertServerError(t, session.storage.get(PATH), message);
        }
      } finally {
        globalThis.fetch = originalFetch;
      }
    }
    t.end();
  });

  test(`refresh errors prevent the storage GET: limit ${label}`, async (t) => {
    const signer = await createSigner(setting);
    const originalFetch = globalThis.fetch;
    let exchanges = 0;
    let storageSent = false;
    globalThis.fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const path = new URL(request.url).pathname;
      if (!path.endsWith("/auth/grant/session") || request.method !== "POST") {
        if (path.endsWith(PATH)) storageSent = true;
        return originalFetch(input, init);
      }

      let response: Response;
      if (exchanges++ === 0) {
        const issued = await originalFetch(input, init);
        const body = await issued.json();
        body.session.token_expires_at = 0;
        response = new Response(JSON.stringify(body), { status: issued.status });
      } else {
        response = new Response("x".repeat(limit + 1), { status: 500 });
      }
      Object.defineProperty(response, "url", { value: request.url });
      return response;
    };

    try {
      const session = await signer.signin("bounded-reader.test");
      await assertServerError(t, session.storage.get(PATH), overflowMessage);
      t.equal(exchanges, 2, "expired bearer triggers a refresh");
      t.notOk(storageSent, "failed refresh prevents the storage GET");
    } finally {
      globalThis.fetch = originalFetch;
    }
    t.end();
  });
}
