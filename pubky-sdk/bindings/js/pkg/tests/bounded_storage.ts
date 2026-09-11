import test from "tape";
import { Client, Keypair, Pubky, PublicKey, type Path } from "../index.js";
import { assertPubkyError, createSignupToken, getStatusCode } from "./utils.js";

const PATH: Path = "/priv/bounded-reader/value";
const errorPrefix = "Request failed: Server responded with an error: 500 Internal Server Error - ";

for (const setting of [undefined, 16, 8192, 0]) {
  test(`checked storage error-body limit: ${setting ?? "default"}`, async (t) => {
    const limit = setting ?? 4096;
    const sdk = Pubky.withClient(new Client({
      maxErrorBodyBytes: setting,
      pkarr: { relays: ["http://localhost:15411/"] },
    }));
    const signer = sdk.signer(Keypair.random());
    const homeserver = PublicKey.from(
      "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo",
    );
    await signer.signup(homeserver, await createSignupToken());
    const session = await signer.signin("bounded-reader.test");
    await session.storage.exists(PATH);
    const originalFetch = globalThis.fetch;
    const encoder = new TextEncoder();
    let reply: () => Response;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (!new URL(request.url).pathname.endsWith(PATH)) return originalFetch(input, init);
      t.ok(request.headers.has("authorization"), "GET remains authenticated");
      const response = reply();
      Object.defineProperty(response, "url", { value: request.url });
      return response;
    }) as typeof fetch;
    try {
      const bodies = limit === 0 ? [[]] : [["x".repeat(limit + 1)], ["x".repeat(limit), "y"]];
      for (const parts of bodies) {
        let cancelled = false;
        let pulled = 0;
        reply = () => new Response(new ReadableStream<Uint8Array>({
          pull(controller) {
            const part = parts[pulled++];
            if (part !== undefined) controller.enqueue(encoder.encode(part));
            // Withhold EOF to catch readers that drain the body.
          },
          cancel() { cancelled = true; },
        }, { highWaterMark: 0 }), { status: 500 });
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          await Promise.race([
            session.storage.get(PATH),
            new Promise<never>((_, reject) => {
              timer = setTimeout(() => reject(new Error("reader waited for EOF")), 5000);
            }),
          ]);
          t.fail("checked GET must reject 500");
        } catch (error) {
          assertPubkyError(t, error);
          t.equal(getStatusCode(error), 500, "original status survives");
          const message = limit === 0
            ? "Internal Server Error"
            : "x".repeat(limit) + `\n[response body truncated at ${limit} bytes]`;
          t.equal(error.message, errorPrefix + message, "configured diagnostic limit");
        } finally {
          clearTimeout(timer);
        }
        await new Promise((resolve) => setTimeout(resolve, 0));
        t.ok(cancelled, "error reader releases the stream");
        if (limit === 0) t.equal(pulled, 0, "zero limit never polls the body");
      }

      for (const body of ["", "small", "\ufeffhello", "x".repeat(limit)]) {
        reply = () => new Response(encoder.encode(body), { status: 500 });
        try {
          await session.storage.get(PATH);
          t.fail("checked GET must reject 500");
        } catch (error) {
          assertPubkyError(t, error);
          const message = limit === 0 ? "Internal Server Error" : body.replace(/^\ufeff/, "");
          t.equal(error.message, errorPrefix + message, "complete error text");
        }
      }
      // Successful bodies are independent of the error-body setting, even at zero.
      reply = () => new Response("successful body", { status: 200 });
      const response = await session.storage.get(PATH);
      t.equal(await response.text(), "successful body", "success body remains readable");

      let exchanges = 0;
      let storageSent = false;
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
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
      }) as typeof fetch;
      const expiring = await signer.signin("bounded-reader.test");
      try {
        await expiring.storage.get(PATH);
        t.fail("refresh error must reject the storage read");
      } catch (error) {
        assertPubkyError(t, error);
        t.equal(getStatusCode(error), 500, "refresh status survives");
        const message = limit === 0
          ? "Internal Server Error"
          : "x".repeat(limit) + `\n[response body truncated at ${limit} bytes]`;
        t.equal(error.message, errorPrefix + message, "refresh uses the client limit");
      }
      t.equal(exchanges, 2, "expired bearer triggers a refresh");
      t.notOk(storageSent, "failed refresh prevents the storage GET");
    } finally {
      globalThis.fetch = originalFetch;
    }
    t.end();
  });
}
