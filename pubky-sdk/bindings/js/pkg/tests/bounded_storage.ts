import test from "tape";
import { Keypair, Pubky, PublicKey, type Path } from "../index.js";
import { assertPubkyError, createSignupToken, getStatusCode } from "./utils.js";

const PATH: Path = "/priv/bounded-reader/value";
const SUFFIX = "\n[response body truncated at 4096 bytes]";

test("checked storage bounds and cancels error bodies", async (t) => {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  const homeserver = PublicKey.from(
    "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo",
  );
  await signer.signup(homeserver, await createSignupToken());
  const session = await signer.signin("bounded-reader.test");
  await session.storage.exists(PATH); // Warm discovery before intercepting GET.
  const originalFetch = globalThis.fetch;
  const encoder = new TextEncoder();
  try {
    for (const parts of [["x".repeat(8192)], ["x".repeat(4096), "y"]]) {
      let cancelled = false;
      let pulled = 0;
      let intercepted = 0;
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = input instanceof Request ? input : new Request(input, init);
        if (!new URL(request.url).pathname.endsWith(PATH)) {
          return originalFetch(input, init);
        }
        intercepted += 1;
        t.ok(request.headers.has("authorization"), "GET remains authenticated");
        const body = new ReadableStream<Uint8Array>(
          {
            pull(controller) {
              if (pulled < parts.length) {
                controller.enqueue(encoder.encode(parts[pulled++]));
              }
              // No EOF: status handling must stop at overflow.
            },
            cancel() {
              cancelled = true;
            },
          },
          { highWaterMark: 0 },
        );
        const response = new Response(body, { status: 500 });
        Object.defineProperty(response, "url", { value: request.url });
        return response;
      }) as typeof fetch;
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          session.storage.get(PATH),
          new Promise<never>((_, reject) => {
            timer = setTimeout(
              () => reject(new Error("error reader waited for EOF")),
              5000,
            );
          }),
        ]);
        t.fail("500 must reject checked GET");
      } catch (error) {
        assertPubkyError(t, error);
        t.equal(getStatusCode(error), 500, "original status survives");
        t.ok(
          error.message.endsWith("x".repeat(4096) + SUFFIX),
          "bounded prefix and truncation marker",
        );
      } finally {
        clearTimeout(timer);
      }
      t.equal(intercepted, 1, "one storage GET");
      await new Promise((resolve) => setTimeout(resolve, 0));
      t.ok(cancelled, "overflow cancels the response stream");
    }

    for (const [status, body] of [
      [500, ""],
      [500, "small"],
      [500, "x".repeat(4096)],
      [500, "\ufeffhello"],
      [200, "success"],
    ] as const) {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = input instanceof Request ? input : new Request(input, init);
        if (!new URL(request.url).pathname.endsWith(PATH)) {
          return originalFetch(input, init);
        }
        const response = new Response(encoder.encode(body), { status });
        Object.defineProperty(response, "url", { value: request.url });
        return response;
      }) as typeof fetch;
      try {
        const response = await session.storage.get(PATH);
        t.equal(status, 200, "only success returns a response");
        t.equal(await response.text(), body, "success body remains readable");
      } catch (error) {
        assertPubkyError(t, error);
        t.equal(getStatusCode(error), status, "small error status preserved");
        t.equal(
          error.message,
          `Request failed: Server responded with an error: 500 Internal Server Error - ${body.replace(/^\ufeff/, "")}`,
          "complete errors preserve browser text decoding",
        );
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
  t.end();
});
