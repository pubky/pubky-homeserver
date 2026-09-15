import test from "tape";
import { Keypair, Pubky, PublicKey } from "../index.js";
import { assertPubkyError } from "./utils.js";

const HOMESERVER = PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo");
const USER = Keypair.random().publicKey;

function subscription(sdk: Pubky, limit?: number) {
  const builder = sdk.eventStreamFor(HOMESERVER).addUsers([[USER.z32(), null]]);
  return limit === undefined ? builder : builder.maxEventBytes(limit);
}

function event(cursor: number, path = "/pub/café") {
  return `event: DEL\ndata: pubky://${USER.z32()}${path}\ndata: cursor: ${cursor}\n\n`;
}

function mockEventResponse(chunks: Uint8Array[]) {
  const originalFetch = globalThis.fetch;
  const state = {
    pulls: 0,
    cancelled: false,
    restore() { globalThis.fetch = originalFetch; },
  };
  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    if (new URL(request.url).pathname !== "/events-stream") return originalFetch(input, init);
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        const chunk = chunks[state.pulls++];
        if (chunk !== undefined) controller.enqueue(chunk);
        // Withhold EOF to catch readers that wait for the response to close.
      },
      cancel() { state.cancelled = true; },
    }, { highWaterMark: 0 });
    const response = new Response(body, { headers: { "content-type": "text/event-stream" } });
    Object.defineProperty(response, "url", { value: request.url });
    return response;
  };
  return state;
}

test("event byte limit rejects invalid JavaScript numbers", (t) => {
  const sdk = Pubky.testnet();
  for (const limit of [0, -1, 1.5, NaN, Infinity, -Infinity, 4294967296]) {
    try {
      subscription(sdk, limit);
      t.fail(`accepted ${limit}`);
    } catch (error) {
      assertPubkyError(t, error);
      t.equal(error.name, "InvalidInput");
    }
  }
  for (const limit of [1, 4096, 4294967295]) {
    subscription(sdk, limit).free();
    t.pass(`accepts ${limit}`);
  }
  t.end();
});

for (const limit of [4096, 256, 8192]) {
  test(`oversized SSE cancels the response: ${limit}`, async (t) => {
    const sdk = Pubky.testnet();
    const encoder = new TextEncoder();
    const valid = event(42);
    const oversized = `data: pubky://${USER.z32()}/pub/${"x".repeat(limit + 1)}`;
    for (const live of [false, true]) {
      for (const chunks of [[valid + oversized], [valid, oversized.slice(0, limit), oversized.slice(limit)]]) {
        const response = mockEventResponse(chunks.map((chunk) => encoder.encode(chunk)));
        let timer: ReturnType<typeof setTimeout> | undefined;

        let reader: ReadableStreamDefaultReader | undefined;
        try {
          let builder = subscription(sdk, limit);
          if (live) builder = builder.live();
          const stream = await builder.subscribe();
          reader = stream.getReader();
          t.equal((await reader.read()).value.cursor, "42", "prior valid event survives");
          const deadline = new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error("SSE decoder waited for EOF")), 5000);
          });
          try {
            await Promise.race([reader.read(), deadline]);
            t.fail("overflow must reject the read");
          } catch (error) {
            assertPubkyError(t, error);
            t.ok(error.message.includes(`SSE event exceeds the configured limit of ${limit} bytes`));
          }
          await new Promise((resolve) => setTimeout(resolve, 0));
          t.ok(response.cancelled, "underlying response cancelled while reader is retained");
          t.equal(response.pulls, chunks.length, "no read past the overflowing chunk");
        } finally {
          clearTimeout(timer);
          reader?.releaseLock();
          response.restore();
        }
      }
    }
    t.end();
  });
}

test("SSE event size is unbounded by default in historical and live mode", async (t) => {
  const sdk = Pubky.testnet();
  const encoder = new TextEncoder();
  for (const pathBytes of [4096, 16384]) {
    // Includes the legacy homeserver path maximum, whose frame exceeds 4 KiB.
    const path = `/pub/${`${"a".repeat(255)}/`.repeat(Math.floor((pathBytes - 5) / 256))}${"b".repeat((pathBytes - 5) % 256)}`;
    for (const live of [false, true]) {
      const response = mockEventResponse([encoder.encode(event(42, path))]);
      let reader: ReadableStreamDefaultReader | undefined;
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        let builder = subscription(sdk);
        if (live) builder = builder.live();
        reader = (await builder.subscribe()).getReader();
        const deadline = new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error("Unbounded SSE waited for EOF")), 5000);
        });
        const result = await Promise.race([reader.read(), deadline]);
        t.equal(result.value.cursor, "42");
        t.equal(result.value.resource.path, path, `accepts ${pathBytes}-byte path, live=${live}`);
        await reader.cancel();
        t.ok(response.cancelled, "caller cancellation releases the unbounded response");
      } finally {
        clearTimeout(timer);
        reader?.releaseLock();
        response.restore();
      }
    }
  }
  t.end();
});

test("SSE limits allow long streams, fragmented UTF-8 and explicit cancellation", async (t) => {
  const sdk = Pubky.testnet();
  const encoder = new TextEncoder();
  const body = encoder.encode(Array.from({ length: 100 }, (_, i) => `:keepalive\n\n${event(i)}`).join(""));
  for (const fragmented of [false, true]) {
    const chunks = fragmented ? Array.from(body, (byte) => Uint8Array.of(byte)) : [body];
    const response = mockEventResponse(chunks);
    try {
      const reader = (await subscription(sdk, 128).live().subscribe()).getReader();
      try {
        for (let i = 0; i < 100; i++) {
          const result = await reader.read();
          t.equal(result.value.cursor, String(i));
          t.equal(result.value.resource.path, "/pub/caf%C3%A9");
        }
        await reader.cancel();
        t.ok(response.cancelled, "caller cancellation releases the response");
      } finally {
        reader.releaseLock();
      }
    } finally {
      response.restore();
    }
  }
  t.end();
});
