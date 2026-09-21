import test from "tape";
import { Keypair, Pubky, PublicKey, type EventStreamBuilder } from "../index.js";
import { assertPubkyError, createSignupToken, mockStreamingResponse } from "./utils.js";

const HOMESERVER = PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo");
const USER = Keypair.random().publicKey;

function subscription(sdk: Pubky, limit?: number) {
  const builder = sdk.eventStreamFor(HOMESERVER).addUsers([[USER.z32(), null]]);
  return limit === undefined ? builder : builder.maxEventBytes(limit);
}

function event(cursor: number, path = "/pub/café") {
  return `event: DEL\ndata: pubky://${USER.z32()}${path}\ndata: cursor: ${cursor}\n\n`;
}

function mockEventResponse(chunks: Uint8Array[], onRequest?: (request: Request) => void) {
  return mockStreamingResponse(chunks, {
    matches: (request) => new URL(request.url).pathname === "/events-stream",
    response: { headers: { "content-type": "text/event-stream" } },
    onRequest,
  });
}

test("event byte limit rejects invalid JavaScript numbers", (t) => {
  const sdk = Pubky.testnet();
  for (const limit of [0, -0, -1, 1.5, NaN, Infinity, -Infinity, 4294967296]) {
    try {
      subscription(sdk, limit);
      t.fail(`accepted ${limit}`);
    } catch (error) {
      assertPubkyError(t, error);
      t.equal(error.name, "InvalidInput");
    }
  }
  for (const limit of [1, 4096, 70000, 4294967295]) {
    subscription(sdk, limit).free();
    t.pass(`accepts ${limit}`);
  }
  t.end();
});

test("event stream builders survive rejected options", async (t) => {
  const sdk = Pubky.testnet();
  const encoder = new TextEncoder();
  const users: [string, null][] = Array.from({ length: 50 }, () => [Keypair.random().publicKey.z32(), null]);
  for (const reject of [
    (builder: EventStreamBuilder) => builder.maxEventBytes(0),
    (builder: EventStreamBuilder) => builder.addUsers([users[0], [USER.z32(), "invalid"]]),
    (builder: EventStreamBuilder) => builder.addUsers([[USER.z32(), "99"], ...users]),
  ]) {
    const builder = subscription(sdk);
    t.throws(() => reject(builder), "invalid option throws");
    const response = mockEventResponse([encoder.encode(event(42))], (request) => {
      t.deepEqual(new URL(request.url).searchParams.getAll("user"), [USER.z32()], "rejected options leave users and cursors unchanged");
    });
    try {
      const reader = (await builder.subscribe()).getReader();
      try {
        t.equal((await reader.read()).value.cursor, "42", "original builder still subscribes");
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

test("event stream validation setters update the receiver and support chaining", async (t) => {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  await signer.signup(HOMESERVER, await createSignupToken());
  const session = await signer.signin("event-builder.test");
  const user = session.info.publicKey;

  for (const privateStream of [false, true]) {
    for (const chain of [false, true]) {
      let builder = sdk.eventStreamForUser(user, null);
      for (const configure of [
        (b: EventStreamBuilder) => b.addUsers([[privateStream ? user.z32() : USER.z32(), "12"]]),
        (b: EventStreamBuilder) => b.maxEventBytes(256),
      ]) {
        const updated = configure(builder);
        if (chain) builder = updated;
        else updated.free();
      }
      builder = builder
        .limit(3)
        .path("/pub/")
        .path(privateStream ? "/priv/app/" : "/pub/app/")
        .session(session)
        .reverse();

      const body = event(42) + event(43, `/pub/${"x".repeat(256)}`);
      const response = mockEventResponse([new TextEncoder().encode(body)], (request) => {
        const params = new URL(request.url).searchParams;
        t.deepEqual(params.getAll("user"), privateStream ? [`${user.z32()}:12`] : [user.z32(), `${USER.z32()}:12`], "users and cursors reach the request");
        t.equal(params.get("limit"), "3", "event count reaches the request");
        t.deepEqual(params.getAll("path"), ["/pub/", privateStream ? "/priv/app/" : "/pub/app/"], "repeated filters reach the request");
        t.equal(params.get("reverse"), "true", "reverse reaches the request");
        t.equal(request.headers.has("authorization"), privateStream, "session authenticates only private subscriptions");
      });
      try {
        const reader = (await builder.subscribe()).getReader();
        try {
          t.equal((await reader.read()).value.cursor, "42", `subscribes with chain=${chain}`);
          try {
            await reader.read();
            t.fail("configured byte limit must reject the oversized event");
          } catch (error) {
            assertPubkyError(t, error);
            t.ok(error.message.includes("limit of 256 bytes"), `enforces byte limit with chain=${chain}`);
          }
        } finally {
          reader.releaseLock();
        }
      } finally {
        response.restore();
      }
    }
  }
  t.end();
});

test("oversized SSE cancels the response", async (t) => {
  const limit = 8192;
  const sdk = Pubky.testnet();
  const encoder = new TextEncoder();
  const valid = event(42);
  const oversized = `data: pubky://${USER.z32()}/pub/${"x".repeat(limit + 1)}`;
  for (const live of [false, true]) {
    for (const chunks of [[valid + oversized], [valid, oversized.slice(0, limit), oversized.slice(limit)]]) {
      const response = mockEventResponse(chunks.map((chunk) => encoder.encode(chunk)), (request) => {
        t.equal(new URL(request.url).searchParams.get("live"), live ? "true" : null, "live reaches the request");
      });
      let timer: ReturnType<typeof setTimeout> | undefined;

      let reader: ReadableStreamDefaultReader | undefined;
      try {
        let builder = subscription(sdk);
        builder.maxEventBytes(limit);
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

test("SSE event size is unbounded by default in historical and live mode", async (t) => {
  const sdk = Pubky.testnet();
  const encoder = new TextEncoder();
  for (const pathBytes of [4096, 16384, 1024 * 1024]) {
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

test("SSE limits allow ignored fields, long streams, fragmented UTF-8 and cancellation", async (t) => {
  const sdk = Pubky.testnet();
  const encoder = new TextEncoder();
  const ignored = `:${"x".repeat(256)}\nunknown: ${"x".repeat(256)}\nretry: 10\n\n`;
  const body = encoder.encode(ignored + Array.from({ length: 100 }, (_, i) => `:keepalive\n\n${event(i)}`).join(""));
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
