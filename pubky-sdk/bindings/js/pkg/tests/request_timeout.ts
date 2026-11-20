import test, { type Test } from "tape";
import { AuthFlowKind, Client, Keypair, Pubky, PublicKey, type Address } from "../index.js";
import { assertPubkyError, createSignupToken, sleep } from "./utils.js";

const HOMESERVER = PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo");
const TESTNET_HTTP_RELAY = "http://localhost:15412/inbox";
const PATH = "/pub/request-timeout.test/value";
const REQUEST_TIMEOUT_MS = 500;

function clientWithRequestTimeout(requestTimeout = REQUEST_TIMEOUT_MS) {
  return new Client({ requestTimeout, pkarr: { relays: ["http://localhost:15411/"] } });
}

function sdkWithRequestTimeout(requestTimeout = REQUEST_TIMEOUT_MS) {
  return Pubky.withClient(clientWithRequestTimeout(requestTimeout));
}

/**
 * Answer requests with `handler` until the test ends, even when it ends by timing out.
 * Requests the handler returns `undefined` for go to the real `fetch`.
 *
 * Like Node's `fetch`, the handler only gets the signal the call holds strongly: the
 * init's own signal for `fetch(url, init)`, but the `Request`'s derived signal for
 * `fetch(request)`. Node holds that one weakly once the response arrives; this mock
 * holds it weakly throughout, so the SDK must never send a deadline on a `Request`.
 */
function mockFetch(
  t: Test,
  handler: (request: Request, signal: AbortSignal) => Promise<Response> | Response | undefined,
) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const signal = input instanceof Request ? input.signal : init?.signal ?? request.signal;
    return Promise.resolve(handler(request, signal)).then(
      (response) => response ?? originalFetch(input, init),
    );
  };
  t.teardown(() => { globalThis.fetch = originalFetch; });
}

/** Reject with the signal's reason once it aborts, or at once if it already has. */
function onAbort(signal: AbortSignal, reject: (reason: unknown) => void) {
  if (signal.aborted) reject(signal.reason);
  signal.addEventListener("abort", () => reject(signal.reason));
}

/**
 * Stand in for a server that accepts matching requests and never answers:
 * the response only ends when the request's signal aborts.
 */
function mockUnansweredFetch(t: Test, matches: (request: Request) => boolean) {
  mockFetch(t, (request, signal) => {
    if (!matches(request)) return undefined;
    return new Promise<Response>((_, reject) => onAbort(signal, reject));
  });
}

/** Sign up and in through a client with a deadline a slow runner can meet. */
async function sessionWithRequestTimeout(deadlineMs: number) {
  const signer = sdkWithRequestTimeout(deadlineMs).signer(Keypair.random());
  await signer.signup(HOMESERVER, await createSignupToken());
  const session = await signer.signin("request-timeout.test");
  await session.storage.exists(PATH);
  return session;
}

async function assertTimeout(t: Test, request: Promise<unknown>, deadlineMs: number) {
  const started = Date.now();
  try {
    await request;
    t.fail("unanswered request must reject");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "RequestError", "timeout is a RequestError");
    t.deepEqual(error.data, { reason: "Timeout" }, "reason is Timeout");
    t.ok(Date.now() - started >= deadlineMs, "rejects once the deadline passes");
  }
}

test("requestTimeout rejects a request the server never answers", async (t) => {
  // Fail rather than hang if the deadline is not applied.
  t.timeoutAfter(REQUEST_TIMEOUT_MS * 20);
  // Set up without a deadline so a slow runner cannot fail before the request under test.
  const signer = Pubky.testnet().signer(Keypair.random());
  await signer.signup(HOMESERVER, await createSignupToken());
  const address: Address = `pubky${signer.publicKey.z32()}${PATH}`;
  const publicStorage = sdkWithRequestTimeout().publicStorage;

  mockUnansweredFetch(t, (request) => new URL(request.url).pathname.endsWith(PATH));
  await assertTimeout(t, publicStorage.get(address), REQUEST_TIMEOUT_MS);
  t.end();
});

test("requestTimeout bounds putBlob", async (t) => {
  const deadlineMs = 3000;
  t.timeoutAfter(deadlineMs * 5);
  const session = await sessionWithRequestTimeout(deadlineMs);

  mockUnansweredFetch(t, (request) => request.method === "PUT");
  await assertTimeout(t, session.storage.putBlob(PATH, new Blob(["contents"])), deadlineMs);
  t.end();
});

test("requestTimeout bounds the putBlob error-body read", async (t) => {
  const deadlineMs = 3000;
  t.timeoutAfter(deadlineMs * 5);
  const session = await sessionWithRequestTimeout(deadlineMs);

  // The error status arrives at once; its body never finishes until the request aborts.
  mockFetch(t, (request, signal) => {
    if (request.method !== "PUT") return undefined;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        onAbort(signal, (reason) => controller.error(reason));
      },
    });
    return new Response(body, { status: 500 });
  });
  const put = session.storage.putBlob(PATH, new Blob(["contents"]));
  // With `--expose-gc`, check the deadline survives collection during the body read.
  const { gc } = globalThis as { gc?: () => void };
  for (let round = 0; gc && round < 5; round++) {
    gc();
    await sleep(20); // Weak references clear between turns.
  }
  try {
    await put;
    t.fail("stalled error body must reject");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "RequestError", "the PUT still reports its HTTP error");
  }
  t.end();
});

test("requestTimeout ends a live event stream", async (t) => {
  t.timeoutAfter(REQUEST_TIMEOUT_MS * 20);
  const signer = Pubky.testnet().signer(Keypair.random());
  await signer.signup(HOMESERVER, await createSignupToken());
  const stream = await sdkWithRequestTimeout()
    .eventStreamForUser(signer.publicKey, null)
    .live()
    .subscribe();

  const started = Date.now();
  const reader = stream.getReader();
  try {
    while (!(await reader.read()).done);
  } catch {
    // Ending with an error is fine too; the stream must not stay open.
  }
  t.ok(Date.now() - started < REQUEST_TIMEOUT_MS * 10, "the deadline ends the stream");
  t.end();
});

test("Client.fetch does not apply requestTimeout", async (t) => {
  t.timeoutAfter(REQUEST_TIMEOUT_MS * 20);
  mockFetch(t, (request, signal) => {
    if (new URL(request.url).pathname !== "/slow") return undefined;
    return new Promise<Response>((resolve, reject) => {
      onAbort(signal, reject);
      setTimeout(() => resolve(new Response("late")), REQUEST_TIMEOUT_MS * 2);
    });
  });
  const response = await clientWithRequestTimeout().fetch("http://localhost:6286/slow");
  t.equal(await response.text(), "late", "a response slower than requestTimeout arrives");
  t.end();
});

test("auth flow completes when requestTimeout is shorter than the relay long-poll", async (t) => {
  const signer = Pubky.testnet().signer(Keypair.random());
  await signer.signup(HOMESERVER, await createSignupToken());

  const flow = sdkWithRequestTimeout().startCookieAuthFlow(
    "/pub/request-timeout.test/:rw",
    AuthFlowKind.signin(),
    TESTNET_HTTP_RELAY,
  );
  const approval = flow.awaitApproval();
  // Outlast the three consecutive poll failures after which the flow gives up,
  // so this fails if a poll timeout ever counts as a failure.
  await sleep(REQUEST_TIMEOUT_MS * 5);
  await signer.approveAuthRequest(flow.authorizationUrl);

  const session = await approval;
  t.equal(session.info.publicKey.z32(), signer.publicKey.z32(), "session belongs to the signer");
  t.end();
});
