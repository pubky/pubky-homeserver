import test from "tape";
import { AuthFlowKind, Pubky } from "../index.js";

const LIMIT = 1024 * 1024;
const LIMIT_ERROR = `Auth relay response exceeds the ${LIMIT}-byte limit`;

// Accepted bodies reach HPKE validation; no signer or homeserver is needed.
test("relay body limits apply to inbox and link WASM flows", async (t) => {
  const originalFetch = globalThis.fetch;
  try {
    for (const transport of ["inbox", "link"]) {
      for (const { name, bodyBytes, contentLength } of [
        { name: "below", bodyBytes: LIMIT - 1 },
        { name: "exact", bodyBytes: LIMIT },
        { name: "declared", bodyBytes: null, contentLength: LIMIT + 1 },
        { name: "streamed", bodyBytes: LIMIT + 1 },
        { name: "misleading", bodyBytes: LIMIT + 1, contentLength: 16 },
      ]) {
        const oversized = bodyBytes === null || bodyBytes > LIMIT;
        let reads = 0;
        let cancelled = false;
        let requests = 0;
        let acknowledgements = 0;
        const stream = new ReadableStream<Uint8Array>({
          pull(controller) {
            reads += 1;
            // A null body or exhausted chunks leaves the connection open.
            if (bodyBytes === null || reads > 2) return new Promise<void>(() => {});
            controller.enqueue(new Uint8Array(reads === 1 ? Math.min(bodyBytes, LIMIT) : 1));
            if (!oversized) controller.close();
          },
          cancel() { cancelled = true; },
        }, { highWaterMark: 0 });
        globalThis.fetch = (async (input: RequestInfo | URL) => {
          const request = input as Request;
          if (request.method === "DELETE") {
            acknowledgements += 1;
            const response = new Response(null, { status: 204 });
            Object.defineProperty(response, "url", { value: request.url });
            return response;
          }
          requests += 1;
          t.equal(request.method, "GET", "only the relay is polled");
          t.ok(request.url.includes(`/${transport}/`), "expected relay transport");
          const response = new Response(stream, {
            status: 200,
            headers: contentLength === undefined
              ? undefined : { "Content-Length": String(contentLength) },
          });
          Object.defineProperty(response, "url", { value: request.url });
          return response;
        }) as typeof fetch;
        const flow = await Pubky.testnet().startGrantAuthFlow("", AuthFlowKind.signin(), {
          clientId: "relay-limit-test",
          relay: `https://relay.example/${transport}`,
          approvalFormat: "signedApprovalV1",
        });
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          const error = await Promise.race([
            flow.awaitApproval().then(
              () => { throw new Error("invalid approval unexpectedly accepted"); },
              (error: Error) => error,
            ),
            new Promise<never>((_, reject) => {
              timer = setTimeout(() => reject(new Error("body reader did not stop")), 5000);
            }),
          ]);
          t.equal(error.message.includes(LIMIT_ERROR), oversized, `${transport}: ${name}`);
          t.equal(error.name, "AuthenticationError", "validation error reaches JS");
          t.equal(requests, 1, "failure does not retry or downgrade");
          t.equal(acknowledgements, !oversized && transport === "inbox" ? 1 : 0,
            "only completely received inbox messages are acknowledged");
          if (oversized) {
            t.ok(cancelled, "unread browser body is cancelled");
            t.equal(reads, bodyBytes === null ? 0 : 2, "no extra body reads");
          }
        } finally {
          clearTimeout(timer);
        }
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
  t.end();
});
