import test from "tape";
import { Client, Keypair } from "../index.js";
import type { PubkyError } from "../index.js";
import { hasNetwork } from "./utils.js";

function isLikelyNetworkFetchError(error: unknown): error is Error & PubkyError {
  if (error instanceof TypeError && /fetch failed/i.test(error.message)) {
    return true;
  }

  if (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    typeof (error as { name?: unknown }).name === "string" &&
    (error as { name: string }).name === "RequestError"
  ) {
    const message = getErrorMessage(error);
    return /\b(fetch failed|ENETUNREACH|EAI_AGAIN|ENOTFOUND|ECONNREFUSED|EHOSTUNREACH)\b/i.test(
      message,
    );
  }

  return false;
}

function getErrorMessage(error: unknown): string {
  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof (error as { message?: unknown }).message === "string"
  ) {
    return (error as { message: string }).message;
  }

  return "";
}

const TLD = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";

test("basic fetch", async (t) => {
  const client = Client.testnet();
  type ClientInstance = typeof client;
  type FetchResult = Awaited<ReturnType<ClientInstance["fetch"]>>;
  void (null as unknown as FetchResult);

  // ICANN domain
  {
    if (await hasNetwork()) {
      let response: Response | undefined;

      try {
        response = await client.fetch("https://example.com/");
      } catch (error) {
        if (isLikelyNetworkFetchError(error)) {
          const message = getErrorMessage(error) || "fetch failed";
          t.comment(
            `Unable to reach example.com (${message}); skipping external fetch assertion`,
          );
        } else {
          throw error;
        }
      }

      if (response) {
        t.equal(response.status, 200, "fetch example.com ok");
      }
    } else {
      t.comment("No external network detected; skipping example.com fetch assertion");
    }
  }

  // Pubky - requires your testnet to be up
  {
    try {
      const response = await client.fetch(`https://${TLD}/`);
      t.equal(response.status, 200, "fetch pubky TLD ok (testnet running)");
    } catch (error) {
      if (isLikelyNetworkFetchError(error)) {
        const message = getErrorMessage(error) || "fetch failed";
        t.fail(
          `Pubky fetch failed (${message}). Ensure \`npm run testnet\` is running before tests.`,
        );
        t.end();
        return;
      }

      throw error;
    }
  }

  t.end();
});

test("fetch merges plain object headers", async (t) => {
  const client = Client.testnet();
  const originalFetch = globalThis.fetch;

  t.teardown(() => {
    globalThis.fetch = originalFetch;
  });

  let seenRequest: Request | undefined;
  let fetchCalls = 0;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    fetchCalls += 1;

    if (input instanceof Request) {
      if (input.headers.has("pubky-host")) {
        seenRequest = input;
      }
    } else {
      const request = new Request(input, init);
      if (request.headers.has("pubky-host")) {
        seenRequest = request;
      }
    }

    return originalFetch(input as RequestInfo | URL, init);
  }) as typeof fetch;

  const response = await client.fetch(`https://${TLD}/`, {
    headers: {
      "Content-Type": "application/json",
    },
  });

  t.ok(fetchCalls >= 1, "fetch invoked");
  t.ok(seenRequest, "fetch received a Request instance");

  const headers = seenRequest!.headers;
  t.equal(headers.get("content-type"), "application/json", "caller header preserved");
  t.equal(headers.get("pubky-host"), TLD, "pubky-host header appended");
  t.equal(response.status, 200, "fetch responded with success");

  t.end();
});

test("path-addressed storage omits pubky-host", async (t) => {
  const client = Client.testnet();
  const owner = Keypair.random().publicKey.z32();
  const originalFetch = globalThis.fetch;
  let infoRequest: Request | undefined;
  let seenRequest: Request | undefined;
  let storageRequests = 0;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;

    if (path === "/info") {
      infoRequest = request;
      const response = new Response(JSON.stringify({ features: ["path-addressed-storage"] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
      Object.defineProperty(response, "url", { value: request.url });
      return response;
    } else if (path.startsWith("/storage/")) {
      seenRequest = request;
      storageRequests += 1;
      const response = new Response(null, { status: 404 });
      Object.defineProperty(response, "url", { value: request.url });
      return response;
    }

    return originalFetch(input as RequestInfo | URL, init);
  }) as typeof fetch;

  try {
    await client.fetch(
      `https://${TLD}/storage/${owner}/pub/missing.txt?cursor=hello%20world`,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }

  t.ok(infoRequest, "feature discovery requested /info");
  t.equal(infoRequest!.credentials, "omit", "feature discovery omitted credentials");
  t.equal(infoRequest!.headers.get("pubky-host"), null, "feature discovery omitted pubky-host");
  t.ok(seenRequest, "fetch preserved the path-addressed storage request");
  t.equal(storageRequests, 1, "storage response did not trigger a fallback retry");
  t.equal(seenRequest!.headers.get("pubky-host"), null, "pubky-host omitted");
  t.equal(seenRequest!.credentials, "include", "cookie credentials preserved");
  t.equal(
    new URL(seenRequest!.url).search,
    "?cursor=hello%20world",
    "query parameters preserved",
  );
  t.end();
});

test("storage falls back when homeserver info is unavailable", async (t) => {
  const client = Client.testnet();
  const owner = Keypair.random().publicKey.z32();
  const originalFetch = globalThis.fetch;
  let infoRequest: Request | undefined;
  let storageRequest: Request | undefined;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;

    if (path === "/info") {
      infoRequest = request;
      const response = new Response(null, { status: 404 });
      Object.defineProperty(response, "url", { value: request.url });
      return response;
    }
    if (path === "/pub/fallback.txt") {
      storageRequest = request;
      const response = new Response(null, { status: 404 });
      Object.defineProperty(response, "url", { value: request.url });
      return response;
    }

    return originalFetch(input as RequestInfo | URL, init);
  }) as typeof fetch;

  try {
    await client.fetch(
      `https://${TLD}/storage/${owner}/pub/fallback.txt?cursor=hello%20world`,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }

  t.ok(infoRequest, "feature discovery requested /info");
  t.equal(infoRequest!.credentials, "omit", "feature discovery omitted credentials");
  t.equal(infoRequest!.headers.get("pubky-host"), null, "feature discovery omitted pubky-host");
  t.ok(storageRequest, "storage used the legacy path");
  t.equal(storageRequest!.headers.get("pubky-host"), owner, "legacy owner header attached");
  t.equal(storageRequest!.credentials, "include", "storage credentials preserved");
  t.equal(
    new URL(storageRequest!.url).search,
    "?cursor=hello%20world",
    "query parameters preserved",
  );
  t.end();
});

test("fetch failed", async (t) => {
  const client = Client.testnet();

  // ICANN: likely fails
  {
    const response = await client
      .fetch("https://nonexistent.domain/")
      .catch((error: unknown) => error as PubkyError);
    t.equal(
      (response as PubkyError).name,
      "RequestError",
      "ICANN fetch error bubbled to JS",
    );
  }

  // Pubky: invalid TLD -> should fail
  {
    const response = await client
      .fetch("https://1pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ew1/")
      .catch((error: unknown) => error as PubkyError);
    t.equal(
      (response as PubkyError).name,
      "PkarrError",
      "pubky fetch error bubbled to JS",
    );
  }

  t.end();
});

test("fetch respects credential overrides", async (t) => {
  const client = Client.testnet();
  const originalFetch = globalThis.fetch;
  const captured: Request[] = [];

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);

    const isExample = request.url.startsWith("https://example.com/");
    const isPubkyRequest = request.headers.get("pubky-host") === TLD;

    if (isExample || isPubkyRequest) {
      captured.push(request);
      return new Response(null, { status: 200 });
    }

    return originalFetch(input as RequestInfo, init);
  }) as typeof fetch;

  try {
    await client.fetch("https://example.com/", { credentials: "omit" });
    const icannRequest = captured.shift();
    t.equal(icannRequest?.credentials, "omit", "non-Pubky URL keeps caller credentials");

    await client.fetch(`https://${TLD}/`);
    const pubkyRequest = captured.pop();
    t.equal(pubkyRequest?.credentials, "include", "Pubky URL defaults credentials to include");
  } finally {
    globalThis.fetch = originalFetch;
  }

  t.end();
});
