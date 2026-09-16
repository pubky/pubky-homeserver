/**
 * Request a signup token from the homeserver admin endpoint.
 *
 * @param {string} [homeserverAddress="127.0.0.1:6288"]
 *   Host:port of the homeserver admin HTTP endpoint (testnet default).
 * @param {string} [adminPassword="admin"]
 *   Admin password sent as `X-Admin-Password`.
 * @returns {Promise<string>} The signup token.
 */
import type { PubkyError } from "../index.js";
import type { Test } from "tape";

export type PubkyErrorInstance = Error & PubkyError;

export type Assert<T extends true> = T;
export type IsExact<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2
    ? true
    : false;

export async function createSignupToken(
  homeserverAddress = "127.0.0.1:6288",
  adminPassword = "admin",
): Promise<string> {
  const url = `http://${homeserverAddress}/generate_signup_token`;

  const res = await fetch(url, {
    method: "GET",
    headers: { "X-Admin-Password": adminPassword },
  });

  const body = await res.text().catch(() => "");
  if (!res.ok) {
    throw new Error(
      `Failed to get signup token: ${res.status} ${res.statusText}${
        body ? ` - ${body}` : ""
      }`,
    );
  }

  return body;
}

// Quick probe to avoid failing when offline in CI/dev
export async function hasNetwork() {
  try {
    // Use native fetch directly for the probe
    const res = await fetch("https://example.com/", { method: "HEAD" });
    return res.ok;
  } catch (_) {
    return false;
  }
}

export function assertPubkyError(
  t: Test,
  error: unknown,
  message = "expected a PubkyError instance",
): asserts error is PubkyErrorInstance {
  if (
    typeof error === "object" &&
    error !== null &&
    error instanceof Error &&
    "name" in error &&
    typeof (error as { name: unknown }).name === "string" &&
    "message" in error &&
    typeof (error as { message: unknown }).message === "string"
  ) {
    return;
  }

  t.fail(message);
  throw error;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function mockStreamingResponse(
  chunks: Uint8Array[],
  options: {
    matches: (request: Request) => boolean;
    response?: ResponseInit;
    onRequest?: (request: Request) => void;
  },
) {
  const originalFetch = globalThis.fetch;
  const state = {
    pulls: 0,
    cancelled: false,
    restore() { globalThis.fetch = originalFetch; },
  };
  globalThis.fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    if (!options.matches(request)) return originalFetch(input, init);
    options.onRequest?.(request);
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        const chunk = chunks[state.pulls++];
        if (chunk !== undefined) controller.enqueue(chunk);
        // Withhold EOF to catch readers that wait for the response to close.
      },
      cancel() { state.cancelled = true; },
    }, { highWaterMark: 0 });
    const response = new Response(body, options.response);
    Object.defineProperty(response, "url", { value: request.url });
    return response;
  };
  return state;
}

export function getStatusCode(error: PubkyError): number | undefined {
  if (
    typeof error.data === "object" &&
    error.data !== null &&
    "statusCode" in error.data
  ) {
    const status = (error.data as { statusCode?: unknown }).statusCode;
    if (typeof status === "number") {
      return status;
    }
  }

  return undefined;
}
