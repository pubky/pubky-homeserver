import test from "tape";

import { Pubky, Session, SessionAgent } from "../index.js";
import { Assert, IsExact, assertPubkyError } from "./utils.js";

type Facade = ReturnType<typeof Pubky.testnet>;

type _Connect = Assert<
  IsExact<ReturnType<Facade["connectSessionAgent"]>, Promise<Session | undefined>>
>;
type _Serve = Assert<IsExact<ReturnType<Facade["serveSessionAgent"]>, SessionAgent>>;
type _HasSession = Assert<IsExact<SessionAgent["hasSession"], boolean>>;

// The cross-origin flow needs several real origins and runs in
// `npm run test-browser:agent`. These tests cover the single-runtime edges.

test("serveSessionAgent: accepts exact origins only", async (t) => {
  const sdk = Pubky.testnet();

  for (const origin of [
    "not an origin",
    "https://example.app/",
    "https://example.app/agent.html",
    "https://example.app:443",
    "null",
  ]) {
    try {
      sdk.serveSessionAgent([origin]);
      t.fail(`accepted ${origin}`);
    } catch (error) {
      assertPubkyError(t, error);
      t.equal(error.name, "InvalidInput", `rejects ${origin}`);
    }
  }

  const origins = ["https://example.app", "http://localhost:8081"];
  if (typeof globalThis.addEventListener !== "function") {
    try {
      sdk.serveSessionAgent(origins);
      t.fail("serve should reject without a window");
    } catch (error) {
      assertPubkyError(t, error);
      t.equal(error.name, "ClientStateError", "Node has no window to serve from");
    }
    t.end();
    return;
  }

  const agent = sdk.serveSessionAgent(origins);
  t.equal(agent.hasSession, false, "starts without a session");
  agent.clearSession();
  agent.stop();
  t.end();
});

test("connectSessionAgent: fails cleanly when no agent answers", async (t) => {
  const sdk = Pubky.testnet();
  try {
    await sdk.connectSessionAgent("http://localhost:1/agent.html", { timeoutMs: 300 });
    t.fail("connect should reject");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "ClientStateError");
    t.ok(
      /browser document|did not answer/.test(error.message),
      "names the missing document (Node) or the silent agent (browser)",
    );
  }
  t.end();
});
