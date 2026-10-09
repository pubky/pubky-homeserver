import test from "tape";

import {
  AgentStatus,
  Pubky,
  Session,
  SessionAgent,
  SessionAgentClient,
  type Capabilities,
} from "../index.js";
import { Assert, IsExact, assertPubkyError } from "./utils.js";

type Facade = ReturnType<typeof Pubky.testnet>;

type _Listen = Assert<
  IsExact<ReturnType<Facade["listenSessionAgent"]>, Promise<SessionAgent>>
>;
type _Connect = Assert<
  IsExact<ReturnType<Facade["connectSessionAgent"]>, Promise<SessionAgentClient>>
>;
type _Status = Assert<IsExact<SessionAgentClient["status"], AgentStatus>>;
type _ClientSession = Assert<IsExact<SessionAgentClient["session"], Session | undefined>>;
type _State = Assert<
  IsExact<AgentStatus["state"], "signed-in" | "signed-out" | "insufficient-scope" | "unavailable">
>;

const hasWindow = typeof globalThis.addEventListener === "function";

// The multi-origin flow runs in `npm run test-browser:sso`. These cover the
// single-runtime edges.

test("SessionAgent.listen: validates origins and scope before listening", async (t) => {
  const sdk = Pubky.testnet();
  for (const origin of [
    "not an origin",
    "https://example.app/",
    "https://example.app/agent",
    "https://example.app:443",
    "null",
    // Wildcards cover one domain, written like a CSP source.
    "*.example.app",
    "https://*",
    "https://*.",
    "https://*example.app",
    "https://*.*.example.app",
    "https://a.*.example.app",
    "https://*.example.app/",
    "https://*.example.app:443",
  ]) {
    try {
      await sdk.listenSessionAgent({ allowedOrigins: [origin], capabilities: "/pub/app/:rw" });
      t.fail(`accepted ${origin}`);
    } catch (error) {
      assertPubkyError(t, error);
      t.equal(error.name, "InvalidInput", `rejects ${origin}`);
    }
  }
  if (hasWindow) {
    const agent = await sdk.listenSessionAgent({
      allowedOrigins: ["https://*.example.app", "http://*.localhost:8080"],
      capabilities: "/pub/app/:rw",
    });
    agent.close();
    t.pass("accepts wildcard patterns");
  }
  try {
    await sdk.listenSessionAgent({
      allowedOrigins: ["https://example.app"],
      capabilities: "oops" as Capabilities,
    });
    t.fail("accepted malformed scope");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "InvalidInput", "rejects a malformed scope");
  }

  try {
    const agent = await sdk.listenSessionAgent({
      allowedOrigins: ["https://example.app"],
      capabilities: "/pub/app/:rw",
    });
    t.ok(hasWindow, "only a browser window can listen");
    t.equal(agent.hasSession, false, "starts without a session");
    t.equal(agent.returnUrl, undefined, "no app connected yet");
    agent.close();
  } catch (error) {
    assertPubkyError(t, error);
    t.notOk(hasWindow, "Node has no window to listen in");
    t.equal(error.name, "ClientStateError");
  }
  t.end();
});

test("SessionAgentClient.connect: fails cleanly when no agent answers", async (t) => {
  const sdk = Pubky.testnet();
  const frame = typeof document === "undefined" ? {} : document.createElement("iframe");
  if (frame instanceof Object && "src" in frame) {
    (frame as HTMLIFrameElement).src = "about:blank";
    document.body.append(frame as HTMLIFrameElement);
  }
  try {
    await sdk.connectSessionAgent(frame as HTMLIFrameElement, {
      agentOrigin: "https://*.example.app",
      capabilities: "",
    });
    t.fail("accepted a wildcard agent origin");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "InvalidInput", "the agent origin is exact");
  }
  try {
    await sdk.connectSessionAgent(frame as HTMLIFrameElement, {
      agentOrigin: "http://localhost:1",
      capabilities: "",
      timeoutMs: 300,
    });
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
