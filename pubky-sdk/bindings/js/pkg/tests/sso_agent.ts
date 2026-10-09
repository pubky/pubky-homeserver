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

test("SessionAgent.listen: validates options, then needs a window", async (t) => {
  const sdk = Pubky.testnet();
  // Origin and wildcard forms are covered by the Rust unit tests; one of each
  // kind of bad option shows that the JS entry point reports them as InvalidInput.
  for (const options of [
    { allowedOrigins: ["https://example.app/"], capabilities: "/pub/app/:rw" as Capabilities },
    { allowedOrigins: ["https://example.app"], capabilities: "oops" as Capabilities },
  ]) {
    try {
      await sdk.listenSessionAgent(options);
      t.fail(`accepted ${JSON.stringify(options)}`);
    } catch (error) {
      assertPubkyError(t, error);
      t.equal(error.name, "InvalidInput", `rejects ${JSON.stringify(options)}`);
    }
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
