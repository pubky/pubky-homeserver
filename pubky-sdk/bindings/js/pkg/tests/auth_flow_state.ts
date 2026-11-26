import test from "tape";
import { Pubky, AuthFlowKind, GrantAuthFlow } from "../index.js";
import { assertPubkyError } from "./utils.js";

const DEAD_RELAY = "http://127.0.0.1:9/inbox"; // port 9 is typically closed; yields quick connection refusal

test("GrantAuthFlow: repeat awaitApproval reports ClientStateError", async (t) => {
  const sdk = Pubky.testnet();
  const flow = await sdk.startGrantAuthFlow(
    "",
    AuthFlowKind.signin(),
    { clientId: "grant-state-repeat.test", relay: DEAD_RELAY },
  );

  await flow.awaitApproval().catch(() => {});

  try {
    await flow.awaitApproval();
    t.fail("calling awaitApproval twice should reject with ClientStateError");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "ClientStateError", "second awaitApproval -> ClientStateError");
    t.ok(
      /already called/i.test(error.message),
      "error message explains the grant flow was already awaited",
    );
  }

  t.end();
});

test("GrantAuthFlow: awaitApproval blocked while tryPollOnce is in-flight", async (t) => {
  const sdk = Pubky.testnet();
  const flow = await sdk.startGrantAuthFlow(
    "",
    AuthFlowKind.signin(),
    { clientId: "grant-state-in-flight.test", relay: DEAD_RELAY },
  );

  const pendingPoll = flow.tryPollOnce();

  try {
    await flow.awaitApproval();
    t.fail("concurrent awaitApproval should reject with ClientStateError");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "ClientStateError", "rejects with ClientStateError while in use");
    t.ok(
      /in-flight/i.test(error.message),
      "message explains another grant flow call is in-flight",
    );
  }

  await pendingPoll.catch(() => {});

  t.end();
});

test("GrantAuthFlow: tryPollOnce after completion reports ClientStateError", async (t) => {
  const sdk = Pubky.testnet();
  const flow = await sdk.startGrantAuthFlow(
    "",
    AuthFlowKind.signin(),
    { clientId: "grant-state-completed.test", relay: DEAD_RELAY },
  );

  await flow.awaitApproval().catch(() => {});

  try {
    await flow.tryPollOnce();
    t.fail("tryPollOnce after completion should reject with ClientStateError");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "ClientStateError", "polling after completion -> ClientStateError");
    t.ok(
      /already completed/i.test(error.message),
      "error message states the grant flow already completed",
    );
  }

  t.end();
});

test("Delegated grant auth: unsupported runtime reports ClientStateError", async (t) => {
  if (typeof indexedDB !== "undefined") {
    t.comment("browser runtime has IndexedDB; unsupported-runtime check is Node-only");
    t.end();
    return;
  }

  t.equal(
    GrantAuthFlow.isDelegationAvailable,
    false,
    "delegated grant availability is false without browser key storage",
  );

  try {
    await GrantAuthFlow.startDelegated(
      "",
      AuthFlowKind.signin(),
      { clientId: "delegated-unsupported.test", relay: DEAD_RELAY },
    );
    t.fail("delegated grant auth should reject without IndexedDB");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "ClientStateError", "unsupported runtime -> ClientStateError");
    t.ok(
      /secure browser context|WebCrypto and IndexedDB/i.test(error.message),
      "error message names missing browser primitives",
    );
  }

  t.end();
});
