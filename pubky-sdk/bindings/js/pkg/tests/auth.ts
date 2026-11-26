import test from "tape";
import * as legacy from "pubky-legacy/index.js";
import {
  SigninGrantDeepLink,
  SignupGrantDeepLink,
  GrantAuthFlow,
  Keypair,
  Pubky,
  PublicKey,
  SessionInfo,
  AuthFlowKind
} from "../index.js";
import {
  Assert,
  IsExact,
  assertPubkyError,
  createSignupToken,
  getStatusCode,
} from "./utils.js";

const HOMESERVER_PUBLICKEY = PublicKey.from(
  "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo",
);

// relay base (no trailing slash is fine; the flow will append the channel id)
const TESTNET_HTTP_RELAY = "http://localhost:15412/inbox";

test("Signer approves legacy sign-in and sign-up links", async (t) => {
  const requester = legacy.Pubky.testnet();
  const signer = Pubky.testnet().signer(Keypair.random());
  const token = await createSignupToken();
  const homeserver = legacy.PublicKey.from(HOMESERVER_PUBLICKEY.z32());
  const readOnlyFile = "/pub/other.app/read-only";
  const capabilities = `/pub/legacy.app/:rw,${readOnlyFile}:r`;
  for (const kind of [legacy.AuthFlowKind.signup(homeserver, token), legacy.AuthFlowKind.signin()]) {
    const intent = kind.intent;
    const flow = requester.startCookieAuthFlow(capabilities, kind, TESTNET_HTTP_RELAY);
    if (intent === "signup") await signer.signup(HOMESERVER_PUBLICKEY, token);
    await signer.approveAuthRequest(flow.authorizationUrl);
    const session = await flow.awaitApproval();
    t.equal(session.info.publicKey.z32(), signer.publicKey.z32());
    t.deepEqual(session.info.capabilities, capabilities.split(","));
    await session.storage.putText("/pub/legacy.app/data", intent);
    t.equal(await session.storage.getText("/pub/legacy.app/data"), intent);
    for (const path of ["/pub/legacy.app", "/pub/other.app/data", readOnlyFile] as const) {
      try {
        await session.storage.putText(path, intent);
        t.fail(`unexpected write access to ${path}`);
      } catch (error) {
        assertPubkyError(t, error);
        t.equal(getStatusCode(error), 403, `${intent} cannot write to ${path}`);
      }
    }
    await session.signout();
  }
  t.end();
});

test("Auth: direct signup deeplink", async (t) => {
  const sdk = Pubky.testnet();

  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();
  // A direct signup link carries only the homeserver (+ token).
  const deeplink = `pubkyauth://direct_signup?hs=${HOMESERVER_PUBLICKEY.z32()}&st=${encodeURIComponent(
    signupToken,
  )}`;

  await signer.handleDeepLink(deeplink);

  const session = await signer.signin("direct-signup-js.test");
  t.equal(
    session.info.publicKey.z32(),
    signer.publicKey.z32(),
    "session belongs to expected user",
  );

  t.end();
});

test("Grant auth: 3rd party signin", async (t) => {
  const sdk = Pubky.testnet();

  const signer = sdk.signer(Keypair.random());
  const pubky = signer.publicKey.z32();
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);

  const capabilities = "/pub/pubky.app/:rw,/pub/foo.bar/file:r";
  const clientId = "grant-js.test";
  const flow = await sdk.startGrantAuthFlow(
    capabilities,
    AuthFlowKind.signin(),
    { clientId, relay: TESTNET_HTTP_RELAY },
  );

  type Flow = typeof flow;
  type SessionPromise = ReturnType<Flow["awaitApproval"]>;
  type Session = Awaited<SessionPromise>;

  const _flowUrl: Assert<IsExact<Flow["authorizationUrl"], string>> = true;
  const _sessionInfo: Assert<IsExact<Session["info"], SessionInfo>> = true;

  const deepLink = SigninGrantDeepLink.parse(flow.authorizationUrl);
  t.equal(deepLink.clientId, clientId, "grant deep link includes client id");
  t.ok(deepLink.clientPublicKey.z32(), "grant deep link includes client public key");

  await signer.approveAuthRequest(flow.authorizationUrl);
  const session = await flow.awaitApproval();

  t.equal(
    session.info.publicKey.z32(),
    pubky,
    "grant session belongs to expected user",
  );
  t.deepEqual(
    session.info.capabilities,
    capabilities.split(","),
    "grant session capabilities match",
  );

  await session.storage.putText("/pub/pubky.app/grant-js.txt", "hello");

  t.end();
});

test("Grant auth: 3rd party signup", async (t) => {
  const sdk = Pubky.testnet();

  const signer = sdk.signer(Keypair.random());
  const pubky = signer.publicKey.z32();
  const signupToken = await createSignupToken();

  const capabilities = "/pub/pubky.app/:rw,/pub/foo.bar/file:r";
  const clientId = "grant-signup-js.test";
  const flow = await sdk.startGrantAuthFlow(
    capabilities,
    AuthFlowKind.signup(HOMESERVER_PUBLICKEY, signupToken),
    { clientId, relay: TESTNET_HTTP_RELAY },
  );

  type Flow = typeof flow;
  type SessionPromise = ReturnType<Flow["awaitApproval"]>;
  type Session = Awaited<SessionPromise>;

  const _flowUrl: Assert<IsExact<Flow["authorizationUrl"], string>> = true;
  const _sessionInfo: Assert<IsExact<Session["info"], SessionInfo>> = true;

  const deepLink = SignupGrantDeepLink.parse(flow.authorizationUrl);
  t.equal(deepLink.clientId, clientId, "grant signup deep link includes client id");
  t.equal(
    deepLink.homeserver.z32(),
    HOMESERVER_PUBLICKEY.z32(),
    "grant signup deep link includes homeserver",
  );
  t.equal(deepLink.signupToken, signupToken, "grant signup deep link includes signup token");
  t.ok(deepLink.clientPublicKey.z32(), "grant signup deep link includes client public key");

  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
  await signer.approveAuthRequest(flow.authorizationUrl);
  const session = await flow.awaitApproval();

  t.equal(
    session.info.publicKey.z32(),
    pubky,
    "grant signup session belongs to expected user",
  );
  t.deepEqual(
    session.info.capabilities,
    capabilities.split(","),
    "grant signup session capabilities match",
  );

  await session.storage.putText("/pub/pubky.app/grant-signup-js.txt", "hello");

  t.end();
});

test("auth flow builders add Ring-compatible x-callback parameters", async (t) => {
  const sdk = Pubky.testnet();
  const xCallback = {
    xSource: "Bitkit Wallet",
    xSuccess: "bitkit://auth/success?nonce=builder&state=ready",
    xError: "bitkit://auth/error?nonce=builder",
    xCancel: "bitkit://auth/cancel?nonce=builder",
  };

  const grantFlow = await sdk.startGrantAuthFlow(
    "/pub/example/:rw",
    AuthFlowKind.signin(),
    {
      clientId: "grant-x-callback-js.test",
      relay: TESTNET_HTTP_RELAY,
      xCallback,
    },
  );
  const grantLink = SigninGrantDeepLink.parse(grantFlow.authorizationUrl);
  t.deepEqual(grantLink.xCallback, xCallback, "grant flow carries callbacks");

  grantFlow.free();
  t.end();
});

test("startGrantAuthFlow validates capabilities and options", async (t) => {
  const sdk = Pubky.testnet();
  const clientId = "grant-validation-js.test";

  try {
    await sdk.startGrantAuthFlow(
      "/ok/:rw,not/a/cap" as any,
      AuthFlowKind.signin(),
      { clientId, relay: TESTNET_HTTP_RELAY },
    );
    t.fail("startGrantAuthFlow() should reject malformed capabilities");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "InvalidInput", "invalid capabilities -> InvalidInput");
  }

  const normalizedFlow = await sdk.startGrantAuthFlow(
    "/pub/example/:wr" as any,
    AuthFlowKind.signin(),
    { clientId, relay: TESTNET_HTTP_RELAY },
  );
  const normalizedLink = SigninGrantDeepLink.parse(normalizedFlow.authorizationUrl);
  t.equal(normalizedLink.capabilities, "/pub/example/:rw", "normalizes capabilities");

  const emptyFlow = await sdk.startGrantAuthFlow("", AuthFlowKind.signin(), {
    clientId,
    relay: TESTNET_HTTP_RELAY,
  });
  const emptyLink = SigninGrantDeepLink.parse(emptyFlow.authorizationUrl);
  t.equal(emptyLink.capabilities, "", "allows empty capabilities");

  {
    const flow = GrantAuthFlow.start("/pub/standalone/:rw", AuthFlowKind.signin(), {
      clientId,
      relay: TESTNET_HTTP_RELAY,
    });
    const deepLink = SigninGrantDeepLink.parse(flow.authorizationUrl);
    t.equal(deepLink.clientId, clientId, "standalone grant start accepts options object");
    flow.free();
  }

  try {
    await sdk.startGrantAuthFlow("", AuthFlowKind.signin(), {
      clientId: "",
      relay: TESTNET_HTTP_RELAY,
    });
    t.fail("startGrantAuthFlow() should throw on invalid client id");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "AuthenticationError", "invalid client id -> AuthenticationError");
    t.ok(/ClientId must not be empty/i.test(error.message), "error explains invalid client id");
  }

  try {
    await sdk.startGrantAuthFlow("", AuthFlowKind.signin(), {
      clientId,
      relay: "not a url",
    });
    t.fail("startGrantAuthFlow() should throw on invalid relay URL");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "InvalidInput", "invalid relay URL -> InvalidInput");
  }

  t.end();
});

test("Grant auth: selective approval narrows access and delivered keys", async (t) => {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  await signer.signup(HOMESERVER_PUBLICKEY, await createSignupToken());

  for (const approved of ["/pub/pubky.app/file:r", "/pub/pubky.app/selected/:re", ""]) {
    const flow = await sdk.startGrantAuthFlow(
      "/pub/pubky.app/:rwe",
      AuthFlowKind.signin(),
      { clientId: "selective-js.test", relay: TESTNET_HTTP_RELAY, approvalFormat: "signedApprovalV1" },
    );
    for (const [invalid, expectedError] of [
      ["/pub/other/:r", "AuthenticationError"],
      ["not-a-capability", "InvalidInput"],
    ]) {
      try {
        await signer.approveAuthWithCapabilities(flow.authorizationUrl, invalid);
        t.fail("invalid approval should fail");
      } catch (error) {
        assertPubkyError(t, error);
        t.equal(error.name, expectedError, "invalid approval returns a structured error");
      }
    }
    await signer.approveAuthWithCapabilities(flow.authorizationUrl, approved);
    const session = await flow.awaitApproval();
    t.deepEqual(session.info.capabilities, approved ? [approved] : [], "session has only approved capabilities");
    const keys = session.grant!.encryptionKeys!;
    t.deepEqual(keys.scopes, approved.endsWith(":re") ? ["/pub/pubky.app/selected/"] : [], "only approved e scopes deliver keys");
    keys.free();
    await session.signout();
  }
  t.end();
});

test("Grant auth: resume signin flow from saved state", async (t) => {
  const sdk = Pubky.testnet();

  const signer = sdk.signer(Keypair.random());
  const pubky = signer.publicKey.z32();
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);

  const capabilities = "/pub/pubky.app/:rwe";
  const originalFlow = await sdk.startGrantAuthFlow(
    capabilities,
    AuthFlowKind.signin(),
    { clientId: "grant-resume-js.test", relay: TESTNET_HTTP_RELAY, approvalFormat: "signedApprovalV1" },
  );
  const savedUrl = originalFlow.authorizationUrl;
  let savedState: string;
  let delegated = false;
  try {
    savedState = originalFlow.saveDelegated();
    delegated = true;
  } catch (_error) {
    savedState = originalFlow.saveLocal();
  }
  t.ok(new URL(savedUrl).searchParams.has("epk"), "signed approval includes its HPKE recipient key");
  t.equal(
    SigninGrantDeepLink.parse(savedUrl).ephemeralPublicKey?.length,
    32,
    "parsed link exposes the 32-byte HPKE public key",
  );
  t.notOk(new URL(savedUrl).searchParams.has("secret"), "signed approval omits the shared relay secret");
  originalFlow.free();

  await signer.approveAuthRequest(savedUrl);

  const resumedFlow = delegated
    ? await sdk.resumeDelegatedGrantAuthFlow(savedState)
    : sdk.resumeGrantAuthFlow(savedState);
  t.equal(
    resumedFlow.authorizationUrl,
    savedUrl,
    "resumed grant flow produces the same authorization URL",
  );

  const session = await resumedFlow.awaitApproval();
  t.equal(
    session.info.publicKey.z32(),
    pubky,
    "resumed grant session belongs to expected user",
  );
  t.deepEqual(
    session.info.capabilities,
    capabilities.split(","),
    "resumed grant session capabilities match",
  );
  const keys = session.grant!.encryptionKeys!;
  t.deepEqual(keys.scopes, ["/pub/pubky.app/"], "resumed signed approval flow decrypts scoped keys");
  keys.free();

  t.end();
});
