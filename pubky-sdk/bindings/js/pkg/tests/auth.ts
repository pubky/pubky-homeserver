import test from "tape";
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
} from "./utils.js";

const HOMESERVER_PUBLICKEY = PublicKey.from(
  "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo",
);

// relay base (no trailing slash is fine; the flow will append the channel id)
const TESTNET_HTTP_RELAY = "http://localhost:15412/inbox";

test("Auth: 3rd party signup", async (t) => {
  const sdk = Pubky.testnet();

  const signer = sdk.signer(Keypair.random());
  const pubky = signer.publicKey.z32();
  const signupToken = await createSignupToken();

  const capabilities = "/pub/pubky.app/:rw,/pub/foo.bar/file:r";
  const flow = sdk.startCookieAuthFlow(capabilities, AuthFlowKind.signup(HOMESERVER_PUBLICKEY, signupToken), TESTNET_HTTP_RELAY);

  type Flow = typeof flow;
  type SessionPromise = ReturnType<Flow["awaitApproval"]>;
  type Session = Awaited<SessionPromise>;

  const _flowUrl: Assert<IsExact<Flow["authorizationUrl"], string>> = true;
  const _sessionInfo: Assert<IsExact<Session["info"], SessionInfo>> = true;

  {

    await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
    await signer.approveAuthRequest(flow.authorizationUrl);
  }

  const session = await flow.awaitApproval();

  t.equal(
    session.info.publicKey.z32(),
    pubky,
    "session belongs to expected user",
  );
  t.deepEqual(
    session.info.capabilities,
    capabilities.split(","),
    "session capabilities match",
  );

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

test("Auth: 3rd party signin", async (t) => {
  const sdk = Pubky.testnet();

  const signer = sdk.signer(Keypair.random());
  const pubky = signer.publicKey.z32();

  const capabilities = "/pub/pubky.app/:rw,/pub/foo.bar/file:r";
  const flow = sdk.startCookieAuthFlow(capabilities, AuthFlowKind.signin(), TESTNET_HTTP_RELAY);

  type Flow = typeof flow;
  type SessionPromise = ReturnType<Flow["awaitApproval"]>;
  type Session = Awaited<SessionPromise>;

  const _flowUrl: Assert<IsExact<Flow["authorizationUrl"], string>> = true;
  const _sessionInfo: Assert<IsExact<Session["info"], SessionInfo>> = true;

  {
    const signupToken = await createSignupToken();
    await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
    await signer.approveAuthRequest(flow.authorizationUrl);
  }

  const session = await flow.awaitApproval();

  t.equal(
    session.info.publicKey.z32(),
    pubky,
    "session belongs to expected user",
  );
  t.deepEqual(
    session.info.capabilities,
    capabilities.split(","),
    "session capabilities match",
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

test("startCookieAuthFlow validates capabilities", (t) => {
  const sdk = Pubky.testnet();

  try {
    // @ts-ignore: malformed capability string for runtime validation.
    sdk.startCookieAuthFlow("/ok/:rw,not/a/cap", AuthFlowKind.signin(), TESTNET_HTTP_RELAY);
    t.fail("startCookieAuthFlow() should reject malformed capabilities");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "InvalidInput", "invalid capabilities -> InvalidInput");
  }

  // @ts-ignore: unordered actions are accepted and normalized at runtime.
  const flow = sdk.startCookieAuthFlow("/pub/example/:wr", AuthFlowKind.signin(), TESTNET_HTTP_RELAY);
  const url = new URL(flow.authorizationUrl);
  t.equal(url.searchParams.get("caps"), "/pub/example/:rw", "normalizes capabilities");

  const emptyFlow = sdk.startCookieAuthFlow("", AuthFlowKind.signin(), TESTNET_HTTP_RELAY);
  const emptyUrl = new URL(emptyFlow.authorizationUrl);
  t.equal(emptyUrl.searchParams.get("caps"), "", "allows empty capabilities");

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

test("Grant auth: resume signin flow from saved state", async (t) => {
  const sdk = Pubky.testnet();

  const signer = sdk.signer(Keypair.random());
  const pubky = signer.publicKey.z32();
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);

  const capabilities = "/pub/pubky.app/:rw";
  const originalFlow = await sdk.startGrantAuthFlow(
    capabilities,
    AuthFlowKind.signin(),
    { clientId: "grant-resume-js.test", relay: TESTNET_HTTP_RELAY },
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

  t.end();
});

test("Auth: resume signin flow reconnects to same channel", async (t) => {
  const sdk = Pubky.testnet();

  const signer = sdk.signer(Keypair.random());
  const pubky = signer.publicKey.z32();

  const capabilities = "/pub/pubky.app/:rw,/pub/foo.bar/file:r";

  // 1) Start a flow and save the URL (as the app would before a refresh).
  const originalFlow = sdk.startCookieAuthFlow(capabilities, AuthFlowKind.signin(), TESTNET_HTTP_RELAY);
  const savedUrl = originalFlow.authorizationUrl;
  // Explicitly free the WASM handle — simulates page refresh killing WASM memory.
  // JS block scoping does NOT trigger WASM destructors; .free() does.
  originalFlow.free();

  // 2) Signer approves while the original flow is gone (token waits in the relay inbox).
  {
    const signupToken = await createSignupToken();
    await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
    await signer.approveAuthRequest(savedUrl);
  }

  // 3) Resume from the saved URL — reconnects to the same relay channel.
  const resumedFlow = sdk.resumeCookieAuthFlow(savedUrl);

  t.equal(
    resumedFlow.authorizationUrl,
    savedUrl,
    "resumed flow produces the same authorization URL",
  );

  const session = await resumedFlow.awaitApproval();

  t.equal(
    session.info.publicKey.z32(),
    pubky,
    "resumed flow session belongs to expected user",
  );
  t.deepEqual(
    session.info.capabilities,
    capabilities.split(","),
    "resumed flow session capabilities match",
  );

  t.end();
});

test("Auth: resume signup flow preserves signup params and channel", async (t) => {
  const sdk = Pubky.testnet();

  const signer = sdk.signer(Keypair.random());
  const pubky = signer.publicKey.z32();
  const signupToken = await createSignupToken();

  const capabilities = "/pub/pubky.app/:rw,/pub/foo.bar/file:r";

  // 1) Start a signup flow and save URL before refresh.
  const originalFlow = sdk.startCookieAuthFlow(
    capabilities,
    AuthFlowKind.signup(HOMESERVER_PUBLICKEY, signupToken),
    TESTNET_HTTP_RELAY,
  );
  const savedUrl = originalFlow.authorizationUrl;

  // Signup-specific params are present in the persisted URL.
  const savedParsed = new URL(savedUrl);
  t.equal(
    savedParsed.searchParams.get("hs"),
    HOMESERVER_PUBLICKEY.z32(),
    "saved URL keeps homeserver parameter",
  );
  t.equal(
    savedParsed.searchParams.get("st"),
    signupToken,
    "saved URL keeps signup token parameter",
  );

  // Simulate page refresh destroying the in-memory flow handle.
  originalFlow.free();

  // 2) Signer approves while original flow is gone.
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
  await signer.approveAuthRequest(savedUrl);

  // 3) Resume from persisted URL.
  const resumedFlow = sdk.resumeCookieAuthFlow(savedUrl);

  t.equal(
    resumedFlow.authorizationUrl,
    savedUrl,
    "resumed signup flow produces the same authorization URL",
  );

  const resumedParsed = new URL(resumedFlow.authorizationUrl);
  t.equal(
    resumedParsed.searchParams.get("hs"),
    HOMESERVER_PUBLICKEY.z32(),
    "resumed URL keeps homeserver parameter",
  );
  t.equal(
    resumedParsed.searchParams.get("st"),
    signupToken,
    "resumed URL keeps signup token parameter",
  );

  const session = await resumedFlow.awaitApproval();

  t.equal(
    session.info.publicKey.z32(),
    pubky,
    "resumed signup flow session belongs to expected user",
  );
  t.deepEqual(
    session.info.capabilities,
    capabilities.split(","),
    "resumed signup flow session capabilities match",
  );

  t.end();
});

test("resumeCookieAuthFlow: rejects invalid URL", async (t) => {
  const sdk = Pubky.testnet();

  try {
    sdk.resumeCookieAuthFlow("https://not-a-pubkyauth-url.com");
    t.fail("resumeCookieAuthFlow() should throw on non-pubkyauth URL");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "AuthenticationError", "invalid URL -> AuthenticationError");
    t.ok(
      /Failed to parse/i.test(error.message),
      "error message explains parse failure",
    );
  }

  try {
    sdk.resumeCookieAuthFlow("pubkyauth://secret_export?secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8");
    t.fail("resumeCookieAuthFlow() should reject seed export URLs");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "AuthenticationError", "seed export URL -> AuthenticationError");
    t.ok(
      /Only signin and signup/i.test(error.message),
      "error message explains only auth URLs are valid",
    );
  }

  t.end();
});
