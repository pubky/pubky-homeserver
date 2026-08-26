import test from "tape";

import {
  AuthFlowKind,
  CookieSession,
  GrantInfo,
  GrantManager,
  GrantSession,
  GrantSessionInfo,
  Keypair,
  Pubky,
  PublicKey,
  Session,
  type Address,
  type Path,
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
const TESTNET_HTTP_RELAY = "http://localhost:15412/inbox";

type Facade = ReturnType<typeof Pubky.testnet>;
type Signer = ReturnType<Facade["signer"]>;
type SignupSession = Awaited<ReturnType<Signer["signupCookie"]>>;
type SessionStorageType = SignupSession["storage"];
type PublicStorageType = Facade["publicStorage"];

type _StoragePutText = Assert<
  IsExact<Parameters<SessionStorageType["putText"]>, [Path, string]>
>;
type _StorageGetBytes = Assert<
  IsExact<ReturnType<SessionStorageType["getBytes"]>, Promise<Uint8Array>>
>;
type _PublicGetText = Assert<
  IsExact<ReturnType<PublicStorageType["getText"]>, Promise<string>>
>;

type _SessionGrant = Assert<
  IsExact<SignupSession["grant"], GrantSession | undefined>
>;
type _SessionCookie = Assert<
  IsExact<SignupSession["cookie"], CookieSession | undefined>
>;
type _GrantSessionInfo = Assert<
  IsExact<ReturnType<GrantSession["sessionInfo"]>, Promise<GrantSessionInfo>>
>;
type _GrantManagerList = Assert<
  IsExact<ReturnType<GrantManager["list"]>, Promise<GrantInfo[]>>
>;
type _CookieExportSecret = Assert<
  IsExact<ReturnType<CookieSession["exportSecret"]>, Promise<string>>
>;
type _GrantExportLocalSecret = Assert<
  IsExact<ReturnType<GrantSession["exportLocalSecret"]>, Promise<string>>
>;

const PATH_AUTH_BASIC: Path = "/pub/example.com/auth-basic.txt";

test("Session: export/import uses browser cookie", async (t) => {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();

  const session = await signer.signupCookie(HOMESERVER_PUBLICKEY, signupToken);
  const cookie = session.cookie;
  t.ok(cookie, "cookie-backed session exposes cookie view");
  t.equal(session.grant, undefined, "cookie-backed session has no grant view");
  if (!cookie) {
    t.end();
    return;
  }

  const exported = session.export();
  t.equal(cookie.export(), exported, "cookie export() matches legacy session export()");

  t.equal(typeof exported, "string", "export() returns a string snapshot");

  const restored = await sdk.restoreSession(exported);
  t.equal(
    restored.info.publicKey.z32(),
    session.info.publicKey.z32(),
    "restored session keeps the same identity",
  );

  const path = `/pub/example.com/export-${Date.now()}.txt` as Path;
  await restored.storage.putText(path, "persisted");

  const url = `https://_pubky.${restored.info.publicKey.z32()}${path}`;
  const res = await sdk.client.fetch(url, {
    method: "GET",
    credentials: "include",
  });

  t.ok(res.ok, "restored session can read via retained cookie");
  t.equal(await res.text(), "persisted", "resource content matches");

  t.end();
});

test("Session: cookie exportSecret restores from secret token", async (t) => {
  if (typeof window !== "undefined") {
    t.comment("cookie exportSecret() is Node-only; browsers cannot read HTTP-only Set-Cookie");
    t.end();
    return;
  }

  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();

  const session = await signer.signupCookie(HOMESERVER_PUBLICKEY, signupToken);
  const cookie = session.cookie;
  t.ok(cookie, "cookie-backed session exposes cookie view");
  if (!cookie) {
    t.end();
    return;
  }

  const exported = await cookie.exportSecret();

  t.equal(typeof exported, "string", "cookie exportSecret() returns a string token");
  t.ok(exported.includes(":"), "cookie secret token includes public key and cookie secret");

  const restored = await sdk.restoreSession(exported);
  t.equal(
    restored.info.publicKey.z32(),
    session.info.publicKey.z32(),
    "restored cookie session keeps the same identity",
  );

  const path = `/pub/example.com/cookie-secret-${Date.now()}.txt` as Path;
  await restored.storage.putText(path, "cookie secret persisted");
  t.equal(
    await restored.storage.getText(path),
    "cookie secret persisted",
    "restored cookie session can read/write",
  );

  t.end();
});

test("Session: grant-only view exposes metadata; GrantManager manages grants", async (t) => {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();

  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
  const clientId = "grant-view-js.test";
  const session = await signer.signin(clientId);
  const grant = session.grant;

  t.ok(grant, "grant-backed session exposes grant view");
  t.equal(session.cookie, undefined, "grant-backed session has no cookie view");
  if (!grant) {
    t.end();
    return;
  }

  const info = await grant.sessionInfo();
  t.equal(
    info.publicKey.z32(),
    session.info.publicKey.z32(),
    "grant info belongs to expected user",
  );
  t.equal(info.homeserver.z32(), HOMESERVER_PUBLICKEY.z32(), "homeserver matches");
  t.equal(info.clientId, clientId, "client id matches");
  t.deepEqual(info.capabilities, session.info.capabilities, "capabilities match");
  t.ok(info.grantId, "grant id is present");
  t.ok(info.tokenExpiresAt > 0, "token expiry is present");
  t.ok(info.grantExpiresAt > 0, "grant expiry is present");
  t.ok(info.createdAt > 0, "created timestamp is present");
  t.equal(await grant.grantId(), info.grantId, "grantId() matches sessionInfo()");

  const exported = await grant.exportLocalSecret();
  const restored = await sdk.restoreSession(exported);
  const restoredGrant = restored.grant;
  t.ok(restoredGrant, "restored grant session exposes grant view");
  t.equal(restored.cookie, undefined, "restored grant session has no cookie view");
  if (!restoredGrant) {
    t.end();
    return;
  }
  t.equal(
    restored.info.publicKey.z32(),
    session.info.publicKey.z32(),
    "restored grant keeps identity",
  );

  const grantManager = new GrantManager(restored);
  const grants = await grantManager.list();
  t.ok(
    grants.some((entry) => entry.grantId === info.grantId && entry.clientId === clientId),
    "GrantManager.list includes the active grant",
  );

  await grantManager.revoke(info.grantId);
  try {
    await sdk.restoreSession(exported);
    t.fail("restoring a revoked grant should fail");
  } catch (error) {
    assertPubkyError(t, error, "revoked grant restore throws PubkyError");
    t.ok(
      error.name === "RequestError" || error.name === "AuthenticationError",
      "revoked grant restore uses existing auth/request error shape",
    );
  }

  t.end();
});

test("Session: cookie sessions expose cookie-only view", async (t) => {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();

  const session = await signer.signupCookie(HOMESERVER_PUBLICKEY, signupToken);
  const cookie = session.cookie;
  t.ok(cookie, "cookie-backed session exposes cookie view");
  t.equal(session.grant, undefined, "cookie-backed session has no grant view");
  if (cookie) {
    t.equal(cookie.export(), session.export(), "cookie export() matches session export()");
  }

  t.end();
});

test("Session: non-root grant management calls return homeserver 403", async (t) => {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();
  const capabilities = "/pub/pubky.app/:r";
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
  const flow = await sdk.startGrantAuthFlow(
    capabilities,
    AuthFlowKind.signin(),
    { clientId: "grant-non-root-js.test", relay: TESTNET_HTTP_RELAY },
  );

  await signer.approveAuthRequest(flow.authorizationUrl);
  const session = await flow.awaitApproval();
  const grant = session.grant;

  t.ok(grant, "non-root grant session exposes grant view");
  t.equal(session.cookie, undefined, "non-root grant session has no cookie view");
  if (!grant) {
    t.end();
    return;
  }

  const info = await grant.sessionInfo();
  const grantManager = new GrantManager(session);

  try {
    await grantManager.list();
    t.fail("non-root GrantManager.list should fail");
  } catch (error) {
    assertPubkyError(t, error, "GrantManager.list throws PubkyError");
    t.equal(error.name, "RequestError", "GrantManager.list maps to RequestError");
    t.equal(getStatusCode(error), 403, "GrantManager.list status code is 403");
  }

  try {
    await grantManager.revoke(info.grantId);
    t.fail("non-root GrantManager.revoke should fail");
  } catch (error) {
    assertPubkyError(t, error, "GrantManager.revoke throws PubkyError");
    t.equal(error.name, "RequestError", "GrantManager.revoke maps to RequestError");
    t.equal(getStatusCode(error), 403, "GrantManager.revoke status code is 403");
  }

  t.end();
});

test("Session: invalid grant id throws InvalidInput", async (t) => {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();

  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
  const session = await signer.signin("grant-invalid-id-js.test");
  const grant = session.grant;

  t.ok(grant, "grant-backed session exposes grant view");
  if (!grant) {
    t.end();
    return;
  }

  try {
    await new GrantManager(session).revoke("");
    t.fail("empty grant id should fail");
  } catch (error) {
    assertPubkyError(t, error, "invalid grant id throws PubkyError");
    t.equal(error.name, "InvalidInput", "invalid grant id maps to InvalidInput");
  }

  t.end();
});

test("Session: grant exportLocalSecret restores with fresh bearer", async (t) => {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();

  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
  const session = await signer.signin("grant-restore-js.test");
  const exported = await session.exportLocalSecret();

  t.equal(typeof exported, "string", "exportLocalSecret() returns a string token");

  const restored = await sdk.restoreSession(exported);
  t.equal(
    restored.info.publicKey.z32(),
    session.info.publicKey.z32(),
    "restored grant session keeps the same identity",
  );

  const path = `/pub/example.com/grant-restore-${Date.now()}.txt` as Path;
  await restored.storage.putText(path, "grant persisted");
  t.equal(
    await restored.storage.getText(path),
    "grant persisted",
    "restored grant session can read/write",
  );

  t.end();
});

/**
 * Basic auth lifecycle:
 *  - signer -> signup -> session (cookie stored)
 *  - write succeeds while authenticated
 *  - signout invalidates cookie
 *  - raw PUT without a valid cookie returns 401
 *  - signer -> signin -> new session; writes succeed again
 */
test("Auth: basic", async (t) => {
  const sdk = Pubky.testnet();

  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();

  // 1) Signup -> valid session
  const session = await signer.signupCookie(HOMESERVER_PUBLICKEY, signupToken);
  t.ok(session, "signup returned a session");
  const userPk = session.info.publicKey.z32();

  // 2) Write while logged in
  await session.storage.putText(PATH_AUTH_BASIC, "hello world");

  // 3) Sign out (server clears cookie)
  await session.signout();

  // Info remains readable and stable after signout
  t.ok(session.info, "info getter still works after signout");
  t.equal(
    session.info.publicKey.z32(),
    userPk,
    "Session is not null pointer after signout",
  );

  // TODO: Storage access must now fail
  // It seems to return "hello world";
  // t.throws(async() => await session.storage.getText(path), "storage throws after signout");

  // Idempotent signout
  await session.signout();
  t.pass("second signout is a no-op");

  // 4) Unauthorized write should now fail with 401
  const url = `https://_pubky.${userPk}${PATH_AUTH_BASIC}`;
  const res401 = await sdk.client.fetch(url, {
    method: "PUT",
    body: "should fail",
    credentials: "include",
  });
  t.equal(res401.status, 401, "PUT without session returns 401");

  // 5) Sign in again (local key proves identity)
  const session2 = await signer.signinCookie();
  t.ok(session2, "signin returned a new session");

  // 6) Write succeeds again
  await session2.storage.putText(PATH_AUTH_BASIC, "hello again");

  t.end();
});

/**
 * Multi-user cookie isolation in one process:
 *  - signup Alice and Bob (both cookies stored)
 *  - generic client.fetch PUT with credentials:include writes under the correct user's host
 *  - signout Bob; Alice remains authenticated and can still write
 *  - Bob can no longer write (401)
 */
test("Auth: multi-user (cookies)", async (t) => {
  const sdk = Pubky.testnet();

  const alice = sdk.signer(Keypair.random());
  const bob = sdk.signer(Keypair.random());

  const aliceSignup = await createSignupToken();
  const bobSignup = await createSignupToken();

  // 1) Signup Alice
  const aliceSession = await alice.signupCookie(HOMESERVER_PUBLICKEY, aliceSignup);
  t.ok(aliceSession, "alice signed up");
  const alicePk = aliceSession.info.publicKey.z32();

  // 2) Signup Bob (cookie jar now holds both sessions)
  const bobSession = await bob.signupCookie(HOMESERVER_PUBLICKEY, bobSignup);
  t.ok(bobSession, "bob signed up");
  const bobPk = bobSession.info.publicKey.z32();

  // 3) Write for Bob via generic client.fetch
  {
    const url = `https://_pubky.${bobPk}/pub/example.com/multi-bob.txt`;
    const r = await sdk.client.fetch(url, {
      method: "PUT",
      body: "bob-data",
      credentials: "include",
    });
    t.ok(r.ok, "bob can write");
  }

  // 4) Alice still authenticated and can write too
  {
    const url = `https://_pubky.${alicePk}/pub/example.com/multi-alice.txt`;
    const r = await sdk.client.fetch(url, {
      method: "PUT",
      body: "alice-data",
      credentials: "include",
    });
    t.ok(r.ok, "alice can still write");
  }

  // 5) Sign out Bob
  await bobSession.signout();

  // 6) Alice still authenticated after Bob signs out
  {
    const url = `https://_pubky.${alicePk}/pub/example.com/multi-alice-2.txt`;
    const r = await sdk.client.fetch(url, {
      method: "PUT",
      body: "alice-still-ok",
      credentials: "include",
    });
    t.ok(r.ok, "alice still can write after bob signout");
  }

  // 7) Bob can no longer write
  {
    const url = `https://_pubky.${bobPk}/pub/example.com/multi-bob-2.txt`;
    const r = await sdk.client.fetch(url, {
      method: "PUT",
      body: "should-fail",
      credentials: "include",
    });
    t.equal(r.status, 401, "bob write fails after signout");
  }

  t.end();
});

/**
 * - Have *two* valid sessions (cookies for both users in one process).
 * - Interleave writes across both users, using BOTH high-level SessionStorage (absolute paths)
 *   and low-level Client.fetch (transport URLs).
 * - Ensure each write lands under the correct user regardless of recent activity or order.
 *
 * If the WASM client ever derives `pubky-host` from a stale/global identity,
 * or the cookie jar gets mismatched, we should see 401/403 or wrong-user data.
 */
test("Auth: multi-user host isolation + stale-handle safety", async (t) => {
  const sdk = Pubky.testnet();

  // Create two users & sign them up — both cookies end up in the same jar.
  const alice = sdk.signer(Keypair.random());
  const bob = sdk.signer(Keypair.random());

  const aliceToken = await createSignupToken();
  const bobToken = await createSignupToken();

  const aliceSession = await alice.signupCookie(HOMESERVER_PUBLICKEY, aliceToken);
  const bobSession = await bob.signupCookie(HOMESERVER_PUBLICKEY, bobToken);

  const A = aliceSession.info.publicKey.z32();
  const B = bobSession.info.publicKey.z32();

  const readTextPublic = async (
    user: string,
    relPath: Path,
  ): Promise<string> => {
    const address = `pubky://${user}${relPath}` as Address;
    return sdk.publicStorage.getText(address);
  };

  const P: Path = "/pub/example.com/owner.txt";

  // 1) Alice writes via SessionStorage (absolute path)
  await aliceSession.storage.putText(P, "alice#1");
  t.equal(
    await readTextPublic(A, P),
    "alice#1",
    "alice write visible under alice",
  );

  // 2) Bob writes via SessionStorage
  await bobSession.storage.putText(P, "bob#1");
  t.equal(await readTextPublic(B, P), "bob#1", "bob write visible under bob");

  // 3) Interleave in reverse order (ensure no global “current user” leakage)
  await bobSession.storage.putText(P, "bob#2");
  await aliceSession.storage.putText(P, "alice#2");
  t.equal(
    await readTextPublic(A, P),
    "alice#2",
    "alice second write still under alice",
  );
  t.equal(
    await readTextPublic(B, P),
    "bob#2",
    "bob second write still under bob",
  );

  // 4) Raw client.fetch using transport URLs
  {
    const urlA = `https://_pubky.${A}${P}`;
    const r = await sdk.client.fetch(urlA, {
      method: "PUT",
      body: "alice#3",
      credentials: "include",
    });
    t.ok(r.ok, "client.fetch PUT for alice ok");
  }
  {
    const urlB = `https://_pubky.${B}${P}`;
    const r = await sdk.client.fetch(urlB, {
      method: "PUT",
      body: "bob#3",
      credentials: "include",
    });
    t.ok(r.ok, "client.fetch PUT for bob ok");
  }

  t.equal(await readTextPublic(A, P), "alice#3", "client.fetch wrote to alice");
  t.equal(await readTextPublic(B, P), "bob#3", "client.fetch wrote to bob");

  // 5) Stale-handle safety: Create a third user; ensure earlier Session handles still write correctly.
  const carol = sdk.signer(Keypair.random());
  const carolToken = await createSignupToken();
  const carolSession = await carol.signupCookie(HOMESERVER_PUBLICKEY, carolToken);
  const C = carolSession.info.publicKey.z32();

  await aliceSession.storage.putText(P, "alice#4");
  await bobSession.storage.putText(P, "bob#4");
  t.equal(
    await readTextPublic(A, P),
    "alice#4",
    "stale alice handle still targets alice",
  );
  t.equal(
    await readTextPublic(B, P),
    "bob#4",
    "stale bob handle still targets bob",
  );

  await carolSession.storage.putText(P, "carol#1");
  t.equal(
    await readTextPublic(C, P),
    "carol#1",
    "carol write lands under carol",
  );

  t.end();
});

/**
 * Simulates a user repeatedly signing up and signing out — which in browsers often
 * correlates with page reloads and “switch account” flows.
 *
 * We assert that:
 *  - Each *new* session writes only for its own user.
 *  - The most recently *signed-out* user cannot write anymore (401).
 *  - Older Session handles never “jump” to a newer identity.
 */
test("Auth: signup/signout loops keep cookies and host in sync", async (t) => {
  const sdk = Pubky.testnet();

  const P: Path = "/pub/example.com/loop.txt";

  async function signupAndMark(label: string): Promise<{
    signer: ReturnType<Facade["signer"]>;
    session: SignupSession;
    user: string;
  }> {
    const signer = sdk.signer(Keypair.random());
    const token = await createSignupToken();
    const session = await signer.signupCookie(HOMESERVER_PUBLICKEY, token);
    const user = session.info.publicKey.z32();
    await session.storage.putText(P, label);
    return { signer, session, user };
  }

  const u1 = await signupAndMark("user#1:hello");
  t.equal(
    await sdk.publicStorage.getText(`pubky://${u1.user}${P}` as Address),
    "user#1:hello",
    "first user marked",
  );

  await u1.session.signout();

  {
    const url = `https://_pubky.${u1.user}${P}`;
    const r = await sdk.client.fetch(url, {
      method: "PUT",
      body: "should-401",
      credentials: "include",
    });
    t.equal(r.status, 401, "signed-out user cannot write");
  }

  const u2 = await signupAndMark("user#2:hello");
  t.equal(
    await sdk.publicStorage.getText(`pubky://${u2.user}${P}` as Address),
    "user#2:hello",
    "second user marked",
  );

  try {
    await u1.session.storage.putText(P, "nope");
    t.fail("stale user#1 session should not be able to write after signout");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "RequestError", "stale handle write -> Error");
  }

  {
    const url = `https://_pubky.${u2.user}${P}`;
    const r = await sdk.client.fetch(url, {
      method: "PUT",
      body: "user#2:via-client",
      credentials: "include",
    });
    t.ok(r.ok, "low-level client PUT for user#2 ok");
  }
  t.equal(
    await sdk.publicStorage.getText(`pubky://${u2.user}${P}` as Address),
    "user#2:via-client",
    "low-level client wrote under user#2",
  );

  t.end();
});
test("Auth: signout removes persisted session cookies", async (t) => {
  const sdk = Pubky.testnet();

  type CookieRecord = { key?: string | null; expires?: unknown; maxAge?: unknown };

  const readSessionCookieNames = async (): Promise<
    | { names: string[] }
    | { reason: string }
  > => {
    type CookieJarLike = {
      serializeSync?: () => { cookies?: CookieRecord[] } | undefined;
      store?: { getAllCookies?: (cb: (error: unknown, cookies?: CookieRecord[] | null) => void) => void };
    };

    const fetchImpl = globalThis.fetch as (typeof globalThis.fetch & { cookieJar?: CookieJarLike }) | undefined;
    if (!fetchImpl || typeof fetchImpl !== "function") {
      return { reason: "global fetch does not expose a cookie jar" };
    }

    const jar = fetchImpl.cookieJar;
    if (!jar) {
      return { reason: "fetch.cookieJar is not available" };
    }

    const fromSerialized = (() => {
      if (typeof jar.serializeSync !== "function") {
        return undefined;
      }
      try {
        const serialized = jar.serializeSync();
        return serialized?.cookies;
      } catch (_) {
        return undefined;
      }
    })();

    if (fromSerialized && Array.isArray(fromSerialized)) {
      return { names: dedupeActiveCookieNames(fromSerialized) };
    }

    const fromStore = await new Promise<CookieRecord[] | undefined>((resolve) => {
      try {
        jar.store?.getAllCookies?.((error, cookies) => {
          if (error) {
            resolve(undefined);
            return;
          }
          resolve(Array.isArray(cookies) ? cookies : []);
        });
      } catch (_) {
        resolve(undefined);
      }
    });

    if (fromStore) {
      return { names: dedupeActiveCookieNames(fromStore) };
    }

    return { reason: "cookie jar did not expose its contents" };
  };

  const dedupeActiveCookieNames = (records: CookieRecord[]): string[] => {
    const names: string[] = [];
    for (const record of records) {
      const name = record?.key;
      if (typeof name !== "string" || name.length === 0) {
        continue;
      }
      if (isExpired(record)) {
        continue;
      }
      names.push(name);
    }
    return Array.from(new Set(names));
  };

  const isExpired = (record: CookieRecord | undefined): boolean => {
    if (!record) {
      return false;
    }

    const expiresAt = parseExpiry(record.expires);
    if (typeof expiresAt === "number" && expiresAt <= Date.now()) {
      return true;
    }

    const maxAgeSeconds = parseMaybeNumber(record.maxAge);
    return typeof maxAgeSeconds === "number" && maxAgeSeconds <= 0;
  };

  const parseExpiry = (value: unknown): number | undefined => {
    if (value instanceof Date) {
      return value.getTime();
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
    if (typeof value === "string" && value.length > 0) {
      const parsed = Date.parse(value);
      if (!Number.isNaN(parsed)) {
        return parsed;
      }
    }
    return undefined;
  };

  const parseMaybeNumber = (value: unknown): number | undefined => {
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
    if (typeof value === "string" && value.length > 0) {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }
    return undefined;
  };

  const sessions: Array<{ session: SignupSession; user: string }> = [];

  for (let i = 0; i < 3; i += 1) {
    const signer = sdk.signer(Keypair.random());
    const token = await createSignupToken();
    const session = await signer.signupCookie(HOMESERVER_PUBLICKEY, token);
    const user = session.info.publicKey.z32();

    sessions.push({ session, user });
  }

  {
    const inspection = await readSessionCookieNames();
    if ("names" in inspection) {
      const expectedUsers = sessions.map(({ user }) => user);
      const missing = expectedUsers.filter((user) => !inspection.names.includes(user));

      t.deepEqual(missing, [], "signup should install a session cookie per user");
    } else {
      t.comment(`after signup: ${inspection.reason}`);
    }
  }

  for (const { session } of sessions) {
    await session.signout();
  }

  const inspection = await readSessionCookieNames();

  if ("names" in inspection) {
    const expectedUsers = sessions.map(({ user }) => user);
    const lingering = expectedUsers.filter((user) => inspection.names.includes(user));

    t.deepEqual(
      lingering,
      [],
      "cookies belonging to signed-out sessions should be removed from the environment",
    );
  } else {
    t.comment(`after signout: ${inspection.reason}`);
  }

  t.end();
});
