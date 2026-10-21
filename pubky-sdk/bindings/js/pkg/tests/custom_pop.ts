import test from "tape";
import { Keypair, PublicKey, Pubky, verifyCustomGrantPop, type GrantSession, type CustomPop, type JsonValue } from "../index.js";
import { Assert, IsExact, assertPubkyError, createSignupToken } from "./utils.js";

type _ProofResult = Assert<IsExact<ReturnType<GrantSession["createCustomPop"]>, Promise<CustomPop>>>;

test("custom PoP: restored local session signs arbitrary JSON offline", async t => {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  await signer.signup(PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo"), await createSignupToken());
  const session = await signer.signin("custom-pop.test");
  const original = await session.grant!.createCustomPop(null);
  const restored = await sdk.restoreSession(await session.grant!.exportLocalSecret());
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("custom proofs must be network-free"); };
  try {
    const values: JsonValue[] = [null, true, 42, "é/生产", [1, "two"], { gid: "application-field", nested: { challenge: "abc" } }];
    const nonces = new Set<string>();
    for (const data of values) {
      const proof = await restored.grant!.createCustomPop(data);
      t.equal(proof.grant, original.grant, "bundle preserves the original grant");
      const verified = verifyCustomGrantPop(JSON.parse(JSON.stringify(proof)));
      t.deepEqual(verified.data, data, "arbitrary JSON round-trips through verification");
      t.equal(verified.identity, verified.grantClaims.iss, "identity comes from verified grant");
      t.ok(Math.abs(verified.iat - Date.now() / 1000) < 60, "proof carries its signing time");
      nonces.add(verified.nonce);
      t.deepEqual(verifyCustomGrantPop(proof).data, data, "stateless verification permits reuse");
      const [header, payload, signature] = proof.pop.split(".");
      const claims = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
      claims.data = "tampered";
      const changed = btoa(JSON.stringify(claims)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      try {
        verifyCustomGrantPop({ grant: proof.grant, pop: `${header}.${changed}.${signature}` });
        t.fail("tampered data must fail");
      } catch (error) {
        assertPubkyError(t, error);
        t.deepEqual(error.data, { reason: "InvalidProofSignature" });
      }
    }
    t.equal(nonces.size, values.length, "each proof gets a fresh nonce");

    const omitted = await restored.grant!.createCustomPop({ dropped: undefined, kept: 1 } as unknown as JsonValue);
    t.deepEqual(verifyCustomGrantPop(omitted).data, { kept: 1 }, "data follows JSON.stringify semantics");
    const extended = { ...omitted, future: "field" } as CustomPop;
    t.deepEqual(verifyCustomGrantPop(extended).data, { kept: 1 }, "unknown bundle fields are ignored");
    try {
      await restored.grant!.createCustomPop(undefined as unknown as JsonValue);
      t.fail("non-JSON data must fail");
    } catch (error) {
      assertPubkyError(t, error);
      t.equal(error.name, "InvalidInput");
    }
  } finally {
    globalThis.fetch = originalFetch;
  }

  const verifiedOriginal = verifyCustomGrantPop(original);
  const { exp } = verifiedOriginal.grantClaims;
  // The proof is signed at or after the grant's issue time; skew is measured from the later one.
  const iat = Math.max(verifiedOriginal.iat, verifiedOriginal.grantClaims.iat);
  const notYetValid = verifiedOriginal.iat > verifiedOriginal.grantClaims.iat ? "ProofNotYetValid" : "GrantNotYetValid";
  const originalNow = Date.now;
  try {
    Date.now = () => (iat - 30) * 1000;
    t.ok(verifyCustomGrantPop(original), "default accepts exactly 30 seconds of future skew");
    t.ok(verifyCustomGrantPop(original, {}), "empty options preserve the default");
    for (const [now, seconds] of [[iat - 31, undefined], [iat - 1, 0], [iat - 61, 60]] as const) {
      Date.now = () => now * 1000;
      try {
        verifyCustomGrantPop(original, seconds === undefined ? undefined : { clockSkewSeconds: seconds });
        t.fail("issue time beyond allowance must fail");
      } catch (error) {
        assertPubkyError(t, error);
        t.deepEqual(error.data, { reason: notYetValid });
      }
    }
    Date.now = () => (iat - 60) * 1000;
    t.ok(verifyCustomGrantPop(original, { clockSkewSeconds: 60 }), "custom allowance includes its boundary");
    Date.now = () => exp * 1000;
    try {
      verifyCustomGrantPop(original, { clockSkewSeconds: 60 });
      t.fail("skew must not extend grant expiry");
    } catch (error) {
      assertPubkyError(t, error);
      t.deepEqual(error.data, { reason: "GrantExpired" });
    }
  } finally {
    Date.now = originalNow;
  }
  for (const clockSkewSeconds of [-1, 0.5, NaN, Infinity, 4294967296]) {
    try {
      verifyCustomGrantPop(original, { clockSkewSeconds });
      t.fail("invalid allowance must fail");
    } catch (error) {
      assertPubkyError(t, error);
      t.equal(error.name, "InvalidInput");
    }
  }
  t.end();
});
