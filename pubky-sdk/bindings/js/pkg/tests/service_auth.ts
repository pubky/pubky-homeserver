import test from "tape";
import { Keypair, PublicKey, Pubky, type GrantSession, type ServiceAuthProof } from "../index.js";
import { Assert, IsExact, assertPubkyError, createSignupToken } from "./utils.js";
import { assertServiceAuthCredentials } from "./service_auth_helpers.js";

type _ProofResult = Assert<IsExact<ReturnType<GrantSession["createServiceAuthProof"]>, Promise<ServiceAuthProof>>>;

test("service auth: local grant survives existing restoration", async t => {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  await signer.signup(PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo"), await createSignupToken());
  const session = await signer.signin("service-auth.test");
  const audience = " Inbox:é/生产 ";
  const proof = await session.grant!.createServiceAuthProof(audience);
  await assertServiceAuthCredentials(t, proof, audience);
  const restored = await sdk.restoreSession(await session.grant!.exportLocalSecret());
  const originalFetch = globalThis.fetch;
  let requests = 0;
  globalThis.fetch = async () => {
    requests++;
    throw new Error("proof generation must be network-free");
  };
  try {
    const restoredProof = await restored.grant!.createServiceAuthProof(audience);
    await assertServiceAuthCredentials(t, restoredProof, audience);
    t.equal(restoredProof.grant, proof.grant, "restoration preserves the original grant");
    t.equal(requests, 0, "proof generation makes no network requests");
  } finally {
    globalThis.fetch = originalFetch;
  }
  t.end();
});

test("service auth: audience limits count UTF-8 bytes", async t => {
  const sdk = Pubky.testnet();
  const signer = sdk.signer(Keypair.random());
  await signer.signup(PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo"), await createSignupToken());
  const session = await signer.signin("service-auth-audience.test");
  for (const invalid of ["", "é".repeat(513)]) {
    try {
      await session.grant!.createServiceAuthProof(invalid);
      t.fail("invalid audience must fail");
    } catch (error) {
      assertPubkyError(t, error);
      t.deepEqual(error.data, { reason: "InvalidServiceAudience" }, "audience failure is actionable");
    }
  }
  const audience = "é".repeat(512);
  const proof = await session.grant!.createServiceAuthProof(audience);
  await assertServiceAuthCredentials(t, proof, audience);
  t.end();
});
