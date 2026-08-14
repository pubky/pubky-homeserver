import test from "tape";
import { Keypair, Pubky, PublicKey } from "../index.js";
import {
  Assert,
  IsExact,
  assertPubkyError,
  createSignupToken,
} from "./utils.js";

const HOMESERVER_PUBLICKEY = PublicKey.from(
  "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo",
);

/**
 * PKDNS: operational resolution failures reject.
 * Flow:
 *  - facade -> read-only pkdns resolver
 *  - generate keypair without publishing any record
 *  - the isolated testnet cannot resolve the key
 *  - resolver rejects instead of treating the failure as an absent record
 */
test("pkdns: getHomeserver rejects resolution failures", async (t) => {
  const sdk = Pubky.testnet();
  type Sdk = typeof sdk;
  const _resolver: Assert<
    IsExact<Awaited<ReturnType<Sdk["getHomeserverOf"]>>, PublicKey | undefined>
  > = true;

  const fresh = Keypair.random();
  const pubkey = fresh.publicKey;

  try {
    await sdk.getHomeserverOf(pubkey);
    t.fail("resolution failure should reject");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "PkarrError", "resolution failure maps to PkarrError");
    t.ok(
      error.message.includes("no responses"),
      "error preserves the resolution failure",
    );
  }
  t.end();
});

/**
 * PKDNS: signup publishes _pubky; both read-only and signer-bound resolvers agree.
 * Flow:
 *  - facade -> signer -> signup -> server publishes _pubky(host=homeserver)
 *  - read-only resolver returns homeserver public key
 *  - signer-bound resolver returns the same
 */
test("pkdns: getHomeserver success", async (t) => {
  const sdk = Pubky.testnet();

  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);

  const pubkey = signer.publicKey;

  // Read-only resolver
  const hs = await sdk.getHomeserverOf(pubkey);
  t.ok(hs, "resolver returns homeserver public key");
  t.equal(
    hs?.z32(),
    HOMESERVER_PUBLICKEY.z32(),
    "resolver matches homeserver public key",
  );

  // Self resolver (signer-bound)
  const hsSelf = await signer.pkdns.getHomeserver();
  t.ok(hsSelf, "signer resolver returns homeserver public key");
  t.equal(
    hsSelf?.z32(),
    HOMESERVER_PUBLICKEY.z32(),
    "self getHomeserver matches",
  );

  t.end();
});

/**
 * PKDNS: IfStale respects freshness; Force overrides immediately.
 * Flow:
 *  - signup publishes initial record (fresh)
 *  - publishHomeserverIfStale(alt) is a no-op when record is fresh
 *  - publishHomeserverForce(alt2) overrides regardless of age
 */
test("pkdns: ifStale is a no-op when fresh; force overrides", async (t) => {
  const sdk = Pubky.testnet();

  // 1) Signup a user so an initial _pubky record exists
  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
  const userPk = signer.publicKey;

  const publisher = signer.pkdns;

  const altHost1 = PublicKey.from(
    "m14ckuxretmbwb3cfuucxa8g3o1yzkxu5dx5b5iowxb1onfn6t4o",
  );
  const altHost2 = PublicKey.from(
    "ci6ss67bc3th6uxbwrkimeo7y3rfgs8m59ce8pt6ts5tn8o63cto",
  );

  // Sanity: initial host matches homeserver
  {
    const initialHost = await sdk.getHomeserverOf(userPk);
    t.ok(initialHost, "initial record exists");
    t.equal(
      initialHost?.z32(),
      HOMESERVER_PUBLICKEY.z32(),
      "initial homeserver matches signup",
    );
  }

  // 2) IfStale with override should NOT change a fresh record
  {
    await publisher.publishHomeserverIfStale(altHost1); // fresh -> no-op
    const host = await sdk.getHomeserverOf(userPk);
    t.ok(host, "ifStale returns homeserver");
    t.equal(
      host?.z32(),
      HOMESERVER_PUBLICKEY.z32(),
      "ifStale did not override fresh record",
    );
  }

  // 3) Force should override immediately regardless of age
  {
    const altHost2z32 = altHost2.z32();
    await publisher.publishHomeserverForce(altHost2);
    const host = await sdk.getHomeserverOf(userPk);
    t.ok(host, "force publish returns homeserver");
    t.equal(
      host?.z32(),
      altHost2z32,
      "force publish overrides regardless of age",
    );
  }

  t.end();
});
