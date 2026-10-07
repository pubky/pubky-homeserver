import test from "tape";
import {
  Keypair, MemoryReplayStore, ServiceAuthVerifier,
  type ConsumeOutcome, type ReplayRequest, type ReplayStore, type ServiceAuthProof,
  type VerifiedGrantClaims, type VerifiedServiceProofClaims,
} from "../index.js";
import { assertPubkyError } from "./utils.js";

const audience = "inbox:production";

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sign(keypair: Keypair, typ: string, claims: object): Promise<string> {
  // PKCS#8 Ed25519 private key prefix followed by the 32-byte seed.
  const prefix = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
  const key = await crypto.subtle.importKey("pkcs8", new Uint8Array([...prefix, ...keypair.secret()]), "Ed25519", false, ["sign"]);
  const encode = (value: object) => base64url(new TextEncoder().encode(JSON.stringify(value)));
  const input = `${encode({ alg: "EdDSA", typ })}.${encode(claims)}`;
  const signature = await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(input));
  return `${input}.${base64url(new Uint8Array(signature))}`;
}

/** Real signatures without network or homeserver fixtures. */
async function fixture() {
  const root = Keypair.random();
  const client = Keypair.random();
  const now = Math.floor(Date.now() / 1000);
  const grantClaims: VerifiedGrantClaims = {
    iss: root.publicKey.z32(), client_id: "inbox.test", caps: ["/pub/inbox/:rw"],
    cnf: client.publicKey.z32(), jti: "test-grant", iat: now - 10, exp: now + 3600,
  };
  const proofClaims: VerifiedServiceProofClaims = {
    aud: audience, gid: grantClaims.jti, nonce: base64url(crypto.getRandomValues(new Uint8Array(32))), iat: now,
  };
  async function credentials(): Promise<ServiceAuthProof> {
    return {
      grant: await sign(root, "pubky-grant", grantClaims),
      pop: await sign(client, "pubky-service-pop-v1", proofClaims),
    };
  }
  return { grantClaims, proofClaims, credentials };
}

async function rejects(t: test.Test, operation: () => unknown, reason: string, storageReason?: string) {
  try {
    await operation();
    t.fail(`expected ${reason}`);
  } catch (error) {
    assertPubkyError(t, error);
    t.deepEqual(error.data, storageReason ? { reason, storageReason } : { reason }, "structured failure");
    return error;
  }
}

test("service verifier: complete verified claims and atomic replay protection", async t => {
  const f = await fixture();
  const credentials = await f.credentials();
  const store = new MemoryReplayStore(10);
  const verifier = new ServiceAuthVerifier(audience, store, { maxProofAgeSeconds: 120 });
  const results = await Promise.allSettled([
    verifier.verifyAndConsume(credentials), verifier.verifyAndConsume(credentials),
  ]);
  const accepted = results.filter(result => result.status === "fulfilled");
  t.equal(accepted.length, 1, "only one concurrent request succeeds");
  if (accepted[0]?.status === "fulfilled") {
    t.deepEqual(accepted[0].value, {
      identity: f.grantClaims.iss, clientId: f.grantClaims.client_id,
      grantId: f.grantClaims.jti, grantExpiresAt: f.grantClaims.exp,
      grantClaims: f.grantClaims, proofClaims: f.proofClaims,
    }, "plain result exposes every signed claim and summary field");
  }
  const rejected = results.find(result => result.status === "rejected");
  t.equal(rejected?.status === "rejected" && rejected.reason.data.reason, "Replay", "loser is a replay");
  const other = new ServiceAuthVerifier(audience, store, { maxProofAgeSeconds: 120 });
  await rejects(t, () => other.verifyAndConsume(credentials), "Replay");
  const changed = new ServiceAuthVerifier(audience, store, { maxProofAgeSeconds: 60 });
  await rejects(t, () => changed.verifyAndConsume(credentials), "Storage", "PolicyMismatch");
  t.end();
});

test("service verifier: built-in memory handles retain Rust state independently of JS wrappers", async t => {
  const f = await fixture();
  const proof = await f.credentials();
  const store = new MemoryReplayStore(10);
  store.consumeOnce = async () => { throw new Error("built-in verification must stay in Rust"); };
  const verifier = new ServiceAuthVerifier(audience, store);
  const other = new ServiceAuthVerifier(audience, store);
  store.free();
  await verifier.verifyAndConsume(proof);
  await rejects(t, () => other.verifyAndConsume(proof), "Replay");
  t.end();
});

test("service verifier: invalid credentials do not consume memory capacity", async t => {
  const f = await fixture();
  const verifier = new ServiceAuthVerifier(audience, new MemoryReplayStore(1));
  const valid = await f.credentials();
  await rejects(t, () => verifier.verifyAndConsume({ ...valid, pop: "broken" }), "MalformedCredential");
  const [header, payload, signature] = valid.pop.split(".");
  const damaged = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  await rejects(t, () => verifier.verifyAndConsume({ ...valid, pop: `${header}.${payload}.${damaged}` }), "InvalidProofSignature");
  f.proofClaims.aud = "other-service";
  await rejects(t, () => f.credentials().then(proof => verifier.verifyAndConsume(proof)), "AudienceMismatch");
  f.proofClaims.aud = audience;
  await verifier.verifyAndConsume(valid);
  f.proofClaims.nonce = base64url(new Uint8Array(32));
  await rejects(t, () => f.credentials().then(proof => verifier.verifyAndConsume(proof)), "Storage", "Capacity");
  t.end();
});

test("service verifier: custom store receives bounded requests and retains its receiver", async t => {
  const f = await fixture();
  const proof = await f.credentials();
  const requests: ReplayRequest[] = [];
  const store = {
    memory: new MemoryReplayStore(10),
    async consumeOnce(request: ReplayRequest): Promise<ConsumeOutcome> {
      requests.push(request);
      return this.memory.consumeOnce(request);
    },
  } satisfies ReplayStore & { memory: MemoryReplayStore };
  const verifier = ServiceAuthVerifier.withStore(audience, store);
  await verifier.verifyAndConsume(proof);
  await rejects(t, () => verifier.verifyAndConsume(proof), "Replay");
  t.equal(requests[0].key.length, 32, "32-byte replay key");
  t.deepEqual(requests[0].key, requests[1].key, "stable key across retries");
  t.equal(requests[0].policyFingerprint.length, 32, "32-byte policy fingerprint");
  t.equal(requests[0].notBefore, f.proofClaims.iat - 30, "inclusive lower bound");
  t.equal(requests[0].expiresAt, f.proofClaims.iat + 180, "exclusive retention deadline");
  const key = requests[0].key;
  key.fill(0);
  t.notDeepEqual(requests[0].key, key, "byte getters return copies");
  const changed = ServiceAuthVerifier.withStore(audience, store, { maxProofAgeSeconds: 60 });
  await rejects(t, () => changed.verifyAndConsume(proof), "Storage", "Backend");
  t.end();
});

test("service verifier: custom store failures fail closed", async t => {
  const f = await fixture();
  const proof = await f.credentials();
  const callbacks: Array<{ consumeOnce: () => unknown; reason: string; message: string }> = [
    { consumeOnce: () => { throw new Error("synchronous failure"); }, reason: "Backend", message: "synchronous failure" },
    { consumeOnce: async () => { throw new Error("database unavailable"); }, reason: "Backend", message: "database unavailable" },
    // Custom errors are diagnostics, not instructions to reconstruct a Rust variant.
    { consumeOnce: async () => { throw { message: "custom capacity error", data: { reason: "Capacity" } }; }, reason: "Backend", message: "custom capacity error" },
    { consumeOnce: async () => undefined, reason: "InvalidResponse", message: "must resolve to" },
    { consumeOnce: async () => true, reason: "InvalidResponse", message: "must resolve to" },
    { consumeOnce: async () => "unknown", reason: "InvalidResponse", message: "must resolve to" },
    { consumeOnce: () => "consumed", reason: "InvalidResponse", message: "must return a Promise" },
  ];
  for (const { consumeOnce, reason, message } of callbacks) {
    const verifier = ServiceAuthVerifier.withStore(audience, { consumeOnce } as ReplayStore);
    const error = await rejects(t, () => verifier.verifyAndConsume(proof), "Storage", reason);
    t.ok(error?.message.includes(message), "failure retains a useful diagnostic");
  }
  let calls = 0;
  const verifier = ServiceAuthVerifier.withStore(audience, {
    async consumeOnce() { calls++; return "consumed"; },
  });
  await rejects(t, () => verifier.verifyAndConsume({ grant: "bad", pop: "bad" }), "MalformedCredential");
  t.equal(calls, 0, "invalid credentials never reach a custom store");
  t.end();
});

test("service verifier: time checks include time spent awaiting storage", async t => {
  const f = await fixture();
  const proof = await f.credentials();
  const originalNow = Date.now;
  const now = originalNow();
  try {
    const verifier = ServiceAuthVerifier.withStore(audience, {
      async consumeOnce() {
        Date.now = () => now + 181_000;
        return "consumed";
      },
    });
    await rejects(t, () => verifier.verifyAndConsume(proof), "InvalidTimestamp");
    Date.now = () => now;
    const memory = new ServiceAuthVerifier(audience, new MemoryReplayStore(1));
    await memory.verifyAndConsume(proof);
    Date.now = () => now - 1000;
    await rejects(t, () => memory.verifyAndConsume(proof), "Storage", "ClockRollback");
    Date.now = () => (f.grantClaims.exp + 1) * 1000;
    await rejects(t, () => memory.verifyAndConsume(proof), "GrantExpired");
  } finally {
    Date.now = originalNow;
  }
  t.end();
});

test("service verifier: rejects invalid configuration", async t => {
  for (const capacity of [0, -1, 1.5, NaN, Infinity, 2 ** 32]) {
    await rejects(t, () => new MemoryReplayStore(capacity), "InvalidConfiguration");
  }
  await rejects(t, () => new ServiceAuthVerifier("", new MemoryReplayStore(1)), "InvalidServiceAudience");
  await rejects(t, () => new ServiceAuthVerifier(audience, new MemoryReplayStore(1), { maxProofAgeSeconds: 0 }), "InvalidPolicy");
  t.end();
});

test("service verifier: never rounds a signed expiration in returned claims", async t => {
  const f = await fixture();
  f.grantClaims.exp = Number.MAX_SAFE_INTEGER + 1;
  const verifier = new ServiceAuthVerifier(audience, new MemoryReplayStore(1));
  const error = await rejects(t, () => f.credentials().then(proof => verifier.verifyAndConsume(proof)), "TimestampOutOfRange");
  t.equal(error?.name, "InvalidInput", "numeric representation is an input problem");
  t.ok(error?.message.includes("maximum safe integer"), "message explains the representation limit");
  t.end();
});
