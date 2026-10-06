import test from "tape";
import { PublicKey, type ServiceAuthProof } from "../index.js";

export function decodeClaims<T>(jws: string): T {
  return JSON.parse(new TextDecoder().decode(decodeBase64url(jws.split(".")[1])));
}

function decodeBase64url(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}

async function verifyJws(jws: string, publicKey: string): Promise<boolean> {
  const [header, payload, signature] = jws.split(".");
  const publicKeyBytes = new Uint8Array(PublicKey.from(publicKey).toUint8Array());
  const key = await crypto.subtle.importKey("raw", publicKeyBytes, "Ed25519", false, ["verify"]);
  const signingInput = new TextEncoder().encode(`${header}.${payload}`);
  return crypto.subtle.verify("Ed25519", key, decodeBase64url(signature), signingInput);
}

/** Verify supplied credentials without generating proofs or changing global state. */
export async function assertServiceAuthCredentials(
  t: test.Test,
  proof: ServiceAuthProof,
  audience: string,
): Promise<void> {
  const rootClaims = decodeClaims<{ iss: string; cnf: string; jti: string }>(proof.grant);
  const claims = decodeClaims<{ aud: string; gid: string; nonce: string; iat: number }>(proof.pop);
  const headerBytes = decodeBase64url(proof.pop.split(".")[0]);
  const header = JSON.parse(new TextDecoder().decode(headerBytes));

  t.equal(Object.getPrototypeOf(proof), Object.prototype, "credentials are a plain object");
  t.deepEqual(Object.keys(proof).sort(), ["grant", "pop"], "credentials have the exchange shape");
  t.deepEqual(header, { alg: "EdDSA", typ: "pubky-service-pop-v1" }, "external proof type is versioned");
  t.equal(claims.aud, audience, "opaque audience is preserved exactly");
  t.equal(claims.gid, rootClaims.jti, "proof binds the returned grant");
  t.equal(decodeBase64url(claims.nonce).length, 32, "nonce contains 256 random bits");
  t.ok(Math.abs(claims.iat - Date.now() / 1000) < 10, "proof has a fresh Unix timestamp");
  t.ok(await verifyJws(proof.grant, rootClaims.iss), "original grant has a valid root signature");
  t.ok(await verifyJws(proof.pop, rootClaims.cnf), "proof verifies with the bound client public key");
}
