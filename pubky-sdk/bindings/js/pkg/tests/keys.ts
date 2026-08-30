import test from "tape";

import { Keypair, PublicKey } from "../index.js";
import { Assert, IsExact } from "./utils.js";

type KeypairClass = typeof Keypair;
type PublicKeyClass = typeof PublicKey;

const _keypairReturn: Assert<
  IsExact<ReturnType<KeypairClass["fromSecret"]>, Keypair>
> = true;
const _publicKeyReturn: Assert<
  IsExact<ReturnType<PublicKeyClass["from"]>, PublicKey>
> = true;

test("generate keys from a secret", async (t) => {
  const secret = Buffer.from(
    "5aa93b299a343aa2691739771f2b5b85e740ca14c685793d67870f88fa89dc51",
    "hex",
  );

  const keypair = Keypair.fromSecret(secret);

  t.is(
    keypair.publicKey.z32(),
    "gcumbhd7sqit6nn457jxmrwqx9pyymqwamnarekgo3xppqo6a19o",
  );
});

test("fromSecret error", async (t) => {
  const secret = Buffer.from("5aa93b299a343aa2691739771f2b5b", "hex");

  t.throws(
    () => Keypair.fromSecret(null as unknown as Uint8Array),
    "Expected secret to be an instance of Uint8Array",
  );
  t.throws(
    () => Keypair.fromSecret(secret),
    /Expected secret to be 32 bytes, got 15/,
  );
});

test("PublicKey from and toUint8Array", async (t) => {
  const z32 = "gcumbhd7sqit6nn457jxmrwqx9pyymqwamnarekgo3xppqo6a19o";
  const publicKey = PublicKey.from(z32);
  t.is(publicKey.z32(), z32);
  t.is(publicKey.toString(), z32);
  t.is(PublicKey.from(`pubky${z32}`).toString(), z32, "accepts legacy input");
  t.deepEqual(
    publicKey.toUint8Array(),
    Uint8Array.from([
      51, 38, 176, 240, 125, 179, 171, 31, 8, 90, 223, 82, 245, 146, 142, 127,
      218, 0, 45, 212, 194, 197, 130, 33, 70, 134, 94, 214, 186, 30, 196, 191,
    ]),
  );
});
