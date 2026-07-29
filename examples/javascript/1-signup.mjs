#!/usr/bin/env node
// Sign up using a recovery file -> print session info.
import { Pubky, Keypair, PublicKey } from "@synonymdev/pubky";
import { args, promptHidden, readFileUint8 } from "./_cli.mjs";
import { TESTNET_HOMESERVER } from "./_testnet.mjs";
const DEFAULT_RECOVERY_FILE = new URL("../sample_recovery.key", import.meta.url);

const usage = `
Usage:
  node 1-signup.mjs [homeserver_pubky] [--recovery-file <path>] [--signup-code <code>] [--testnet]

Examples:
  node 1-signup.mjs --testnet
  node 1-signup.mjs pubky8pinxxg... --recovery-file ./alice.recovery --signup-code INVITE-123
`;

const a = args(process.argv.slice(2), { usage });
const [homeserverArg] = a._;
const homeserverKey = homeserverArg ?? (a.testnet ? TESTNET_HOMESERVER : undefined);
if (!homeserverKey) {
  console.error(usage.trim());
  process.exit(1);
}

// 1) Init a mainnet/testnet Pubky SDK entrypoint
const pubky = a.testnet ? Pubky.testnet() : new Pubky();

// 2) Decrypt recovery -> Keypair -> Signer
const recoveryPath = a["recovery-file"] ?? DEFAULT_RECOVERY_FILE;
const recoveryBytes = await readFileUint8(recoveryPath);
let keypair;
try {
  keypair = Keypair.fromRecoveryFile(recoveryBytes, "");
} catch {
  const passphrase = await promptHidden("Enter recovery passphrase: ");
  keypair = Keypair.fromRecoveryFile(recoveryBytes, passphrase);
}
const signer = pubky.signer(keypair);

// 3) Signup at the homeserver (optional invite)
const homeserver = PublicKey.from(homeserverKey);
await signer.signup(homeserver, a["signup-code"]);

// 4) Sign in to create a grant-backed session for this example client
const session = await signer.signin("pubky-js-signup.example");

// 5) Show session owner + capabilities
console.log("\nSigned up as:", session.info.publicKey.toString());
console.log("Capabilities:", session.info.capabilities);
