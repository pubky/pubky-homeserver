#!/usr/bin/env node
// Demonstrate SDK logging by dialing up verbosity before performing a simple roundtrip.
import { Pubky, Keypair, PublicKey, setLogLevel } from "@synonymdev/pubky";
import { args } from "./_cli.mjs";
import { TESTNET_HOMESERVER } from "./_testnet.mjs";

const usage = `
Usage:
  node 7-logging.mjs [--testnet] [--homeserver <pubky>] [--level <error|warn|info|debug|trace>]

Examples:
  node 7-logging.mjs --testnet --level debug
  node 7-logging.mjs --homeserver <mainnet_pk> --level info
`;

const a = args(process.argv.slice(2), {
  usage,
  defaults: {
    level: "info",
  },
});

const level = String(a.level).toLowerCase();
try {
  setLogLevel(level);
  console.log(`Pubky SDK log level set to: ${level}`);
} catch (error) {
  console.error("Failed to configure logging:", error);
  process.exit(1);
}

const pubky = a.testnet ? Pubky.testnet() : new Pubky();

const homeserverArg = a.homeserver ?? (a.testnet ? TESTNET_HOMESERVER : null);
if (!homeserverArg) {
  console.error("Missing --homeserver. Specify one explicitly or pass --testnet.");
  console.error(usage.trim());
  process.exit(1);
}

const homeserver = PublicKey.from(homeserverArg);

const keypair = Keypair.random();
const signer = pubky.signer(keypair);
console.log("Generated ephemeral signer:", keypair.publicKey.toString());

console.log("Signing up to homeserver... (watch the debug logs above)");
await signer.signup(homeserver);

console.log("Signing in with a grant-backed session...");
const session = await signer.signin("logging.example");

const path = `/pub/logging.example/${Date.now()}.txt`;
console.log(`Writing sample data to ${path}`);
await session.storage.putText(path, `Logged at ${new Date().toISOString()}`);

console.log("Reading it back to trigger additional request logging...");
const text = await session.storage.getText(path);
console.log("Roundtrip succeeded:", text);
