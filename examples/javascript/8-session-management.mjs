#!/usr/bin/env node
// Create, list, and delete grant-backed sessions from the command line.
import { GrantManager, Keypair, Pubky, PublicKey } from "@synonymdev/pubky";
import {
  args,
  isConflictError,
  promptHidden,
  readFileUint8,
} from "./_cli.mjs";
import { TESTNET_HOMESERVER } from "./_testnet.mjs";
const MANAGEMENT_CLIENT_ID = "session-management.example";
const DEFAULT_RECOVERY_FILE = new URL("../sample_recovery.key", import.meta.url);

const usage = `
Usage:
  node 8-session-management.mjs [--recovery-file <path>] [--testnet] <list|create|delete> [grant-id]

Examples:
  node 8-session-management.mjs --testnet list
  node 8-session-management.mjs --testnet create
  node 8-session-management.mjs --testnet create --client-id my-app.example
  node 8-session-management.mjs --testnet delete <grant-id>
`;

const a = args(process.argv.slice(2), { usage });
const [command, grantId] = a._;

if (!command || !["list", "create", "delete"].includes(command)) {
  console.error(usage.trim());
  process.exit(1);
}

if (command === "delete" && !grantId) {
  console.error("Missing grant id.\n");
  console.error(usage.trim());
  process.exit(1);
}

if (command === "list") {
  const session = await rootSession();
  await listSessions(session);
} else if (command === "create") {
  await createSession(a["client-id"] ?? MANAGEMENT_CLIENT_ID);
} else if (command === "delete") {
  const session = await rootSession();
  await deleteSession(session, grantId);
}

async function rootSession() {
  return createSessionFor(MANAGEMENT_CLIENT_ID);
}

async function createSession(clientId) {
  const session = await createSessionFor(clientId);
  const info = await grantView(session).sessionInfo();

  console.log("Created session:");
  console.log("  pubky:", info.publicKey.toString());
  console.log("  client_id:", info.clientId);
  console.log("  grant_id:", info.grantId);
  console.log("  token_expires_at:", info.tokenExpiresAt);
  console.log("  grant_expires_at:", info.grantExpiresAt);
}

async function createSessionFor(clientId) {
  const keypair = await decryptRecoveryFile();
  const pubky = a.testnet ? Pubky.testnet() : new Pubky();
  const signer = pubky.signer(keypair);

  if (a.testnet) {
    const homeserver = PublicKey.from(TESTNET_HOMESERVER);
    try {
      await signer.signup(homeserver);
      console.log("Signed up to the testnet homeserver.");
    } catch (error) {
      if (!isConflictError(error)) {
        console.error("Failed to sign up to the testnet homeserver:", error);
        process.exit(1);
      }

      console.log("Testnet user already exists, continuing...");
    }
  }

  return signer.signin(clientId);
}

async function decryptRecoveryFile() {
  const recoveryPath = a["recovery-file"] ?? DEFAULT_RECOVERY_FILE;
  const recoveryBytes = await readFileUint8(recoveryPath);

  try {
    return Keypair.fromRecoveryFile(recoveryBytes, "");
  } catch {
    const passphrase = await promptHidden("Enter recovery file passphrase: ");
    return Keypair.fromRecoveryFile(recoveryBytes, passphrase);
  }
}

async function listSessions(session) {
  const currentGrantId = await grantView(session).grantId();
  const grants = await new GrantManager(session).list();
  await signout(session);

  const activeGrants = grants.filter((grant) => grant.grantId !== currentGrantId);
  if (activeGrants.length === 0) {
    console.log("No active sessions.");
    return;
  }

  console.log("Active sessions:");
  for (const grant of activeGrants) {
    console.log("\nGrant ID:", grant.grantId);
    console.log("  client_id:", grant.clientId);
    console.log("  capabilities:", grant.capabilities);
    console.log("  issued_at:", grant.issuedAt);
    console.log("  expires_at:", grant.expiresAt);
  }
}

async function deleteSession(session, id) {
  await new GrantManager(session).revoke(id);
  await signout(session);
  console.log(`Deleted session with grant id ${id}.`);
}

function grantView(session) {
  if (!session.grant) throw new Error("Expected a grant-backed session.");
  return session.grant;
}

async function signout(session) {
  try {
    await session.signout();
  } catch (err) {
    console.error("Warning: failed to sign out management session:", err);
  }
}
