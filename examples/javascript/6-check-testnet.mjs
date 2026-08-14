#!/usr/bin/env node

/**
 * Script to test if the local testnet is available by performing an end-to-end roundtrip: signup -> signin -> write -> read.
 * Usage: `node 6-check-testnet.mjs`
 */

// End-to-end testnet roundtrip: signup -> signin -> write -> read.
import { Pubky, Keypair, PublicKey } from "@synonymdev/pubky";
import { TESTNET_HOMESERVER } from "./_testnet.mjs";


let isAvailable = await isTestnetAvailable();
if (isAvailable) {
  console.log("Testnet is available, roundtrip succeeded.");
} else {
  console.error("Testnet is not available, roundtrip failed. Please make sure you have a local testnet running");
}

/**
 * Checks if the local testnet is available by performing a roundtrip: signup -> signin -> write -> read.
 * @returns True if the roundtrip succeeded, false otherwise.
 */
async function isTestnetAvailable() {

  try {
    // 1) Build Pubky SDK facade for local testnet host
    const pubky = Pubky.testnet();

    // 2) Make a random keypair, bind it to a signer and sign up on the given homeserver
    const keypair = Keypair.random();
    const signer = pubky.signer(keypair);
    const homeserver = PublicKey.from(TESTNET_HOMESERVER);
    await signer.signup(homeserver);

    // 3) Sign in to create a grant-backed session for storage access
    const session = await signer.signin("my-cool-app.example");

    // 4) Write then read a file under /pub/<your.app>/
    const path = "/pub/my-cool-app/hello.txt";
    await session.storage.putText(path, "hi");

    const roundtrip = await session.storage.getText(path);
    await session.signout();
    return true
  } catch (e) {
    console.error("Testnet roundtrip failed, error:", e);
    return false
  }

}
