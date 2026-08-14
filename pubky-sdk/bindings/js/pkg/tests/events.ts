import test from "tape";

import { Keypair, Pubky, PublicKey, type Path } from "../index.js";
import { assertPubkyError, createSignupToken, sleep } from "./utils.js";

const HOMESERVER_PUBLICKEY = PublicKey.from(
  "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo",
);

/**
 * Test eventStreamForUser() — single-user convenience API.
 */
test("eventStreamForUser: single-user convenience", async (t) => {
  const sdk = Pubky.testnet();

  // Setup: create a user with some events
  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
  const session = await signer.signin("events.test");
  const userPk = session.info.publicKey;

  for (let i = 0; i < 5; i++) {
    const path = `/pub/app/file_${i}.txt` as Path;
    await session.storage.putText(path, `content ${i}`);
  }

  await sleep(500);

  // === Test 1: Basic fetch ===
  t.comment("eventStreamForUser: basic fetch");

  const stream1 = await sdk
    .eventStreamForUser(userPk, null)
    .limit(3)
    .subscribe();

  const events1 = [];
  const reader1 = stream1.getReader();
  try {
    while (true) {
      const { done, value } = await reader1.read();
      if (done) break;
      events1.push(value);
    }
  } finally {
    reader1.releaseLock();
  }

  t.equal(events1.length, 3, "should receive 3 events");
  for (const event of events1) {
    t.equal(event.resource.owner.z32(), userPk.z32(), "owner should match user");
    t.equal(event.eventType, "PUT", "should be PUT events");
    t.ok(event.contentHash, "PUT should have contentHash");
  }

  // === Test 2: Cursor pagination ===
  t.comment("eventStreamForUser: cursor pagination");

  const lastCursor = events1[events1.length - 1].cursor;
  const stream2 = await sdk
    .eventStreamForUser(userPk, lastCursor)
    .limit(5)
    .subscribe();

  const events2 = [];
  const reader2 = stream2.getReader();
  try {
    while (true) {
      const { done, value } = await reader2.read();
      if (done) break;
      events2.push(value);
    }
  } finally {
    reader2.releaseLock();
  }

  t.equal(events2.length, 2, "should receive remaining 2 events after cursor");

  const page1Cursors = new Set(events1.map((e) => e.cursor));
  for (const event of events2) {
    t.notOk(page1Cursors.has(event.cursor), `cursor ${event.cursor} not in first page`);
  }

  // === Test 3: With path filter ===
  t.comment("eventStreamForUser: with path filter");

  const stream3 = await sdk
    .eventStreamForUser(userPk, null)
    .path("/pub/app/")
    .subscribe();

  const events3 = [];
  const reader3 = stream3.getReader();
  try {
    while (true) {
      const { done, value } = await reader3.read();
      if (done) break;
      events3.push(value);
    }
  } finally {
    reader3.releaseLock();
  }

  t.equal(events3.length, 5, "should receive all 5 events under /pub/app/");

  // === Test 4: With reverse ===
  t.comment("eventStreamForUser: reverse order");

  const stream4 = await sdk
    .eventStreamForUser(userPk, null)
    .reverse()
    .limit(3)
    .subscribe();

  const events4 = [];
  const reader4 = stream4.getReader();
  try {
    while (true) {
      const { done, value } = await reader4.read();
      if (done) break;
      events4.push(value);
    }
  } finally {
    reader4.releaseLock();
  }

  t.equal(events4.length, 3, "should receive 3 events in reverse");
  if (events4.length > 1) {
    const first = parseInt(events4[0].cursor);
    const last = parseInt(events4[events4.length - 1].cursor);
    t.ok(first > last, "cursors should be in descending order");
  }

  t.end();
});

/**
 * Test eventStreamFor(homeserver) — homeserver-direct API.
 */
test("eventStreamFor: homeserver-direct subscription", async (t) => {
  const sdk = Pubky.testnet();

  // Setup: create a user
  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
  const session = await signer.signin("events.test");
  const userPk = session.info.publicKey;

  for (let i = 0; i < 4; i++) {
    const path = `/pub/data/item_${i}.json` as Path;
    await session.storage.putText(path, `{"i": ${i}}`);
  }

  await sleep(500);

  // === Test 1: Using homeserver key directly ===
  t.comment("eventStreamFor: direct homeserver subscription");

  const stream1 = await sdk
    .eventStreamFor(HOMESERVER_PUBLICKEY)
    .addUsers([[userPk.z32(), null]])
    .limit(4)
    .subscribe();

  const events1 = [];
  const reader1 = stream1.getReader();
  try {
    while (true) {
      const { done, value } = await reader1.read();
      if (done) break;
      events1.push(value);
    }
  } finally {
    reader1.releaseLock();
  }

  t.equal(events1.length, 4, "should receive 4 events");
  for (const event of events1) {
    t.equal(event.resource.owner.z32(), userPk.z32(), "owner should match user");
  }

  // === Test 2: With path filter ===
  t.comment("eventStreamFor: with path filter");

  const stream2 = await sdk
    .eventStreamFor(HOMESERVER_PUBLICKEY)
    .addUsers([[userPk.z32(), null]])
    .path("/pub/data/")
    .subscribe();

  const events2 = [];
  const reader2 = stream2.getReader();
  try {
    while (true) {
      const { done, value } = await reader2.read();
      if (done) break;
      events2.push(value);
    }
  } finally {
    reader2.releaseLock();
  }

  t.equal(events2.length, 4, "should receive 4 events filtered by path");
  for (const event of events2) {
    t.ok(
      event.resource.path.startsWith("/pub/data/"),
      `path should start with /pub/data/: ${event.resource.path}`,
    );
  }

  t.end();
});

/**
 * Test addUsers() — batch multi-user API.
 */
test("addUsers: batch multi-user subscription", async (t) => {
  const sdk = Pubky.testnet();

  // Create two users
  const signer1 = sdk.signer(Keypair.random());
  const token1 = await createSignupToken();
  await signer1.signup(HOMESERVER_PUBLICKEY, token1);
  const session1 = await signer1.signin("events.test");
  const user1Pk = session1.info.publicKey;

  const signer2 = sdk.signer(Keypair.random());
  const token2 = await createSignupToken();
  await signer2.signup(HOMESERVER_PUBLICKEY, token2);
  const session2 = await signer2.signin("events.test");
  const user2Pk = session2.info.publicKey;

  // Create events for both users
  for (let i = 0; i < 3; i++) {
    await session1.storage.putText(`/pub/u1/f${i}.txt` as Path, `u1-${i}`);
  }
  for (let i = 0; i < 2; i++) {
    await session2.storage.putText(`/pub/u2/f${i}.txt` as Path, `u2-${i}`);
  }

  await sleep(500);

  // === Test 1: addUsers with z32 string tuples ===
  t.comment("addUsers: batch subscription with z32 tuples");

  const stream1 = await sdk
    .eventStreamFor(HOMESERVER_PUBLICKEY)
    .addUsers([
      [user1Pk.z32(), null],
      [user2Pk.z32(), null],
    ])
    .subscribe();

  const events1 = [];
  const reader1 = stream1.getReader();
  try {
    while (true) {
      const { done, value } = await reader1.read();
      if (done) break;
      events1.push(value);
    }
  } finally {
    reader1.releaseLock();
  }

  t.equal(events1.length, 5, "should receive 5 events total (3 + 2)");

  const u1Events = events1.filter((e) => e.resource.owner.z32() === user1Pk.z32());
  const u2Events = events1.filter((e) => e.resource.owner.z32() === user2Pk.z32());

  t.equal(u1Events.length, 3, "should have 3 events from user1");
  t.equal(u2Events.length, 2, "should have 2 events from user2");

  // === Test 2: addUsers with cursor ===
  t.comment("addUsers: with cursor for one user");

  // Get a cursor from user1's first event
  const firstStream = await sdk
    .eventStreamForUser(user1Pk, null)
    .limit(1)
    .subscribe();

  const firstEvents = [];
  const firstReader = firstStream.getReader();
  try {
    while (true) {
      const { done, value } = await firstReader.read();
      if (done) break;
      firstEvents.push(value);
    }
  } finally {
    firstReader.releaseLock();
  }

  const cursor1 = firstEvents[0].cursor;

  const stream2 = await sdk
    .eventStreamFor(HOMESERVER_PUBLICKEY)
    .addUsers([
      [user1Pk.z32(), cursor1],  // skip first event for user1
      [user2Pk.z32(), null],     // all events for user2
    ])
    .subscribe();

  const events2 = [];
  const reader2 = stream2.getReader();
  try {
    while (true) {
      const { done, value } = await reader2.read();
      if (done) break;
      events2.push(value);
    }
  } finally {
    reader2.releaseLock();
  }

  // user1: 2 remaining (skipped 1), user2: 2 total = 4
  t.equal(events2.length, 4, "should receive 4 events (2 from user1 after cursor + 2 from user2)");

  t.end();
});

/**
 * Test getHomeserverOf() — resolve homeserver for a user.
 */
test("getHomeserverOf: resolve user homeserver", async (t) => {
  const sdk = Pubky.testnet();

  // Create a user on the known homeserver
  const signer = sdk.signer(Keypair.random());
  const signupToken = await createSignupToken();
  await signer.signup(HOMESERVER_PUBLICKEY, signupToken);
  const userPk = signer.publicKey;

  // Resolve the homeserver
  const homeserver = await sdk.getHomeserverOf(userPk);

  t.ok(homeserver, "should resolve a homeserver");
  t.equal(
    homeserver!.z32(),
    HOMESERVER_PUBLICKEY.z32(),
    "resolved homeserver should match the signup homeserver",
  );

  t.end();
});

/**
 * Test error handling for non-existent user.
 */
test("eventStreamForUser: invalid user key", async (t) => {
  const sdk = Pubky.testnet();

  const fakeUser = Keypair.random().publicKey;

  try {
    // Try to subscribe to events for a user that doesn't exist
    await sdk.eventStreamForUser(fakeUser, null).limit(10).subscribe();

    // If the homeserver can't be resolved, it should fail
    // But if it goes through, we should be able to read from stream
    t.pass("subscribe succeeded (homeserver resolved)");
  } catch (error) {
    // Expected to fail if user doesn't have a homeserver
    assertPubkyError(t, error);
    t.ok(
      error.message.includes("homeserver") || error.message.includes("resolve"),
      "error should mention homeserver resolution failure",
    );
  }

  t.end();
});
