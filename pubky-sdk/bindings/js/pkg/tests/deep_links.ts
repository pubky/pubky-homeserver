import test from "tape";
import {
  PublicKey,
  DirectSignupDeepLink,
  SigninDeepLink,
  SigninGrantDeepLink,
  SignupDeepLink,
  SignupGrantDeepLink,
} from "../index.js";
import {
  Assert,
  IsExact,
  assertPubkyError,
  createSignupToken,
} from "./utils.js";

const HOMESERVER_PUBLICKEY = PublicKey.from(
  "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo",
);
const CLIENT_PUBLICKEY = PublicKey.from(
  "5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo",
);

// relay base (no trailing slash is fine; the flow will append the channel id)
const TESTNET_HTTP_RELAY = "http://localhost:15412/inbox";

test("signin deep link valid", async (t) => {
  const xSuccess = "bitkit://auth/success?nonce=abc%2F123&state=ready";
  const xError = "bitkit://auth/error?nonce=abc&reason=denied";
  const xCancel = "bitkit://auth/cancel?nonce=abc";
  const url = "pubkyauth://signin?caps=/pub/pubky.app/:rw&relay=http://localhost:15412/inbox&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8" +
    `&x-source=${encodeURIComponent("Bitkit Wallet")}` +
    `&x-success=${encodeURIComponent(xSuccess)}` +
    `&x-error=${encodeURIComponent(xError)}` +
    `&x-cancel=${encodeURIComponent(xCancel)}`;
  const deepLink = SigninDeepLink.parse(url);
  t.equal(deepLink.capabilities, "/pub/pubky.app/:rw");
  t.equal(deepLink.baseRelayUrl, TESTNET_HTTP_RELAY);
  t.deepEqual(deepLink.secret, new Uint8Array([146, 169, 220, 120, 67, 32, 172, 212, 12, 255, 24, 180, 234, 132, 23, 140, 13, 220, 36, 117, 255, 69, 9, 176, 212, 22, 58, 36, 77, 91, 177, 239]));
  t.deepEqual(deepLink.xCallback, {
    xSource: "Bitkit Wallet",
    xSuccess,
    xError,
    xCancel,
  });

  t.equal(SigninDeepLink.parse(deepLink.toString()).toString(), deepLink.toString());

  t.end();
});

test("signin deep link accepts legacy callback and emits canonical x-success", (t) => {
  const callback = "bitkit://auth/success?nonce=legacy";
  const url = "pubkyauth://signin?caps=&relay=http://localhost:15412/inbox" +
    "&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8" +
    `&callback=${encodeURIComponent(callback)}`;

  const deepLink = SigninDeepLink.parse(url);

  t.equal(deepLink.xCallback.xSuccess, callback);
  t.ok(deepLink.toString().includes("x-success="));
  t.notOk(deepLink.toString().includes("callback="));
  t.end();
});

test("signup deep link valid", async (t) => {
  let url = "pubkyauth://signup?caps=/pub/pubky.app/:rw&relay=http://localhost:15412/inbox&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&hs=8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo&st=1234567890";
  const deepLink = SignupDeepLink.parse(url);
  t.equal(deepLink.capabilities, "/pub/pubky.app/:rw");
  t.equal(deepLink.baseRelayUrl, TESTNET_HTTP_RELAY);
  t.deepEqual(deepLink.secret, new Uint8Array([146, 169, 220, 120, 67, 32, 172, 212, 12, 255, 24, 180, 234, 132, 23, 140, 13, 220, 36, 117, 255, 69, 9, 176, 212, 22, 58, 36, 77, 91, 177, 239]));
  t.equal(deepLink.homeserver.z32(), HOMESERVER_PUBLICKEY.z32());
  t.equal(deepLink.signupToken, "1234567890");
  t.equal(SignupDeepLink.parse(deepLink.toString()).capabilities, deepLink.capabilities);

  t.end();
});

test("direct signup deep link valid", async (t) => {
  const url = `pubkyauth://direct_signup?hs=${HOMESERVER_PUBLICKEY.z32()}`;
  const deepLink = DirectSignupDeepLink.parse(url);

  t.equal(deepLink.homeserver.z32(), HOMESERVER_PUBLICKEY.z32());
  t.equal(deepLink.signupToken, undefined, "no token when absent");

  const roundTripped = DirectSignupDeepLink.parse(deepLink.toString());
  t.equal(roundTripped.homeserver.z32(), HOMESERVER_PUBLICKEY.z32());

  t.end();
});

test("direct signup deep link with token", async (t) => {
  const url = `pubkyauth://direct_signup?hs=${HOMESERVER_PUBLICKEY.z32()}&st=1234567890`;
  const deepLink = DirectSignupDeepLink.parse(url);

  t.equal(deepLink.homeserver.z32(), HOMESERVER_PUBLICKEY.z32());
  t.equal(deepLink.signupToken, "1234567890");

  const roundTripped = DirectSignupDeepLink.parse(deepLink.toString());
  t.equal(roundTripped.homeserver.z32(), HOMESERVER_PUBLICKEY.z32());
  t.equal(roundTripped.signupToken, "1234567890");

  t.end();
});

test("signin grant deep link valid", async (t) => {
  let url = `pubkyauth://signin_grant?caps=/pub/pubky.app/:rw&relay=http://localhost:15412/inbox&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&cid=franky.pubky.app&cpk=${CLIENT_PUBLICKEY.z32()}`;
  const deepLink = SigninGrantDeepLink.parse(url);
  t.equal(deepLink.capabilities, "/pub/pubky.app/:rw");
  t.equal(deepLink.baseRelayUrl, TESTNET_HTTP_RELAY);
  t.deepEqual(deepLink.secret, new Uint8Array([146, 169, 220, 120, 67, 32, 172, 212, 12, 255, 24, 180, 234, 132, 23, 140, 13, 220, 36, 117, 255, 69, 9, 176, 212, 22, 58, 36, 77, 91, 177, 239]));
  t.equal(deepLink.clientId, "franky.pubky.app");
  t.equal(deepLink.clientPublicKey.z32(), CLIENT_PUBLICKEY.z32());
  t.equal(SigninGrantDeepLink.parse(deepLink.toString()).clientPublicKey.z32(), CLIENT_PUBLICKEY.z32());

  t.end();
});

test("signup grant deep link valid", async (t) => {
  let url = `pubkyauth://signup_grant?caps=/pub/pubky.app/:rw&relay=http://localhost:15412/inbox&secret=kqnceEMgrNQM_xi06oQXjA3cJHX_RQmw1BY6JE1bse8&hs=${HOMESERVER_PUBLICKEY.z32()}&st=1234567890&cid=franky.pubky.app&cpk=${CLIENT_PUBLICKEY.z32()}`;
  const deepLink = SignupGrantDeepLink.parse(url);
  t.equal(deepLink.capabilities, "/pub/pubky.app/:rw");
  t.equal(deepLink.baseRelayUrl, TESTNET_HTTP_RELAY);
  t.deepEqual(deepLink.secret, new Uint8Array([146, 169, 220, 120, 67, 32, 172, 212, 12, 255, 24, 180, 234, 132, 23, 140, 13, 220, 36, 117, 255, 69, 9, 176, 212, 22, 58, 36, 77, 91, 177, 239]));
  t.equal(deepLink.homeserver.z32(), HOMESERVER_PUBLICKEY.z32());
  t.equal(deepLink.signupToken, "1234567890");
  t.equal(deepLink.clientId, "franky.pubky.app");
  t.equal(deepLink.clientPublicKey.z32(), CLIENT_PUBLICKEY.z32());
  t.equal(SignupGrantDeepLink.parse(deepLink.toString()).clientPublicKey.z32(), CLIENT_PUBLICKEY.z32());

  t.end();
});
