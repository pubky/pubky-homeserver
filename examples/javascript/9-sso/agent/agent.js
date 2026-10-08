// The agent page: holds the one grant session and lends its bearer to the
// allowlisted apps that embed this page. Opened directly, it shows the
// account and a sign-out button.
import { Pubky, Keypair, PublicKey, AuthFlowKind } from "/pubky/index.js";

// Exact origins that may use this agent. A sibling subdomain that is not
// listed is refused even though it is same-site. Keep in step with the
// `frame-ancestors` header in serve.mjs.
const ALLOWED_ORIGINS = ["http://localhost:8081", "http://localhost:8082", "http://127.0.0.1:8084"];
const CLIENT_ID = "auth.sso.example";
// The shared scope: every app gets exactly this, never more.
const SHARED_SCOPE = "/pub/sso.example/:rw";
const TESTNET_HOMESERVER = PublicKey.from("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo");
const TESTNET_RELAY = "http://localhost:15412/inbox";
const PENDING_FLOW_KEY = "pubky-sso-pending-flow";

const pubky = Pubky.testnet();
const store = pubky.browserSessionStore;
const $ = (id) => document.getElementById(id);
const log = (line) => { $("log").textContent += `${new Date().toISOString().slice(11, 19)} ${line}\n`; };
const framed = window.parent !== window;

let session;
let flow;

// Restore first, then listen: apps that connect while we restore wait for an
// answer instead of seeing "signed-out". Sessions saved in other tabs are
// picked up by the agent on its own.
const [record] = await store.list();
if (record) {
  try {
    session = await store.restore(record.id);
  } catch (error) {
    log(`restore failed: ${error.message}`);
  }
}
const agent = await pubky.listenSessionAgent({ allowedOrigins: ALLOWED_ORIGINS, capabilities: SHARED_SCOPE });
if (session) await agent.setSession(session);
addEventListener("pubky-session-changed", () => setTimeout(render, 0));
render();

// A sign-in interrupted by a reload (the mobile deep link, for example)
// resumes from the saved flow; relay messages live about five minutes.
if (!session) {
  const pending = sessionStorage.getItem(PENDING_FLOW_KEY);
  if (pending) {
    try {
      flow = await pubky.resumeDelegatedGrantAuthFlow(pending);
      showSignIn();
      awaitApproval();
    } catch (error) {
      sessionStorage.removeItem(PENDING_FLOW_KEY);
      log(`resume failed: ${error.message}`);
    }
  }
  if (!flow) await startSignIn();
}

async function startSignIn() {
  // On mobile Ring returns to the app that is showing this frame.
  const returnUrl = agent.returnUrl;
  flow = await pubky.startGrantAuthFlow(SHARED_SCOPE, AuthFlowKind.signin(), {
    clientId: CLIENT_ID,
    relay: TESTNET_RELAY,
    xCallback: returnUrl ? { xSuccess: returnUrl } : undefined,
  });
  try {
    sessionStorage.setItem(PENDING_FLOW_KEY, flow.saveDelegated());
  } catch {
    // Local-secret flows (no WebCrypto Ed25519) cannot be saved; fine for a demo.
  }
  showSignIn();
  awaitApproval();
}

function showSignIn() {
  $("auth-url").textContent = flow.authorizationUrl;
  $("ring").href = flow.authorizationUrl;
  $("signin").hidden = false;
}

async function awaitApproval() {
  try {
    const approved = await flow.awaitApproval();
    // Saving is what signs the other agent frames in; they restore the record
    // when the store announces it. Serving it here as well skips that round
    // trip for this frame, and the agent keeps this copy rather than
    // restoring a second one.
    await store.save(approved);
    await agent.setSession(approved);
    session = approved;
    log(`signed in as ${approved.info.publicKey.z32()}`);
  } catch (error) {
    log(`sign-in failed: ${error.message}`);
  } finally {
    sessionStorage.removeItem(PENDING_FLOW_KEY);
    flow = undefined;
    render();
  }
}

// Stand-in for Ring: a throwaway testnet account approves the pending request.
$("approve").onclick = async () => {
  try {
    const signer = pubky.signer(Keypair.random());
    const token = await fetch("http://127.0.0.1:6288/generate_signup_token", {
      headers: { "X-Admin-Password": "admin" },
    }).then((r) => r.text());
    await signer.signup(TESTNET_HOMESERVER, token);
    await signer.approveAuthRequest(flow.authorizationUrl);
  } catch (error) {
    log(`approval failed: ${error.message}`);
  }
};

$("signout").onclick = async () => {
  try {
    await session.signout();
    session = undefined;
    log("signed out");
    await startSignIn();
  } catch (error) {
    log(`sign-out failed: ${error.message}`);
  }
};

function render() {
  const served = agent.hasSession;
  $("status").textContent = served
    ? `Signed in as ${session?.info.publicKey.z32() ?? "(session from another tab)"}; serving ${ALLOWED_ORIGINS.join(", ")}`
    : framed ? "Sign in once to use every app on this site." : "No session.";
  $("signin").hidden = served || !flow;
  $("signout").hidden = !served || framed;
}
