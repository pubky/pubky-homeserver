// An app page: borrows the agent's session through the embedded frame.
import { Pubky } from "/pubky/index.js";

const AGENT_ORIGIN = "http://localhost:8083";
const CAPABILITIES = "/pub/sso.example/:rw";
const NOTES = "/pub/sso.example/";

const pubky = Pubky.testnet();
const $ = (id) => document.getElementById(id);
const log = (line) => { $("log").textContent += `${new Date().toISOString().slice(11, 19)} ${line}\n`; };
const me = location.host.replace(":", "-");
$("origin").textContent = location.origin;

let client;
try {
  client = await pubky.connectSessionAgent($("agent"), {
    agentOrigin: AGENT_ORIGIN,
    capabilities: CAPABILITIES,
    returnUrl: location.href,
  });
  client.addEventListener("change", (event) => {
    log(`agent status: ${event.detail.state}`);
    render();
  });
  render();
} catch (error) {
  $("status").textContent = `Agent connection failed: ${error.message}`;
  log(error.message);
}

const session = () => client?.session;

async function write() {
  await session().storage.putText(`${NOTES}${me}.txt`, `hello from ${location.origin} at ${new Date().toISOString()}`);
  log(`wrote ${NOTES}${me}.txt`);
}

async function readAll() {
  for (const url of await session().storage.list(NOTES)) {
    const path = new URL(url).pathname;
    log(`${path}: ${await session().storage.getText(path)}`);
  }
}

function render() {
  const { state } = client.status;
  const user = session()?.info.publicKey.z32();
  $("status").textContent = {
    "signed-in": `Signed in as ${user} with ${session()?.info.capabilities.join(", ")}`,
    "signed-out": "Not signed in. Sign in below; every app on this site follows.",
    "insufficient-scope": "The shared session does not cover what this app needs. Fall back to an own grant flow.",
    "unavailable": "This browser does not share sessions across origins here. Fall back to an own grant flow.",
  }[state];
  // The agent frame is only shown while the user needs to sign in there.
  $("agent").hidden = state !== "signed-out";
  for (const id of ["write", "read", "signout"]) $(id).disabled = state !== "signed-in";
}

$("write").onclick = () => write().catch((e) => log(`write failed: ${e.message}`));
$("read").onclick = () => readAll().catch((e) => log(`read failed: ${e.message}`));
$("signout").onclick = () => session().signout().then(() => log("signed out via the agent"), (e) => log(`sign-out failed: ${e.message}`));
