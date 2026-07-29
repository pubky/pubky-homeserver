# Pubky JS Examples

Tiny CLI scripts and browser examples that teach the **@synonymdev/pubky** SDK with real flows.

> Tip: call `setLogLevel("debug")` when exploring the scripts to surface SDK logs in your console.

## Prerequisites

- **Node 20+** (fetch + WebCrypto)
- **npm**
- **Rust toolchain** for local checkout usage. These examples link to the local JS SDK package under `pubky-sdk/bindings/js/pkg`, so the SDK package must be built before the examples can import it.

## Install

```bash
cd pubky-sdk/bindings/js/pkg
npm install
npm run build

cd ../../../../examples/javascript
npm install
```

> The examples depend on the local `@synonymdev/pubky` package in this repo. If you see a missing `index.cjs` or `pubky_bg.wasm`, run `npm run build` in `pubky-sdk/bindings/js/pkg`. If you see a missing `fetch-cookie`, run `npm install` in that SDK package.

## How to use these examples

Complete the installation steps above first.

Examples using `--testnet` expect a local testnet to be running. The testnet requires PostgreSQL; see the [Pubky Testnet README](../../pubky-testnet/README.md) for setup instructions.

From the repository root, start the testnet:

```bash
cargo run -p pubky-testnet
```

Wait for `Testnet running` and keep that terminal open. In another terminal, run an example:

```bash
cd examples/javascript
node 1-signup.mjs --testnet
```

To check the basic flow from another terminal:

```bash
cd examples/javascript
node 6-check-testnet.mjs
```

Expected output includes:

```text
Testnet is available, roundtrip succeeded.
```

## Scripts

Each script is a single, commented file under the project root. Run examples explicitly with `node <script>.mjs <args...>`.

### 1) Signup with a recovery file

Decrypts a recovery file, creates a `Signer`, and signs up on a homeserver.

```bash
node 1-signup.mjs [homeserver_pubky] [--recovery-file <path>] [--signup-code <code>] [--testnet]

# use the local testnet homeserver and sample recovery file
node 1-signup.mjs --testnet

# with a custom recovery file and signup code
node 1-signup.mjs <homeserver_pubky> --recovery-file ./alice.recovery --signup-code INVITE-123
```

This example defaults to `../sample_recovery.key`, which has an empty passphrase. You’ll be prompted for the recovery **passphrase** when using an encrypted recovery file.

### 2) Grant authorization flow

Two-process example showing third-party grant authorization. The browser app starts a `signin_grant` flow and waits for approval. The authenticator CLI approves the generated `pubkyauth://` URL using a recovery file.

Start the browser app:

```bash
cd 2-auth-flow
npm install
npm run dev
```

Click **Generate auth link**, copy the generated URL, then approve it from another terminal:

```bash
node 2-authenticator.mjs "<AUTH_URL>" [--recovery-file <path>] [--testnet]

# local testnet with sample recovery file
node 2-authenticator.mjs "<AUTH_URL>" --testnet

# custom recovery file
node 2-authenticator.mjs "<AUTH_URL>" --testnet --recovery-file ./alice.recovery
```

The URL uses the `signin_grant` intent and includes `cid` for the requesting app ID and `cpk` for the grant Proof-of-Possession client key:

```text
pubkyauth://signin_grant?caps=/pub/pubky.app/:rw&relay=http://localhost:15412/inbox&secret=<...>&cid=grant-auth.example&cpk=<...>
```

After approval, the browser receives a grant-backed session and displays the user's public key, client ID, grant ID, requested capabilities, and expiration metadata.

The authenticator defaults to `../sample_recovery.key`, which has an empty passphrase. You'll be prompted for the recovery **passphrase** when using an encrypted recovery file.

See [**2-auth-flow**](./2-auth-flow/README.md) for the browser app details. The Rust tree has a headless version of the third-party client at [**Authorization Flow**](/examples/rust/2-auth_flow/README.md).

### 3) Public storage read (no auth)

Reads a public resource via the **addressed** form: `pubky<z32>/pub/my-cool-app/path/to/file.txt`.
This requires a public resource whose Pubky key is already resolvable. It is not the best first smoke test for a fresh local testnet user because PKDNS publication can lag or fail independently of authenticated storage.

```bash
node 3-storage.mjs <pubky>/<absolute-path> [--testnet]

# examples
node 3-storage.mjs pubkyq5oo7ma.../pub/my-cool-app/hello.txt --testnet
node 3-storage.mjs pubkyoperrr8w.../pub/pubky.app/posts/0033X02JAN0SG
```

Shows **exists**, **stats**, and downloads the content.

### 4) Raw HTTP request (https://\_pubky.<public_key>)

Low-level fetch through the Pubky client. Handy for debugging.

> Use the **raw z-base32** key (no `pubky` prefix) in the `_pubky.<key>` host portion. Call `publicKey.z32()` to get it.
> As with `storage`, Pubky URLs require a resolvable public key record.

```bash
node 4-request.mjs <METHOD> <URL> [--testnet] [-H "Name: value"]... [-d DATA]

# pubky:// read (testnet)
node 4-request.mjs GET https://_pubky.q5oo7ma.../pub/my-cool-app/info.json --testnet

# https:// JSON POST
node 4-request.mjs \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"msg":"hello"}' \
  POST https://example.com/data.json
```

## Browser Examples

### 5) Browser session persistence

Vite app that creates disposable testnet accounts and shows how to save, list, restore, and forget multiple browser-backed Pubky sessions with `browserSessionStore`.

```bash
cd 5-browser-session-persistence
npm install
npm run dev
```

See [**5-browser-session-persistence**](./5-browser-session-persistence/README.md) for the full flow.

### 6) Check local testnet availability

Helper script that checks whether the local testnet is ready by performing a signup, signin, write, and read roundtrip.

```bash
node 6-check-testnet.mjs
```

### 7) Logging and verbosity

Demonstrates how to use `setLogLevel()` to surface the SDK's internal tracing while performing a quick storage roundtrip.

```bash
node 7-logging.mjs --testnet --level debug
```

Override `--homeserver` when pointing at mainnet infrastructure, or change `--level` to reduce the noise.

### 8) Session management

Create, list, and delete grant-backed sessions from the command line.

```bash
node 8-session-management.mjs --testnet list
node 8-session-management.mjs --testnet create
node 8-session-management.mjs --testnet create --client-id my-app.example
node 8-session-management.mjs --testnet delete <grant-id>
```

This example defaults to `../sample_recovery.key`, which has an empty passphrase. Listing and deleting sessions creates a temporary root-capability management session, then signs it out.

## Concepts you’ll bump into

- **Pubky** facade: `new Pubky()` (mainnet defaults) or `Pubky.testnet()` (localhost wiring).
- **Signer** -> **Session**: `signer.signup(homeserver, invite?)` creates the account; `signer.signin(clientId)` returns a grant-backed `session`.
- **SessionStorage** (read/write): absolute paths like `"/pub/my-cool-app/file.txt"`.
- **PublicStorage** (read-only): addressed paths like `"<pubky>/pub/my-cool-app/file.txt"`.
- **https://\_pubky.<key> subdomains and key TLDs**: `https://_pubky.<public_key>/<abs-path>`, supported by the Pubky client.
- **Recovery file**: encrypted root secret; decrypted with a passphrase to get a `Keypair`.

## Quick troubleshooting

- **Cannot find `index.cjs` / `pubky_bg.wasm`**
  Build the local SDK package:

  ```bash
  cd pubky-sdk/bindings/js/pkg
  npm run build
  ```

- **Cannot find module `fetch-cookie`**
  Install the local SDK package dependencies:

  ```bash
  cd pubky-sdk/bindings/js/pkg
  npm install
  ```

- **ECONNREFUSED / transport errors**
  The local testnet probably isn’t running, or it is still starting. Start it in another terminal and wait for `Testnet running`:

  ```bash
  cd pubky-sdk/bindings/js/pkg
  npm run testnet
  ```

- **PkarrError: No HTTPS endpoints found**
  The testnet is not running, is not ready, or the public key has not published/resolved yet. Use `node 6-check-testnet.mjs` as the first smoke test because it performs an authenticated write/read without requiring public PKDNS resolution for the new user.

- **401 Unauthorized**
  You tried to write without a valid session cookie (e.g., after `signout()`), or against the wrong user.
- **403 Forbidden**
  You tried to write outside `/pub/` (e.g., `/priv/...` is not allowed).
- **Wrong passphrase**
  Decryption of the recovery file fails—double-check the passphrase.
- **Windows paths / quoting**
  Wrap `"<AUTH_URL>"` in quotes, and use proper file paths for recovery files.
