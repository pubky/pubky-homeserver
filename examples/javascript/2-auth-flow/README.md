# JavaScript Grant Auth Flow

Browser example for third-party grant authorization with `@synonymdev/pubky`.

The app starts a `signin_grant` flow, displays a Pubky Auth URL and QR code, waits for the JavaScript authenticator CLI to approve it, then shows the resulting grant-backed session metadata.

## Run

Start a local testnet in one terminal:

```bash
cd pubky-sdk/bindings/js/pkg
npm run testnet
```

Start this browser app in another terminal:

```bash
cd examples/javascript/2-auth-flow
npm install
npm run dev
```

Click **Generate auth link**, copy the generated URL, and approve it in a third terminal:

```bash
cd examples/javascript
node 2-authenticator.mjs "<AUTH_URL>" --testnet
```

## What It Shows

- `Pubky.testnet()` creates a facade wired to the local testnet.
- `startGrantAuthFlow(capabilities, AuthFlowKind.signin(), { clientId, relay })` creates a grant auth request.
- The URL uses the `signin_grant` intent and includes `cid` and `cpk` query parameters.
- `flow.awaitApproval()` waits for the authenticator to sign and deliver a `pubky-grant`.
- The app receives a grant-backed session and displays its client ID, grant ID, capabilities, and expiration metadata.

