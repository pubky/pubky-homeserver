# Browser Session Persistence

Small Vite app that shows how to persist and restore multiple Pubky accounts in the browser with `browserSessionStore`.

The app is testnet-only and self-contained. On first load, if there are no saved browser sessions, it creates two random testnet accounts, signs them up, signs them in, stores their grant-backed sessions in IndexedDB, and activates the first account.

## Run

Start a local testnet in one terminal:

```bash
cd pubky-sdk/bindings/js/pkg
npm run testnet
```

Start the browser app in another terminal:

```bash
cd examples/javascript/5-browser-session-persistence
npm install
npm run dev
```

## What It Shows

- `Keypair.random()` creates disposable browser-only testnet identities.
- `signer.signup(testnetHomeserver)` creates each account on the local testnet.
- `signer.signin(clientId)` creates a grant-backed session for each account.
- `browserSessionStore.save(session)` persists each completed grant session.
- `browserSessionStore.list()` lists all saved sessions for this browser origin.
- `browserSessionStore.restore(id)` restores one saved account as the active session.
- `browserSessionStore.remove(id)` forgets a saved session locally.
- `browserSessionStore.clear()` clears saved browser session records for this origin.

Removing or clearing records is local-only. It does not revoke the remote grant on the homeserver.

The demo does not persist root keypairs. If a saved grant expires or is revoked, that generated account is disposable and cannot be recovered from this app.
