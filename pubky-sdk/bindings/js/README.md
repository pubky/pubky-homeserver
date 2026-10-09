# JS Pubky SDK bindings

Wasm-pack wrap of [Pubky](https://github.com/pubky/pubky-homeserver) SDK, published on
[npm as `@synonymdev/pubky`](https://www.npmjs.com/package/@synonymdev/pubky).

Works in modern browsers and Node v20+.

For deeper dives, check out the
[examples/javascript](../../../examples/javascript) scripts and the
[npm package documentation](pkg/README.md).

## Development quick start

Prerequisites:

- Rust toolchain (via [`rustup`](https://rustup.rs/)).
- Wasm-pack `cargo install wasm-pack`.
- Node.js v20+.

Then from `pubky-sdk/bindings/js/pkg`:

```bash
npm install          # grab JS deps once
npm run build        # compile wasm + patch bundle
npm run testnet      # start local DHT + relay + homeserver (in another terminal)
npm run test         # run tape tests against the testnet + browser harness
```

The `build` step will produce an isomorphic bundle (`index.js` / `index.cjs`) and
TypeScript definitions under `pkg/`.

### Shared browser sessions

Call `browserSessionStore.save(session)` after authentication, then use
`browserSessionStore.restore(id)` in other tabs. Tabs on the same origin share a
bearer per grant, with requests and refreshes coordinated by Web Locks. See the
[browser session lifecycle](../../../docs/grant-session-lifecycle.md) for logout,
storage requirements and upgrades from older stored records.

To run the multi-window regression, start a fresh testnet with
`cargo run -p pubky-testnet -- --homeserver-config pubky-sdk/bindings/js/pkg/scripts/session-tabs.toml`
from the repository root. Then run `npm run build && npm run test-browser:tabs`
from `pubky-sdk/bindings/js/pkg`. The testnet uses the existing single-session protocol and
Postgres on port 5432 with the repository's `test_user` / `test_pass` credentials.

## Scoped encryption keys

Apps can ask the user's signer for encryption keys scoped to storage paths.
Set `approvalFormat: "signedApprovalV1"` and add the `e` action to each scope
that needs keys. Storage actions `r` and `w` don't deliver keys. The signer may
narrow scopes or decline `e`, so check `keys.scopes` before deriving keys.

```javascript
const flow = await sdk.startGrantAuthFlow(
  "/pub/chat/:rwe",
  AuthFlowKind.signin(),
  { clientId: "chat.example", approvalFormat: "signedApprovalV1" },
);
// Have the signer approve flow.authorizationUrl.
const session = await flow.awaitApproval();
const keys = session.grant.encryptionKeys;
let key;
try {
  if (!keys.scopes.includes("/pub/chat/")) {
    throw new Error("The signer didn't approve chat keys.");
  }
  key = await keys.deriveCryptoKeyForPath("/pub/chat/message");
} finally {
  keys.free(); // The WebCrypto key remains usable.
}
const iv = crypto.getRandomValues(new Uint8Array(12));
const ciphertext = await crypto.subtle.encrypt(
  { name: "AES-GCM", iv }, key, new TextEncoder().encode("Hello"),
);
// Store the IV with the ciphertext; use a fresh IV for each encryption.
```

`deriveCryptoKeyForPath(path)` returns a non-extractable AES-GCM-256 key for
encryption and decryption. It requires WebCrypto (a secure browser context) and
clears temporary JS key bytes after import. Directory paths and paths outside
the approved scopes are rejected.

Sessions and offline recovery return the same `EncryptionKeys` object:

| API | Returns |
| --- | --- |
| `keys.scopes` | Approved scope paths as `string[]` |
| `keys.deriveForPath(path)` | Raw key bytes as `Uint8Array` |
| `await keys.deriveCryptoKeyForPath(path)` | Non-extractable AES-GCM `CryptoKey` |

Both derivation methods require a canonical file path and reject directories
and files outside the approved scopes. You own the returned raw bytes; clear
the `Uint8Array` after use.

Each read of `session.grant.encryptionKeys` creates a separate copy. Keep the
object for repeated use and call `keys.free()` when you're done. The keys stay
usable after you free or sign out the session, and freeing the keys doesn't
affect the session. Bare grants return `undefined`; signed approvals without `e`
scopes return an object with empty scopes.

`signer.signin()` grants root storage access (`/:rw`) without keys. To
receive keys, request `e` through a signed approval flow.

Before you use keys, read the
[scoped encryption keys guide](../../../docs/scoped-encryption-keys.md). Keys
stay usable after the grant expires or is revoked, and older homeservers reject
any grant containing `e`. The guide also covers encryption limitations and
relay limits.

### Persistence and offline recovery

For signed approvals, `exportLocalSecret()` includes the signed approval, and
with it the keys, in the exported token (`pubky-grant-credential-v2`).
`browserSessionStore.save()` and `restore()` keep the keys for both local and
delegated WebCrypto sessions. The browser store saves them as plaintext in
IndexedDB, readable by any script on the same origin. See
[persistence and offline recovery][persistence].

You can recover keys without authenticating, even after the grant expires or is
revoked:

```javascript
import { EncryptionKeys } from "@synonymdev/pubky";

const keys = EncryptionKeys.fromLocalSecret(savedToken);
// For IndexedDB records instead:
// const keys = await sdk.browserSessionStore.restoreEncryptionKeys(storedId);
if (keys) {
  try {
    const contentKey = await keys.deriveCryptoKeyForPath("/pub/chat/message");
    // Use contentKey with crypto.subtle.decrypt() and downloaded ciphertext.
  } finally {
    keys.free();
  }
}
```

Both methods verify the approval signature and its binding to the grant
without network access. Bare grants return `undefined`; signed approvals
without `e` scopes return an object with empty scopes. Recovery creates no
session. Restoring an authenticated session still checks grant expiry and
contacts the homeserver.

[persistence]:
  ../../../docs/scoped-encryption-keys.md#persistence-and-offline-recovery

### Derivation tests

Native and WASM tests use the [shared v1 vectors][key-vectors]. Run
`wasm-pack test --headless --chrome` from this directory for WASM unit tests.

[key-vectors]: ../../../pubky-common/tests/fixtures/README.md
