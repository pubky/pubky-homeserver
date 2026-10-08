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

Set `approvalFormat: "signedApprovalV1"` and request `e` scopes. Storage
permissions `r` and `w` alone deliver no keys. Signers may decline `e`; check
`keys.scopes` before deriving keys.

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
the delivered scopes are rejected.

Sessions and offline recovery return the same `EncryptionKeys` object:

| API | Returns |
| --- | --- |
| `keys.scopes` | Approved scope paths as `string[]` |
| `keys.deriveForPath(path)` | Raw key bytes as `Uint8Array` |
| `await keys.deriveCryptoKeyForPath(path)` | Non-extractable AES-GCM `CryptoKey` |

Both derivation methods require a canonical file path and reject directories
and files outside the approved scopes. Raw bytes belong to the caller; clear
the returned `Uint8Array` after use.

Each `session.grant.encryptionKeys` access creates an owned copy. Keep the
object for repeated use and call `keys.free()` when finished. It stays usable
after freeing or signing out the session; freeing the keys does not affect
the session. Bare grants return `undefined`; signed approvals without `e`
scopes return an object with empty scopes.

Ordinary `signer.signin()` grants root storage access (`/:rw`) without
encryption keys. Request `e` explicitly through a signed approval flow to
receive keys. See the [key guide](../../../docs/scoped-encryption-keys.md) for compatibility,
encryption limitations, and relay limits.

### Persistence and offline recovery

`exportLocalSecret()` retains keys in V2 tokens for local PoP sessions.
`browserSessionStore.save()` and `restore()` retain keys for both local and
WebCrypto delegated sessions. See [storage requirements][persistence].

Recover keys without authentication, even after expiry or revocation:

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

Both paths verify the approval signature and grant binding without network
access. Bare-grant records return `undefined`; signed approvals without `e`
scopes return an empty bundle. Recovery creates no session; authenticated
restoration still checks expiry and the homeserver.

[persistence]:
  ../../../docs/scoped-encryption-keys.md#persistence-and-offline-recovery

### Derivation tests

Native and WASM tests use the [shared v1 vectors][key-vectors]. Run
`wasm-pack test --headless --chrome` from this directory for WASM unit tests.

[key-vectors]: ../../../pubky-common/tests/fixtures/README.md
