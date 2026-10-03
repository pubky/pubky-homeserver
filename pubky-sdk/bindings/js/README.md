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
