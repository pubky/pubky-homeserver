# Agent instructions

See [README.md](README.md) for the repository layout and project overview.

## Principles

- Code should never prevent the user from exercising the
  [credible exit](https://pubky.org/explore/concepts/credible-exit/).
- Keep changes small and focused. Reuse existing code and libraries, and avoid
  abstractions for problems we don't have.

## Code and documentation

- Follow neighboring code, crate lints, and workspace dependency conventions.
- Keep Rust imports at module scope, not inside functions. Use `#[cfg]` on
  imports that only apply to specific targets or features.
- Keep modules focused. Give each service direct access to the dependencies it
  needs, such as its own database handle.
- Use clear names and existing types and errors. Add comments where the reason
  for a choice isn't obvious.
- Keep Rust and JS/WASM APIs consistent, accounting for platform differences.
  Preserve compatibility; call out intentional API, protocol, or storage changes
  and document migration steps when needed.
- Define configuration defaults explicitly in
  [config.default.toml](pubky-homeserver/src/data_directory/config.default.toml)
  rather than relying on Serde defaults.
- Update the relevant OpenAPI specs when changing HTTP APIs:
  [client](pubky-homeserver/openapi-client.yml) and
  [admin](pubky-homeserver/openapi-admin.yml).
- Document public APIs and update affected examples. Keep docs concise and link
  to detailed guides. Keep unrelated refactors out of the change.

## Validation

For Rust changes, run formatting, Clippy, and tests for the affected crates:

```sh
cargo fmt --check
cargo clippy --workspace --all-features --exclude pubky-wasm -- -D warnings
cargo test -p pubky --all-features
```

Replace `pubky` (the SDK) with the affected package. See [TESTING.md](docs/TESTING.md)
for PostgreSQL setup and database cleanup with `#[pubky_testnet::test]`.
Use `pubky-testnet` for integration tests; cover bug reproductions and relevant
failure paths. For SDK changes, check native and WASM behavior using the
[JS bindings guide](pubky-sdk/bindings/js/README.md) and applicable
[CI checks](.github/workflows/pr-check.yml).

Review the diff. Report what you tested, what changed for callers, and anything
you couldn't verify.
