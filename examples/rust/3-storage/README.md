# Storage Lifecycle

Write, read back, and delete a file on your own Pubky homeserver.

This example defaults to:

- path: `/pub/my-app/data.json`
- content: `my data`
- recovery file: `../../sample_recovery.key`, which has an empty passphrase

If the recovery file cannot be decrypted with an empty passphrase, the CLI prompts for a passphrase.

## Usage

Run against a local testnet:

```bash
cargo run --bin storage -- --testnet
```

Use a custom path or content:

```bash
cargo run --bin storage -- --testnet /pub/my-app/data.json --content "my data"
```

Use a custom recovery file:

```bash
cargo run --bin storage -- --testnet --recovery-file </path/to/recovery file>
```
