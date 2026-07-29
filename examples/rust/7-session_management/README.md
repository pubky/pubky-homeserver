# Session Management

Create, list, and delete grant-backed sessions from the command line.

This example defaults to `../../sample_recovery.key`, which has an empty passphrase. If the recovery file cannot be decrypted with an empty passphrase, the CLI prompts for a passphrase.

## Usage

List active sessions:

```bash
cargo run --bin sessions -- --testnet list
```

Create a session:

```bash
cargo run --bin sessions -- --testnet create
```

Create a session with a custom client id:

```bash
cargo run --bin sessions -- --testnet create --client-id my-app.example
```

Delete a session:

```bash
cargo run --bin sessions -- --testnet delete <grant-id>
```

## Notes

- Listing and deleting sessions requires a root-capability session.
- This example creates that management session from the recovery file.
- Deleting a session revokes its grant id, invalidating sessions minted from that grant.
