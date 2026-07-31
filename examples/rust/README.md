# Pubky examples

Minimal examples for different flows and functions you might need to implement using Pubky.

## How to use these examples

Run the example commands from the `examples/rust` directory.

Most examples use `--testnet` and expect a local testnet to be running. The testnet requires PostgreSQL.

### Quick start

The fastest way to get a testnet running (requires Docker):

```bash
# Start a disposable Postgres container (one-time, runs in background)
docker run --name pubky-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 127.0.0.1:5432:5432 \
  -d postgres:18

# Start the testnet (keep this terminal open)
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres?pubky-test=true' \
  cargo run -p pubky-testnet
```

Wait for `Testnet running`, then run the examples in another terminal. For example:

```bash
cd examples/rust
cargo run --bin signup -- --testnet
```

For more options (persistent mode, custom config, etc.) see the [Pubky Testnet README](../../pubky-testnet/README.md).

The logging and testnet examples (7 and 8) start their own ephemeral testnet and do not need the steps above.

## Utilities

- [**sample_recovery.key**](../sample_recovery.key): Sample recovery file with an empty passphrase, used by default in examples 1, 2, 3, and 6.
- [**keygen**](./keygen.rs): Generate a keypair and save a passphrase-encrypted recovery file when you want to use your own key.

## Examples

1. [**Signup**](./1-signup/README.md): shows how to signup, signin or signout to and from a homeserver.
2. [**Auth Flow**](./2-auth_flow/README.md): shows how to sign in or sign up through Pubky grant auth with a headless third-party client and an authenticator CLI.
3. [**Storage**](./3-storage/README.md): authenticated write, read, and delete lifecycle on homeserver storage.
4. [**Request**](./4-request/README.md): shows how to make direct HTTP requests to Pubky URLs.
5. [**Events Stream**](./5-events_stream/README.md): subscribe to Server-Sent Events from a user's homeserver.
6. [**Session Management**](./6-session_management/README.md): create, list, and delete grant-backed sessions from the command line.
7. [**Logging**](./7-logging/README.md): configure tracing and watch the SDK emit debug output during a storage roundtrip.
8. [**Testnet**](./8-testnet/README.md): spin up an embedded `EphemeralTestnet` programmatically for integration tests or self-contained demos.
