# Pubky Grant Auth Signin Example

This example shows third-party grant authorization in Pubky from two Rust CLIs.

The `auth_client` starts a grant auth flow, prints a Pubky Auth deep link, and waits for a grant-backed session. The `authenticator` approves the request by signing a `pubky-grant` JWS, which the client exchanges for a self-refreshing session.

It consists of 2 parts:

1. [Auth client CLI](./client.rs): A headless third-party app that creates the deep link and awaits approval.
2. [Authenticator CLI](./authenticator.rs): A CLI showing the authenticator (key chain) asking the user for consent and delivering the signed grant.

For the browser version of the third-party app, see the JavaScript [2-auth-flow](../../javascript/2-auth-flow/README.md) example.

## Recovery File

This example defaults to `../../sample_recovery.key`. You may supply a custom recovery file.

## Usage

First you need to be running a local testnet Homeserver, in the root of this repo run

```bash
cargo run -p pubky-testnet
```

Run the third-party auth client in one terminal:

```bash
cargo run --bin auth_client -- --testnet

# with a custom client id or capabilities
cargo run --bin auth_client -- --testnet \
  --client-id my-app.example \
  --capabilities /pub/my-app/:rw
```

Copy the Pubky Auth URL from the client output. It should use the `signin_grant` intent and include `cid` and `cpk` query parameters.

Finally run the authenticator in another terminal to approve it:

```bash
cargo run --bin authenticator -- "<Auth_URL>" --testnet

# with a custom recovery file
cargo run --bin authenticator -- "<Auth_URL>" --testnet --recovery-file <RECOVERY_FILE>
```

Where the auth URL should be within quotation marks, and `--testnet` uses the local homeserver.

You should see the client receive the approval and print the grant-backed session details.

