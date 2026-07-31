# Pubky Grant Auth Example

This example uses two Rust CLIs to demonstrate third-party grant authorization for signing in and signing up with Pubky.

The `auth_client` starts a grant auth flow, prints a Pubky Auth deep link, and waits for a grant-backed session. The `authenticator` signs up the account when requested, then approves the app's capabilities by signing a `pubky-grant` JWS. The client exchanges that grant for a self-refreshing session.

The example consists of two parts:

1. [Auth client CLI](./client.rs): A headless third-party app that creates the deep link and awaits approval.
2. [Authenticator CLI](./authenticator.rs): A CLI that shows the authenticator (keychain) asking the user for consent and delivering the signed grant.

For the browser version of the third-party app, see the JavaScript [2-auth-flow](../../javascript/2-auth-flow/README.md) example.

## Prerequisites

Examples using `--testnet` require a running local testnet. See the [examples README](../README.md#quick-start) for setup.

## Recovery File

This example defaults to `../../sample_recovery.key`. You may supply a custom recovery file.

## Usage

### 1a) Signing in

Run the third-party auth client in one terminal:

```bash
cargo run --bin auth_client -- --testnet

# with a custom client ID or capabilities
cargo run --bin auth_client -- --testnet \
  --client-id my-app.example \
  --capabilities /pub/my-app/:rw
```

Copy the Pubky Auth URL from the client output. It should use the `signin_grant` intent and include `cid` and `cpk` query parameters.

### 1b) Signing up + Signing in

If you have not signed up to the homeserver yet you can sign up and sign in at the same time with the auth flow. Start the client with `--signup`:

```bash
cargo run --bin auth_client -- --testnet --signup
```

For a non-testnet homeserver, provide its public key and any required signup code:

```bash
cargo run --bin auth_client -- --signup \
  --homeserver <HOMESERVER_PUBLIC_KEY> \
  --signup-code <SIGNUP_CODE>
```

The signup URL uses the `signup_grant` intent. The authenticator first creates the account on the homeserver embedded in the URL and then approves the app grant. Use a recovery file for a key that does not already have an account on that homeserver.

### 2) Approve Authorization Request

Finally, run the authenticator in another terminal to approve the request. To create an account on the local testnet and authorize the app in one flow, start the client with `--signup`.

```bash
cargo run --bin authenticator -- "<Auth_URL>" --testnet

# with a custom recovery file
cargo run --bin authenticator -- "<Auth_URL>" --testnet --recovery-file <RECOVERY_FILE>
```

The auth URL should be enclosed in quotation marks. The `--testnet` option uses the local homeserver.

You should see the client receive the approval and print the grant-backed session details.
