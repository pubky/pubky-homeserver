# Pubky Auth Signup Example

This example shows 3rd party user signup and authorization in Pubky.

It consists of 2 parts:

1. [3rd party app](./3rd-party-app): A web component showing the how to implement a Pubky Auth widget.
2. [Authenticator CLI](./authenticator.rs): A CLI showing the authenticator (key chain) 
- signing up a new user
- asking the user for consent 
- generating the AuthToken

## Usage

First you need to be running a local testnet Homeserver, in the root of this repo run

```bash
cargo run -p pubky-testnet
```

Run the frontend of the 3rd party app

```bash
cd ./3rd-party-app
npm start
```

Copy the Pubky Auth URL from the frontend.

Finally run the CLI to paste the Pubky Auth in.

```bash
cargo run --bin authenticator_signup "<Auth_URL>" [Testnet]
```

Where the auth url should be within quotations marks, and the Testnet is an option you can set to true to use the local homeserver.

You should see the frontend reacting by showing the success of authorization and session details.
