# Recommended: Grant Authentication

Grant authentication is the new Pubky authentication system based on a Proof of Possession (PoP) client key. In an authorization flow, the signer gives the application a grant that it exchanges, together with a short-lived PoP proof, for an opaque one-hour bearer token. The SDK refreshes the bearer automatically without requiring the user's root key again.

**Compared with cookie authentication:**

| **Grant authentication**                                   | **Cookie authentication**                                    |
|------------------------------------------------------------|--------------------------------------------------------------|
| Credentials are isolated per app and client key            | Websites in the same browser insecurely share the same cookie |
| Uses Authorization: Bearer tokens                          | Uses an HTTP session cookie                                  |
| Bearers are short-lived and self-refreshing using PoP      | Cookie sessions can last up to one year                      |
| Grant replay requires possession of the client private key | No replay prevention                                         |
| Grants can be listed and revoked individually              | No listing or revocation possible                            |
| Supports the upcoming homeserver mirroring                 | Doesn't support multiple homeservers                         |
| Recommended in Pubky v0.10+                                | Deprecated and scheduled for removal                         |

The cookie belongs to the homeserver domain rather than the third-party application. Consequently, website B can receive the same homeserver cookie used by website A and potentially exercise A's permissions. Grant authentication prevents this by using bearer tokens, binding each authorization to an app-specific key, and explicitly scoped capabilities.

## Client ID

A new client ID is introduced when creating a grant authentication session. It is an identifier that is saved alongside the session in the homeserver. When a users lists all session with the new session management api, the client ID is listed.

A client name can be any domain like string and should identify your application. 

Examples:
- `pubkyapp.synonym.to`
- `example-app`

## Signer Signup and Signin

The signer methods `signup()` and `signin()` changed.
- `signup()` does not establish a session anymore. It only signs up a user. Therefore, it does not have a return value.
- `signin()` uses the new Grant authentication now. It requires a client ID.

### JavaScript

```js
await signer.signup(homeserver, signupToken);
const session = await signer.signin("my-app.example");
```

For blocking signin, pass the same client ID:

```js
const session = await signer.signinBlocking("my-app.example");
```

### Rust

```rust
use pubky::ClientId;

signer.signup(&homeserver, signup_token).await?;

let client_id = ClientId::new("my-app.example")?;
let session = signer.signin(client_id).await?;
```

For blocking signin:

```rust
let session = signer
    .signin_blocking(ClientId::new("my-app.example")?)
    .await?;
```

## Auth Flow / QR Login

Grant auth flows add a required client ID and produce a grant-backed, self-refreshing session.

### JavaScript

Replace `startAuthFlow` with `startGrantAuthFlow`. The new facade method is asynchronous.

```js
const flow = await pubky.startGrantAuthFlow(
  "/pub/my-app/:rw",
  AuthFlowKind.signin(),
  { clientId: "my-app.example", relay },
);

renderQr(flow.authorizationUrl);
const session = await flow.awaitApproval();
```

### Rust

Replace `start_auth_flow` with `start_grant_auth_flow`, or replace `PubkyAuthFlow` with `PubkyGrantAuthFlow` when using the flow type directly.

```rust
let client_id = ClientId::new("my-app.example")?;
let flow = pubky.start_grant_auth_flow(
    &caps,
    AuthFlowKind::signin(),
    client_id,
)?;

println!("Scan to sign in: {}", flow.authorization_url());
let session = flow.await_approval().await?;
```

Use `PubkyGrantAuthFlow::builder(...)` when you need a custom relay or HTTP client.

## Session Persistence

Persisting the current one-hour bearer is not useful. Persist the grant and its PoP key material; restoring it mints a fresh bearer. Treat exported local credentials as bearer-equivalent secrets until the grant is revoked.

### JavaScript Browsers

The `v0.10` SDK provides a new out-of-the-box `BrowserSessionStore` that handles session persistence in supported browsers.

It supports delegated, non-extractable WebCrypto keys when available and falls back to storing the keys in local storage in other browser environments.

```js
const store = pubky.browserSessionStore;
const saved = await store.save(session);

const restored = await store.restore(saved.id);
```

Important: `store.remove(...)` and `store.clear()` only remove local state; they do not revoke grants on the homeserver.

### JavaScript Outside Browsers

```js
const secret = await session.exportLocalSecret();
const restored = await pubky.restoreSession(secret);
```

### Rust

```rust
let grant = session
    .as_grant()
    .expect("expected a grant-backed session");
let secret = grant
    .export_local_secret()
    .await
    .expect("expected a local PoP key");

let restored = pubky.restore_session(&secret).await?;
```

Store `secret` securely.

## Resume a Pending Flow

Unlike cookie auth, a grant flow cannot be resumed from its authorization URL alone because the application must retain the matching PoP client key.

| Flow mode | Save | Resume |
|-----------|------|--------|
| JS local | `flow.saveLocal()` | `pubky.resumeGrantAuthFlow(state)` |
| JS browser | `flow.saveDelegated()` | `await pubky.resumeDelegatedGrantAuthFlow(state)` |
| Rust local | `flow.save_local()` | `PubkyGrantAuthFlow::restore(state, client)` |

Use the save/resume pair matching the flow mode.

## Examples

- [JavaScript grant auth flow](../../examples/javascript/2-auth-flow/README.md)
- [Rust grant auth flow](../../examples/rust/2-auth_flow/README.md)
- [JavaScript browser session persistence](../../examples/javascript/5-browser-session-persistence/README.md)
- [Rust grant session management](../../examples/rust/7-session_management/README.md)
