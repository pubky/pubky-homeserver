# Sign in to your service with Pubky

Let users sign in to your API using an existing Pubky session. The client creates
a short-lived, signed proof and sends it to your server. Your server verifies
which user it represents, decides whether to allow access, and creates its own
session for subsequent requests.

Start with the [JavaScript client and Node.js server example](#verify-credentials-in-nodejs-or-a-browser).
For a Rust application, see [credential generation](#rust) and
[server verification](#verify-credentials-in-a-rust-service).

After the example, use these sections as needed:

- [Handle errors and retries](#handle-errors-and-retries).
- [Configure verification limits](#configure-verification).
- [Implement a custom replay store](#use-a-custom-replay-store).
- [Manage service sessions](#expiration-and-session-lifecycle).

## How the exchange works

1. The client creates credentials for your service using its existing Pubky grant.
   A grant is the user's signed permission for an application to act on their behalf.
2. Your server checks those credentials and records the proof as used. The SDK
   calls this *consuming* the proof. A second attempt with the same proof fails.
3. Your server creates a service session. The client uses that session to call
   your API, rather than sending the Pubky proof on every request.

## Before you start

- Have a Pubky session with `session.grant` available. A cookie-only session cannot
  create these credentials; first sign in through a grant-based flow.
- Install `@synonymdev/pubky` in the client and server projects. The JavaScript
  verifier supports Node 20+ and browsers. The example verifies on your server,
  where your API makes access decisions.
- Choose a name for your service, called its **audience**. The example uses
  `example.com`. Use exactly the same value in the client and server.
- Provide an API endpoint and your own session management. The example URL
  `https://example.com/auth/session` is a placeholder for your endpoint,
  not a Pubky endpoint.

## Verify credentials in Node.js or a browser

### 1. Client: create and send credentials

Run this function in the application that already holds the user's Pubky session.
Replace the URL with your server's endpoint. This example expects that endpoint
to return JSON containing a service token and its expiry time.

```typescript
import type { Session } from "@synonymdev/pubky";

export async function signInToService(session: Session) {
  if (!session.grant) {
    throw new Error("Sign in with a Pubky grant before accessing this service");
  }

  const credentials = await session.grant.createServiceAuthProof("example.com");
  const response = await fetch("https://example.com/auth/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(credentials),
  });
  if (!response.ok) {
    throw new Error(`Service sign-in failed: HTTP ${response.status}`);
  }
  return response.json(); // { token, expiresAt } from your server
}
```

The SDK creates `{ grant, pop }`: the existing grant and a new signed proof.
It does not contact your server; `fetch` sends the credentials. Create new
credentials for every attempt, including retries after a failed request.

### 2. Server: verify and create your session

Create the verifier once at server startup. It must remember used proofs between
requests. The memory store below holds up to 10,000 proofs that have not expired.
It loses that history on restart, and separate server processes do not share it.
Use a [custom replay store](#use-a-custom-replay-store) when you need shared storage
or protection across restarts. A replay store records which proofs have been used.

In the example, `ServiceSessions` describes **your application's code**, not a
Pubky API. Implement `isAllowed` using your access rules and `create` using your
session system. `create` must return a service token that stops working at
`expiresAt`, expressed as seconds since the Unix epoch.

```typescript
import {
  MemoryReplayStore,
  ServiceAuthVerifier,
  type ServiceAuthProof,
} from "@synonymdev/pubky";

const verifier = new ServiceAuthVerifier(
  "example.com",
  new MemoryReplayStore(10_000),
);

interface ServiceSessions {
  isAllowed(identity: string): Promise<boolean>;
  create(identity: string, expiresAt: number): Promise<string>;
}

export async function authenticateRequest(
  credentials: ServiceAuthProof,
  sessions: ServiceSessions,
) {
  const auth = await verifier.verifyAndConsume(credentials);
  if (!await sessions.isAllowed(auth.identity)) {
    throw new Error("This user is not allowed to access the service");
  }

  const oneHourFromNow = Math.floor(Date.now() / 1000) + 3600;
  const expiresAt = Math.min(oneHourFromNow, auth.grantExpiresAt);
  const token = await sessions.create(auth.identity, expiresAt);
  return { token, expiresAt };
}
```

Connect your `POST /auth/session` route to `authenticateRequest`: read a bounded
JSON request body, pass the credentials and your session implementation, and
return the result as JSON. Map rejected calls to an error response using the
[error guidance](#handle-errors-and-retries). The SDK checks the credentials;
your HTTP framework owns body-size limits, routing, and responses.

Two fields drive this example:

- `identity` identifies the user whose grant was verified. It is their public key
  encoded as a z-base-32 string, suitable for an account lookup.
- `grantExpiresAt` is the latest time your service session may expire. You can
  choose a shorter lifetime, as the example does.

Verification confirms identity, not permission to use your service. Apply your
own access rules before issuing a session. A successful verification also marks
the proof as used: trying the same credentials again fails with `Replay`.

### 3. Client: use the service session

The response contains the token created by your server. Send it as
`Authorization: Bearer <token>` on later requests to your API, according to your
API's contract. Your service implements token validation, expiry, and logout.
An HTTP-only session cookie is another option if that fits your application.

Signing out of the homeserver does not end this service session. See
[session lifecycle](#expiration-and-session-lifecycle) for revocation and renewal.

### Common sign-in failures

| Error | Next step |
| --- | --- |
| `Replay` | Create a new proof and submit it once. Check that the client is not reusing a previous request body. |
| `AudienceMismatch` | Use the exact same service name on both sides, including case and whitespace. |
| `GrantExpired` | Obtain a valid Pubky grant before signing in to the service again. |
| `Storage` | Check the replay store. Verification cannot succeed while it cannot safely record used proofs. |

JavaScript errors expose these codes in `PubkyError.data.reason`. See
[errors and retries](#handle-errors-and-retries) for storage details and other failures.

### Choose an audience

An audience binds a proof to the service you intend to authenticate to. Without
that binding, someone who obtains a valid proof—including the service receiving
it—could submit it to another service that accepts Pubky credentials.

For example, a proof signed for `example.com` must be rejected by a service
configured for `other.example.com`. Because the audience is part of the signed
proof, changing it invalidates the signature.

The audience prevents cross-service replay. Each proof also has a **nonce**, a
random single-use identifier. The nonce check prevents repeated
use at the intended service. You need both: separate services don't necessarily
share nonce history.

An audience is an opaque string of **1–1,024 UTF-8 bytes**. It doesn't need to be
a URL. The SDK preserves it exactly, without trimming, case folding, URL parsing,
or Unicode normalization. `example.com`, `https://example.com`, and
`Example.com` are valid identifiers, but each is a different audience.
Using a domain as the audience does not verify ownership of that domain.

## Generate and submit credentials

Generate a fresh proof for each exchange attempt, including retries after a
failed request or a lost response. Treat the returned credentials as sensitive.

### JavaScript

Use `session.grant.createServiceAuthProof(audience)`, as shown in the
[client example](#1-client-create-and-send-credentials). It supports SDK-held keys
and non-extractable browser WebCrypto keys. Applications don't need to access
IndexedDB or export the signing key.

Proof generation does not prompt the signer or refresh the homeserver bearer
token. A valid grant still works when that bearer has expired. Restoring a session
can still require network requests; creating the proof does not.

### Rust

The Rust method returns `ServiceAuthProof`, which contains the original grant
and the signed proof. This helper handles the absence of a grant view explicitly:

```rust
use pubky::{PubkySession, ServiceAuthProof};

pub async fn create_service_credentials(
    session: &PubkySession,
) -> Result<ServiceAuthProof, Box<dyn std::error::Error>> {
    let grant = session.as_grant().ok_or_else(|| {
        std::io::Error::other("A grant-backed Pubky session is required")
    })?;
    Ok(grant.create_service_auth_proof("example.com").await?)
}
```

Serialize the result as JSON and submit it with your application's HTTP client.
The SDK method creates credentials; your application owns the HTTP exchange
and the resulting service session.

## Verify credentials in a Rust service

### Enable the verifier

Enable `service-auth-verifier` on your `pubky` dependency. For a service project
next to this checkout, the dependency entries look like this. Adjust the local
path to your checkout; merge these entries with your existing dependencies.

```toml
[dependencies]
pubky = { path = "../pubky-core/pubky-sdk", features = ["service-auth-verifier"] }
serde_json = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Verification and both replay stores live in the SDK. The feature adds no runtime
dependencies beyond those the SDK already uses.

### Create a long-lived verifier

Call this function once at service startup, inside your Tokio runtime. The store
creates `./service-replay` beneath the existing current directory. Use a persistent
location appropriate for your deployment.

```rust
use pubky::service_auth::{
    FileReplayStore, FileReplayStoreOptions, ServiceAuthVerifier,
    VerificationPolicy,
};

pub async fn create_verifier(
) -> Result<ServiceAuthVerifier<FileReplayStore>, Box<dyn std::error::Error>> {
    let store = FileReplayStore::open(
        "./service-replay",
        FileReplayStoreOptions {
            max_entries: 100_000,
            max_journal_bytes: 16 * 1024 * 1024,
        },
    )
    .await?;

    Ok(ServiceAuthVerifier::new(
        "example.com",
        VerificationPolicy::default(),
        store,
    )?)
}
```

Keep the verifier in your application's shared state. Cloning a verifier with
either built-in store shares that store's state. Don't create a new memory store
per request or try to open a new file-store owner for every handler.

### Authenticate each exchange

Configure your HTTP framework to bound request-body reading before JSON
deserialization. The verifier's JWS limits apply after the credentials have
been read; they don't bound HTTP-body allocation or JSON-envelope overhead.

Pass the bounded body to a helper like this:

```rust
use pubky::service_auth::{
    FileReplayStore, ServiceAuthProof, ServiceAuthVerifier, VerifiedServiceAuth,
};

pub async fn authenticate_request(
    verifier: &ServiceAuthVerifier<FileReplayStore>,
    body: &[u8],
) -> Result<VerifiedServiceAuth, Box<dyn std::error::Error>> {
    let credentials: ServiceAuthProof = serde_json::from_slice(body)?;
    Ok(verifier.verify_and_consume(&credentials).await?)
}
```

A successful result means both signatures, claim bindings, and time checks
passed, and the nonce was consumed. You don't need a separate nonce check.
Storage failures reject authentication rather than bypassing replay protection.

### Authorize the identity and issue your session

Use the returned `VerifiedServiceAuth` to make your service's authorization
decision. Then issue your service-owned session with an expiry no later than
`grant_expires_at()`. You can apply a shorter lifetime:

```text
session expiry = min(service-defined expiry, grant expiry)
```

Return the service credential or set the session cookie according to your API
contract. Ordinary API endpoints authenticate that credential rather than
calling `verify_and_consume` again. The SDK verifies the exchange; your service
implements session issuance and subsequent request authentication.

Verified provenance doesn't establish service permissions. Homeserver storage
capabilities don't grant service-specific permissions, and `client_id` isn't a verified web
origin. Apply your own policy to the authenticated identity.

## Configure verification

Use the defaults to start. If your service needs a shorter sign-in window, pass
a policy override when creating the verifier. This example accepts proofs for
less than 120 seconds after they were created, rather than the default 180:

```typescript
import { MemoryReplayStore, ServiceAuthVerifier } from "@synonymdev/pubky";

const verifier = new ServiceAuthVerifier(
  "example.com",
  new MemoryReplayStore(10_000),
  { maxProofAgeSeconds: 120 },
);
```

Omitted settings keep their defaults. In Rust, set `max_proof_age_seconds` on
`VerificationPolicy` and use `..VerificationPolicy::default()` for the other
fields. See the [API documentation](#api-documentation) for available settings
and their bounds.

These settings control when a proof can be accepted, not how long your service
session lasts. Before changing settings on an existing store, follow the
[policy-change procedure](#change-policy-or-replace-replay-state).

## Use a custom replay store

The memory store is bounded and rejects new entries when full. Verifiers retain
their own Rust handles to its state. You can pass one store to several verifiers;
freeing a JS store wrapper does not clear a verifier's history. State is shared
only within its WASM instance; restarts lose history and separate Node workers
do not share it.

For shared or persistent storage, use `ServiceAuthVerifier.withStore`, passing an
object implementing `consumeOnce(request): Promise<ConsumeOutcome>`. In this
example, `database.consumeServiceProof` represents your database adapter; it must
implement the atomic contract below.

```typescript
import { ServiceAuthVerifier, type ReplayStore } from "@synonymdev/pubky";

const store: ReplayStore = {
  async consumeOnce(request) {
    return database.consumeServiceProof({
      key: request.key,
      policyFingerprint: request.policyFingerprint,
      notBefore: request.notBefore,
      expiresAt: request.expiresAt,
    });
  },
};
const verifier = ServiceAuthVerifier.withStore("example.com", store);
```

The verifier supplies a request that identifies the proof, its allowed times,
and the verification settings. Use it to enforce the following storage contract;
see `ReplayRequest` in the [API documentation](#api-documentation) for field details.

The operation must be **atomic**: two requests for the same proof cannot both
report success. Within one lock or database transaction, the store must:

1. Reject a policy fingerprint that differs from the store's existing binding.
   Also reject clock rollback: the current time must not be earlier than the last
   time the store observed. Persist the binding and observed time with the records
   when using persistent storage.
2. Recheck `notBefore <= now < expiresAt` after acquiring the lock.
3. Return `"alreadyConsumed"` if the key is present. Otherwise, insert it atomically
   and retain it until `expiresAt`. Never evict live entries to recover capacity.
4. Save the key and metadata durably before returning `"consumed"` from a persistent
   store, so a restart cannot make an accepted proof usable again.

Throw on storage failure. Rejected promises, synchronous exceptions, and invalid
results reject authentication. All service instances must use the same
authoritative storage. Follow the [policy-change procedure](#change-policy-or-replace-replay-state)
before replacing a store or changing its bound policy.

## Choose and operate a replay store

Choose storage explicitly; neither store evicts unexpired entries to make room.

| Store | Persistence and sharing | Configuration |
| --- | --- | --- |
| `MemoryReplayStore` | Clones share process-local state. Restarting or creating a new store loses replay history. | `MemoryReplayStore::new(max_entries)`; capacity must be positive. |
| `FileReplayStore` | History survives restart. Exactly one process owns the directory; clones share that owner. | Positive `max_entries` and `max_journal_bytes` of at least 161 bytes. |

For process-local use, replace the store in the startup example with
`MemoryReplayStore::new(100_000)?` and change the verifier's type parameter to
`MemoryReplayStore`. Use file storage when you need replay protection across
restarts.

For multiple service instances on separate machines, implement `ReplayStore`
over one shared authoritative backend. `ReplayRequest` exposes the replay key,
time bounds, and policy fingerprint. The adapter must provide atomic consumption
and the same retention, clock, capacity, policy-binding, and cancellation
guarantees. Separate memory stores or separate journal directories don't provide
cross-instance replay protection.

### Maintain the file store

The store directory contains these reserved files:

- `owner.lock` holds the exclusive owner lock. Don't delete it.
- `journal` contains a versioned header and checksummed, hash-chained records.
- `journal.next` is a temporary compaction snapshot. Recovery ignores it unless
  compaction has renamed it to `journal`.

Each successful consumption follows a journal append and `sync_all`. Compaction
writes and syncs the unexpired records, atomically replaces the journal, and syncs
the directory. The separate lock file preserves ownership during replacement.

Journal size and live-entry count are bounded by your configuration. Compaction
can temporarily use a second journal's worth of disk space. Recovery also obeys
the configured journal-size limit. Blocking file work runs on Tokio's blocking
pool and continues safely if an async caller cancels.

After a write or sync failure, the open handle becomes unavailable. Reopen the
store to recover complete records conservatively as consumed. Incomplete
records, checksum failures, missing journals, and unsupported formats reject
opening; the SDK never automatically resets them. If recovery is impossible,
follow the replacement procedure below before starting with fresh state.

Use trusted local storage and an accurate system clock. Stores reject observed
clock rollback; persisted clock floors prevent cleanup followed by a restart
from making discarded nonces usable again. Restoring an older journal backup or
deleting the store can undo replay protection. Checksums detect corruption but
don't authenticate files against someone with filesystem write access.

### Change policy or replace replay state

Both stores bind themselves to an audience and verification-policy fingerprint.
Changing the audience, time settings, or input limits causes `PolicyMismatch`.
A failed file consumption can still persist this binding or a consumed nonce.

To replace replay state or change its bound policy:

1. Stop accepting authentication exchanges that use the old state.
2. Wait for the larger old/new maximum-proof-age window plus the larger old/new
   future-skew window. This lets previously acceptable proofs expire under either
   policy. With unchanged defaults, wait at least 210 seconds.
3. Close the old owner and start a verifier with fresh storage and the intended
   policy. Don't delete a live owner's files.

## Handle errors and retries

### Credential generation fails

Check that the client still has a grant-backed session and that the grant has not
expired. If a browser reports `SigningKeyUnavailable`, check access to its saved
signing key; clearing browser storage can remove that key. A removed session or
pending logout also prevents proof generation.

JavaScript exposes SDK failures as `PubkyError`; Rust returns
`ServiceAuthProofError`. Inspect the diagnostic before deciding whether the user
needs to sign in again. Underlying session errors may have no `data.reason`.

### Verification or replay storage fails

Map verification failures to error responses from your endpoint. Never create a
service session after verification fails. Start with the
[common sign-in failures](#common-sign-in-failures); if timestamps are rejected,
also check the client and server clocks.

In JavaScript, inspect `PubkyError.data.reason` and, for `Storage` failures,
`data.storageReason`. In Rust, `ServiceAuthVerificationError::Storage` wraps the
underlying `ReplayStoreError`. Use the storage diagnostic to choose a remedy:

- **The store is full:** increase capacity or wait for records to expire. Do not
  delete unexpired records to make room.
- **The clock moved backwards:** restore accurate time at or beyond the store's
  last observed time. Clearing replay history does not safely fix the problem.
- **The settings changed:** restore the previous settings or follow the
  [policy-change procedure](#change-policy-or-replace-replay-state).
- **The custom backend failed:** inspect the callback's error message. If it
  returned an invalid result, fix its `consumeOnce` implementation.
- **The file store cannot open or write:** reuse its existing owner if it is
  already open, or follow the [file-store recovery guidance](#maintain-the-file-store).

See the [API documentation](#api-documentation) for the complete error types.

An exchange can consume a nonce even if a later authorization decision, session
creation, or HTTP response fails. Cancellation and a lost response can also leave
the outcome uncertain. Generate a fresh proof for the next attempt; nonce
consumption isn't rolled back with your service's session transaction.

## Expiration and session lifecycle

### Use the proof to establish a session

Use a Pubky proof when signing in to your service, then use the service token or
cookie for ordinary API requests. Reusing the proof fails. Creating a new proof
for every API request would repeat signing, signature checks, and replay-store
writes; the native file store also needs a durable disk write for each acceptance.

The short proof window controls when credentials can be exchanged. It doesn't
set the lifetime of the resulting service session. That session must expire no
later than the grant and may expire sooner under service policy.

Any session renewal or token-refresh mechanism must preserve the grant-expiry
ceiling. To establish another session through Pubky credentials, generate a fresh
proof from a still-valid grant. Once the grant expires, obtain a valid grant
before authenticating again.

Homeserver signout or grant revocation doesn't automatically invalidate external
sessions or prevent an otherwise unexpired grant from being used at the service.
Removing a local browser session prevents further use through its managed
handles, but doesn't revoke sessions already issued by external services.

## API documentation

For complete field descriptions, method signatures, and errors, use the SDK's
API documentation:

- **JavaScript:** the installed package includes TypeScript declarations and
  documentation for editor hover help. To build the HTML reference from this
  checkout, run `npm run docs` in `pubky-sdk/bindings/js/pkg` after building the
  [JS bindings](../pubky-sdk/bindings/js/README.md#development-quick-start).
- **Rust:** run `cargo doc -p pubky --all-features --open` from the repository root
  and open the `service_auth` module. Its `VerifiedServiceAuth`, `VerificationPolicy`,
  and `ReplayStore` documentation describes the corresponding types and contracts.
